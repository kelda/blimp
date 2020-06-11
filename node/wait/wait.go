package wait

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	composeTypes "github.com/kelda/compose-go/types"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/kelda-inc/blimp/pkg/kube"
	"github.com/kelda-inc/blimp/pkg/proto/wait"
	"github.com/kelda/blimp/pkg/errors"

	// Install the gzip compressor.
	_ "google.golang.org/grpc/encoding/gzip"
)

type server struct {
	podInformer cache.SharedIndexInformer
	podLister   listers.PodLister
	podWatcher  *kube.Watcher
	syncTracker *SyncTracker
}

// Implementations of waiters should block until they have finished waiting.
// They may send status updates on the updates channel.
type waiter func(ctx context.Context, updates chan<- string) error

// podCondition tests for a condition on a pod. Status is a friendly message used
// for sending status updates to the client.
type podCondition func(corev1.Pod) (status string, satisfied bool)

// podWaiter orchestrates waiting for a pod to satisfy a condition.
type podWaiter struct {
	namespace, name string
	condition       podCondition
	watcher         *kube.Watcher
	lister          listers.PodLister
}

const Port = 9002

func Run(kubeClient kubernetes.Interface, syncTracker *SyncTracker) {
	podInformer := informers.NewSharedInformerFactory(kubeClient, 30*time.Second).
		Core().V1().Pods()
	s := &server{
		podInformer: podInformer.Informer(),
		podLister:   podInformer.Lister(),
		podWatcher:  kube.NewWatcher(podInformer.Informer()),
		syncTracker: syncTracker,
	}

	go s.podInformer.Run(nil)
	cache.WaitForCacheSync(nil, s.podInformer.HasSynced)

	addr := fmt.Sprintf("0.0.0.0:%d", Port)
	if err := s.listenAndServe(addr); err != nil {
		log.WithError(err).Error("Unexpected error")
		os.Exit(1)
	}
}

func (s *server) listenAndServe(address string) error {
	lis, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}

	log.WithField("address", address).Info("Listening for connections to boot blocking manager")
	grpcServer := grpc.NewServer(grpc.UnaryInterceptor(errors.UnaryServerInterceptor))
	wait.RegisterBootWaiterServer(grpcServer, s)
	return grpcServer.Serve(lis)
}

// CheckReady returns whether the boot requirements specified in the request
// are satisfied.
func (s *server) CheckReady(req *wait.CheckReadyRequest, srv wait.BootWaiter_CheckReadyServer) error {
	log.WithField("req", req).Info("Received CheckReady request")

	// Transform the boot requirements into a set of waiters.
	var waiters []waiter
	for _, condition := range req.GetWaitSpec().GetDependsOn() {
		var pc podCondition
		switch condition.Condition {
		case composeTypes.ServiceConditionHealthy:
			pc = conditionPodHealthy
		case composeTypes.ServiceConditionStarted:
			pc = conditionPodStarted
		default:
			// If the service condition is unknown, just ignore it.
			continue
		}

		waiters = append(waiters, podWaiter{
			namespace: req.GetNamespace(),
			name:      kube.PodName(condition.Service),
			condition: pc,
			watcher:   s.podWatcher,
			lister:    s.podLister,
		}.wait)
	}

	for _, service := range req.GetWaitSpec().GetFinishedVolumeInit() {
		waiters = append(waiters, podWaiter{
			namespace: req.GetNamespace(),
			name:      kube.PodName(service),
			condition: conditionFinishedVolumeInit,
			watcher:   s.podWatcher,
			lister:    s.podLister,
		}.wait)
	}

	// We block boot until all the files are synced, even if the sync is
	// waiting on files in another volume.
	if len(req.GetWaitSpec().GetBindVolumes()) != 0 {
		waiters = append(waiters, s.syncTracker.WaitFor(req.GetNamespace()))
	}

	return s.waitForAll(srv, waiters)
}

func (s *server) waitForAll(srv wait.BootWaiter_CheckReadyServer, waiters []waiter) error {
	waitCtx, cancelWaiters := context.WithCancel(context.Background())
	defer cancelWaiters()

	results := make(chan error, len(waiters))
	updates := make(chan string, 16)
	for _, waiter := range waiters {
		waiter := waiter
		go func() {
			results <- waiter(waitCtx, updates)
		}()
	}

	// Wait for all the waiters to successfully complete, or for one of them to
	// fail.
	// If any fail, we return immediately, which cancels the wait context for
	// all other waiters.
	numReady := 0
	for {
		if numReady == len(waiters) {
			break
		}

		select {
		case update := <-updates:
			if err := srv.Send(&wait.CheckReadyResponse{Reason: update}); err != nil {
				return errors.WithContext("send update", err)
			}
		case result := <-results:
			if result != nil {
				log.WithError(result).Info("Aborting waitForAll due to failed wait")
				return errors.WithContext("wait failed", result)
			}
			numReady++
		}
	}

	if err := srv.Send(&wait.CheckReadyResponse{Ready: true}); err != nil {
		return errors.WithContext("send update", err)
	}
	return nil
}

func (w podWaiter) wait(ctx context.Context, updates chan<- string) error {
	checkOnce := func() (msg string, done bool) {
		pod, err := w.lister.Pods(w.namespace).Get(w.name)
		if err != nil {
			return fmt.Sprintf("failed to get pod %s: %s", w.name, err), false
		}

		status, ready := w.condition(*pod)
		return fmt.Sprintf("pod %s is %s", w.name, status), ready
	}

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	podChanged := w.watcher.Watch(ctx, kube.Key{Namespace: w.namespace, Name: w.name})

	for {
		status, done := checkOnce()
		select {
		case updates <- status:
		default:
			log.WithField("status", status).Info("Updates channel is full, dropping.")
		}

		if done {
			return nil
		}

		select {
		case <-podChanged:
		case <-ticker.C:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func conditionPodHealthy(pod corev1.Pod) (string, bool) {
	// Make sure that all the pod's containers have passed their
	// healthchecks. The healthchecks are configured at pod creation by the
	// cluster manager.
	for _, container := range pod.Status.ContainerStatuses {
		if !container.Ready {
			return "not ready", false
		}
	}
	return "ready", true
}

func conditionPodStarted(pod corev1.Pod) (string, bool) {
	return string(pod.Status.Phase), pod.Status.Phase == corev1.PodRunning
}

func conditionFinishedVolumeInit(pod corev1.Pod) (string, bool) {
	for _, c := range pod.Status.InitContainerStatuses {
		if c.Name != kube.ContainerNameInitializeVolumeFromImage {
			continue
		}

		completed := c.State.Terminated != nil && c.State.Terminated.Reason == "Completed"
		if completed {
			return "completed volume initialization", true
		}
		return "waiting for volume initialization", false
	}

	// The pod doesn't have an init container for initializing volumes, so
	// ignore it.
	return "skipped. doesn't initialize volumes", true
}
