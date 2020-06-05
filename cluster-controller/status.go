package main

import (
	"context"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/kelda-inc/blimp/pkg/errors"
	"github.com/kelda-inc/blimp/pkg/kube"
	"github.com/kelda-inc/blimp/pkg/proto/cluster"
)

const (
	imagePullFailureMsg = "Failed to pull image. Make sure that the image exists, " +
		"and that Blimp has access to it."
	imagePullingMsg = "Pulling image"
)

// statusFetcher provides an API for getting the status of namespaces, and
// subscribing to changes to namespaces.
// It caches pod statuses.
type statusFetcher struct {
	podInformer       cache.SharedIndexInformer
	podLister         listers.PodLister
	eventsInformer    cache.SharedIndexInformer
	eventsLister      listers.EventLister
	namespaceInformer cache.SharedIndexInformer
	namespaceLister   listers.NamespaceLister

	podWatcher       *kube.Watcher
	namespaceWatcher *kube.Watcher
}

func newStatusFetcher(kubeClient kubernetes.Interface) *statusFetcher {
	factory := informers.NewSharedInformerFactory(kubeClient, 30*time.Second)
	podInformer := factory.Core().V1().Pods()
	eventsInformer := factory.Core().V1().Events()
	namespaceInformer := factory.Core().V1().Namespaces()

	return &statusFetcher{
		podInformer:       podInformer.Informer(),
		podLister:         podInformer.Lister(),
		eventsInformer:    eventsInformer.Informer(),
		eventsLister:      eventsInformer.Lister(),
		namespaceInformer: namespaceInformer.Informer(),
		namespaceLister:   namespaceInformer.Lister(),
		podWatcher:        kube.NewWatcher(podInformer.Informer()),
		namespaceWatcher:  kube.NewWatcher(namespaceInformer.Informer()),
	}
}

func (sf *statusFetcher) Start() {
	go sf.podInformer.Run(nil)
	go sf.eventsInformer.Run(nil)
	go sf.namespaceInformer.Run(nil)
	cache.WaitForCacheSync(nil, sf.podInformer.HasSynced)
	cache.WaitForCacheSync(nil, sf.eventsInformer.HasSynced)
	cache.WaitForCacheSync(nil, sf.namespaceInformer.HasSynced)
}

func (sf *statusFetcher) Watch(ctx context.Context, namespace string) chan struct{} {
	notifier := make(chan struct{}, 1)
	notify := func() {
		select {
		case notifier <- struct{}{}:
		default:
		}
	}

	// Send notifications whenever a pod within the namespace changes, or the
	// namespace itself changes.
	podSub := sf.podWatcher.Watch(ctx, kube.Key{Namespace: namespace})
	namespaceSub := sf.namespaceWatcher.Watch(ctx, kube.Key{Name: namespace})
	go func() {
		for {
			select {
			case <-podSub:
				notify()
			case <-namespaceSub:
				notify()
			case <-ctx.Done():
				return
			}
		}
	}()

	return notifier
}

func (sf *statusFetcher) Get(namespace string) (cluster.SandboxStatus, error) {
	ns, err := sf.namespaceLister.Get(namespace)
	if err != nil {
		if kerrors.IsNotFound(err) {
			return cluster.SandboxStatus{Phase: cluster.SandboxStatus_DOES_NOT_EXIST}, nil
		}
		return cluster.SandboxStatus{}, errors.WithContext("get sandbox", err)
	}

	if ns.Status.Phase == corev1.NamespaceTerminating {
		return cluster.SandboxStatus{Phase: cluster.SandboxStatus_TERMINATING}, nil
	}

	pods, err := sf.podLister.
		Pods(namespace).
		List(labels.Set(
			map[string]string{"blimp.customerPod": "true"},
		).AsSelector())
	if err != nil {
		return cluster.SandboxStatus{}, errors.WithContext("get services", err)
	}

	services := map[string]*cluster.ServiceStatus{}
	for _, pod := range pods {
		svcName := pod.GetLabels()["blimp.service"]
		serviceStatus := sf.getServiceStatus(pod)
		services[svcName] = &serviceStatus
	}
	return cluster.SandboxStatus{
		Phase:    cluster.SandboxStatus_RUNNING,
		Services: services,
	}, nil
}

func (sf *statusFetcher) isPulling(namespace, pod, fieldPath string) bool {
	events, err := sf.eventsLister.Events(namespace).List(labels.Everything())
	if err != nil {
		log.WithError(err).Warn("Failed to get events")
		return false
	}

	// Get the most recent timestamps of the image events.
	var pullStarted metav1.Time
	var pullCompleted metav1.Time
	for _, event := range events {
		if event.InvolvedObject.Kind != "Pod" ||
			event.InvolvedObject.Namespace != namespace ||
			event.InvolvedObject.Name != pod ||
			event.InvolvedObject.FieldPath != fieldPath {
			continue
		}

		switch event.Reason {
		case "Pulling":
			if pullStarted.IsZero() || pullStarted.Before(&event.LastTimestamp) {
				pullStarted = event.LastTimestamp
			}
		case "Pulled":
			if pullCompleted.IsZero() || pullCompleted.Before(&event.LastTimestamp) {
				pullCompleted = event.LastTimestamp
			}
		}
	}

	// Check if we've tried to pull yet.
	if pullStarted.IsZero() {
		return false
	}

	// We're currently pulling if a pull has never completed, or the completion
	// event was from before the current image pull.
	return pullCompleted.IsZero() || pullCompleted.Before(&pullStarted)
}

func (sf *statusFetcher) getServiceStatus(pod *corev1.Pod) cluster.ServiceStatus {
	// Check if the pod isn't running because an init container is
	// blocking boot.
	for _, c := range pod.Status.InitContainerStatuses {
		var phase cluster.ServicePhase
		switch c.Name {
		case kube.ContainerNameCopyBusybox, kube.ContainerNameCopyVCP, kube.ContainerNameInitializeVolumeFromImage, kube.ContainerNameWaitInitializedVolumes:
			phase = cluster.ServicePhase_INITIALIZING_VOLUMES
		case kube.ContainerNameWaitDependsOn:
			phase = cluster.ServicePhase_WAIT_DEPENDS_ON
		case kube.ContainerNameWaitInitialSync:
			phase = cluster.ServicePhase_WAIT_SYNC_BIND
		}

		if c.State.Terminated != nil {
			// The init container succeeded, so ignore it.
			if c.State.Terminated.Reason == "Completed" {
				continue
			}

			return cluster.ServiceStatus{
				Phase: phase,
				Msg:   fmt.Sprintf("Unexpected system error: %s", c.State.Terminated.Message),
			}
		}

		// Because the volume initialization container uses the user's image,
		// we need to explicitly tell users about those errors.
		if c.Name == kube.ContainerNameInitializeVolumeFromImage {
			if isImagePullFailure(c) {
				return cluster.ServiceStatus{
					Phase: cluster.ServicePhase_PENDING,
					Msg:   imagePullFailureMsg,
				}
			}

			isPulling := sf.isPulling(pod.Namespace, pod.Name,
				fmt.Sprintf("spec.initContainers{%s}", kube.ContainerNameInitializeVolumeFromImage))
			if isPulling {
				return cluster.ServiceStatus{
					Phase: cluster.ServicePhase_PENDING,
					Msg:   imagePullingMsg,
				}
			}
		}

		// For all other states, we just tell the user that we're still working on the
		// system task.
		return cluster.ServiceStatus{Phase: phase}
	}

	// Inspect the container's status to give more detailed information.
	if len(pod.Status.ContainerStatuses) == 1 {
		cs := pod.Status.ContainerStatuses[0]
		switch {
		case cs.State.Running != nil:
			if !cs.Ready {
				return cluster.ServiceStatus{
					Phase:      cluster.ServicePhase_UNHEALTHY,
					HasStarted: true,
				}
			}
			return cluster.ServiceStatus{
				Phase:      cluster.ServicePhase_RUNNING,
				HasStarted: true,
			}
		case cs.State.Waiting != nil:
			if isImagePullFailure(cs) {
				return cluster.ServiceStatus{
					Phase: cluster.ServicePhase_PENDING,
					Msg:   imagePullFailureMsg,
				}
			}

			isPulling := sf.isPulling(pod.Namespace, pod.Name,
				fmt.Sprintf("spec.containers{%s}", cs.Name))
			if isPulling {
				return cluster.ServiceStatus{
					Phase:      cluster.ServicePhase_PENDING,
					Msg:        imagePullingMsg,
					HasStarted: cs.RestartCount > 0,
				}
			}
			return cluster.ServiceStatus{
				Phase:      cluster.ServicePhase_PENDING,
				Msg:        cs.State.Waiting.Message,
				HasStarted: cs.RestartCount > 0,
			}
		case cs.State.Terminated != nil:
			return cluster.ServiceStatus{
				Phase:      cluster.ServicePhase_EXITED,
				Msg:        cs.State.Terminated.Message,
				HasStarted: true,
			}
		}
	}

	// Fallback to the pod's phase.
	switch pod.Status.Phase {
	case corev1.PodRunning:
		return cluster.ServiceStatus{Phase: cluster.ServicePhase_RUNNING}
	case corev1.PodPending:
		return cluster.ServiceStatus{Phase: cluster.ServicePhase_PENDING}
	case corev1.PodSucceeded, corev1.PodFailed:
		return cluster.ServiceStatus{Phase: cluster.ServicePhase_EXITED}
	default:
		return cluster.ServiceStatus{Phase: cluster.ServicePhase_UNKNOWN}
	}
}

func isImagePullFailure(cs corev1.ContainerStatus) bool {
	return cs.State.Waiting != nil &&
		(cs.State.Waiting.Reason == "ErrImagePull" || cs.State.Waiting.Reason == "ImagePullBackOff")
}
