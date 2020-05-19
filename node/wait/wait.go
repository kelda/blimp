package wait

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	composeTypes "github.com/kelda/compose-go/types"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/kelda-inc/blimp/node/wait/tracker"
	"github.com/kelda-inc/blimp/pkg/errors"
	"github.com/kelda-inc/blimp/pkg/proto/node"
	"github.com/kelda-inc/blimp/pkg/syncthing"
	"github.com/kelda-inc/blimp/pkg/volume"

	// Install the gzip compressor.
	_ "google.golang.org/grpc/encoding/gzip"
)

const Port = 9002

func Run(kubeClient kubernetes.Interface, volumeTracker *tracker.VolumeTracker) {
	s := &server{
		kubeClient:    kubeClient,
		volumeTracker: volumeTracker,
	}

	addr := fmt.Sprintf("0.0.0.0:%d", Port)
	if err := s.listenAndServe(addr); err != nil {
		log.WithError(err).Error("Unexpected error")
		os.Exit(1)
	}
}

type server struct {
	kubeClient    kubernetes.Interface
	volumeTracker *tracker.VolumeTracker
}

func (s *server) listenAndServe(address string) error {
	lis, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}

	log.WithField("address", address).Info("Listening for connections to boot blocking manager")
	grpcServer := grpc.NewServer(grpc.UnaryInterceptor(errors.UnaryServerInterceptor))
	node.RegisterBootWaiterServer(grpcServer, s)
	return grpcServer.Serve(lis)
}

// CheckReady returns whether the boot requirements specified in the request
// are satisfied.
func (s *server) CheckReady(req *node.CheckReadyRequest, srv node.BootWaiter_CheckReadyServer) error {
	checkOnce := func() *node.CheckReadyResponse {
		namespace := req.GetNamespace()
		for name, condition := range req.GetWaitSpec().GetDependsOn() {
			isBooted, err := s.testServiceCondition(namespace, name, *condition)
			if err != nil {
				return &node.CheckReadyResponse{
					Ready:  false,
					Reason: fmt.Sprintf("failed to get pod status: %s", err),
				}
			}

			if !isBooted {
				return &node.CheckReadyResponse{
					Ready:  false,
					Reason: fmt.Sprintf("service %s is either not running or not healthy", name),
				}
			}
		}

		for _, volume := range req.GetWaitSpec().GetBindVolumes() {
			isSynced, err := s.isSynced(namespace, volume)
			if err != nil {
				return &node.CheckReadyResponse{
					Ready:  false,
					Reason: fmt.Sprintf("failed to get sync status: %s", err),
				}
			}

			if !isSynced {
				return &node.CheckReadyResponse{
					Ready:  false,
					Reason: fmt.Sprintf("volume %s is not synced", volume),
				}
			}
		}

		return &node.CheckReadyResponse{Ready: true}
	}

	pollInterval := 1 * time.Second
	for {
		update := checkOnce()
		if err := srv.Send(update); err != nil {
			return err
		}
		if update.Ready {
			return nil
		}

		pollInterval *= 2
		if pollInterval > 30*time.Second {
			pollInterval = 30 * time.Second
		}
		time.Sleep(pollInterval)
	}
}

func (s *server) testServiceCondition(namespace, name string, condition node.ServiceCondition) (bool, error) {
	pod, err := s.kubeClient.CoreV1().Pods(namespace).Get(name, metav1.GetOptions{})
	if err != nil {
		if kerrors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}

	switch condition.Condition {
	case composeTypes.ServiceConditionHealthy:
		// Make sure that all the pod's containers have passed their
		// healthchecks. The healthchecks are configured at pod creation by the
		// cluster manager.
		for _, container := range pod.Status.ContainerStatuses {
			if !container.Ready {
				return false, nil
			}
		}
	case composeTypes.ServiceConditionStarted:
		return pod.Status.Phase == "Running", nil
	}

	// If the service condition is unknown, just ignore it.
	return pod.Status.Phase == "Running", nil
}

func (s *server) isSynced(namespace, volumePath string) (bool, error) {
	folderPath := filepath.Join(volume.BindVolumeRoot(namespace).VolumeSource.HostPath.Path, volumePath)
	expHash, ok := s.volumeTracker.Get(namespace, volumePath)
	if !ok {
		return false, errors.New("unknown volume")
	}

	actualHash, err := syncthing.HashVolume(folderPath, nil)
	if err != nil {
		return false, errors.WithContext("calculate actual hash", err)
	}

	return string(expHash) == actualHash, nil
}
