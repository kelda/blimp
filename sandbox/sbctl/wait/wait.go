package wait

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/kelda-inc/blimp/pkg/proto/sandbox"
	"github.com/kelda-inc/blimp/pkg/syncthing"
	"github.com/kelda-inc/blimp/sandbox/sbctl/wait/tracker"

	// Install the gzip compressor.
	_ "google.golang.org/grpc/encoding/gzip"
)

const Port = 9002

func Run(kubeClient kubernetes.Interface, namespace string, volumeTracker *tracker.VolumeTracker) {
	s := &server{
		kubeClient:    kubeClient,
		namespace:     namespace,
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
	namespace     string
	volumeTracker *tracker.VolumeTracker
}

func (s *server) listenAndServe(address string) error {
	lis, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}

	log.WithField("address", address).Info("Listening for connections to boot blocking manager")
	grpcServer := grpc.NewServer()
	sandbox.RegisterBootWaiterServer(grpcServer, s)
	return grpcServer.Serve(lis)
}

// CheckReady returns whether the boot requirements specified in the request
// are satisfied.
func (s *server) CheckReady(req *sandbox.CheckReadyRequest, srv sandbox.BootWaiter_CheckReadyServer) error {
	checkOnce := func() *sandbox.CheckReadyResponse {
		for _, dep := range req.GetWaitSpec().GetDependsOn() {
			isBooted, err := s.isBooted(dep)
			if err != nil {
				return &sandbox.CheckReadyResponse{
					Ready:  false,
					Reason: fmt.Sprintf("failed to get pod status: %s", err),
				}
			}

			if !isBooted {
				return &sandbox.CheckReadyResponse{
					Ready:  false,
					Reason: fmt.Sprintf("service %s is not running yet", dep),
				}
			}
		}

		for _, volume := range req.GetWaitSpec().GetBindVolumes() {
			isSynced, err := s.isSynced(volume)
			if err != nil {
				return &sandbox.CheckReadyResponse{
					Ready:  false,
					Reason: fmt.Sprintf("failed to get sync status: %s", err),
				}
			}

			if !isSynced {
				return &sandbox.CheckReadyResponse{
					Ready:  false,
					Reason: fmt.Sprintf("volume %s is not synced", volume),
				}
			}
		}

		return &sandbox.CheckReadyResponse{Ready: true}
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

func (s *server) isBooted(service string) (bool, error) {
	pod, err := s.kubeClient.CoreV1().Pods(s.namespace).Get(service, metav1.GetOptions{})
	if err != nil {
		if kerrors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}

	return pod.Status.Phase == "Running", nil
}

func (s *server) isSynced(volumePath string) (bool, error) {
	folderPath := filepath.Join("/bind", volumePath)
	expHash, ok := s.volumeTracker.Get(volumePath)
	if !ok {
		return false, errors.New("unknown volume")
	}

	actualHash, err := syncthing.HashVolume(folderPath, nil)
	if err != nil {
		return false, fmt.Errorf("calculate actual hash: %w", err)
	}

	return string(expHash) == actualHash, nil
}
