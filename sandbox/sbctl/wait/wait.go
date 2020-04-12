package wait

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/kelda-inc/blimp/pkg/proto/sandbox"
	"github.com/kelda-inc/blimp/pkg/syncthing"
	"github.com/kelda-inc/blimp/pkg/volume"

	// Install the gzip compressor.
	_ "google.golang.org/grpc/encoding/gzip"
)

const Port = 9002

func Run(kubeClient kubernetes.Interface, namespace string) {
	s := &server{
		kubeClient: kubeClient,
		namespace:  namespace,
	}

	addr := fmt.Sprintf("0.0.0.0:%d", Port)
	if err := s.listenAndServe(addr); err != nil {
		log.WithError(err).Error("Unexpected error")
		os.Exit(1)
	}
}

type server struct {
	kubeClient kubernetes.Interface
	namespace  string
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

		for _, folder := range req.GetWaitSpec().GetSyncthingFolders() {
			isSynced, err := s.isSynced(folder)
			if err != nil {
				return &sandbox.CheckReadyResponse{
					Ready:  false,
					Reason: fmt.Sprintf("failed to get sync status: %s", err),
				}
			}

			if !isSynced {
				return &sandbox.CheckReadyResponse{
					Ready:  false,
					Reason: fmt.Sprintf("folder %s is not synced", folder),
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

func (s *server) isSynced(folderID string) (bool, error) {
	folderPath := volume.HostPath(s.namespace, folderID)
	expHash, err := ioutil.ReadFile(syncthing.HashTrackerPath(folderPath))
	if err != nil {
		return false, fmt.Errorf("read expected hash: %w", err)
	}

	actualHash, err := syncthing.HashFolder(folderPath)
	if err != nil {
		return false, fmt.Errorf("calculate actual hash: %w", err)
	}

	return string(expHash) == actualHash, nil
}
