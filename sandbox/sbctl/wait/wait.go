package wait

import (
	"context"
	"fmt"
	"net"
	"os"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/kelda-inc/blimp/pkg/proto/sandbox"
	"github.com/kelda-inc/blimp/pkg/syncthing"

	// Install the gzip compressor.
	_ "google.golang.org/grpc/encoding/gzip"
)

const Port = 9002

func Run(kubeClient kubernetes.Interface, namespace string, syncthingClient syncthing.APIClient) {
	s := &server{
		kubeClient:      kubeClient,
		namespace:       namespace,
		syncthingClient: syncthingClient,
	}

	addr := fmt.Sprintf("0.0.0.0:%d", Port)
	if err := s.listenAndServe(addr); err != nil {
		log.WithError(err).Error("Unexpected error")
		os.Exit(1)
	}
}

type server struct {
	kubeClient      kubernetes.Interface
	namespace       string
	syncthingClient syncthing.APIClient
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
func (s *server) CheckReady(ctx context.Context, req *sandbox.CheckReadyRequest) (*sandbox.CheckReadyResponse, error) {
	for _, dep := range req.GetWaitSpec().GetDependsOn() {
		isBooted, err := s.isBooted(dep)
		if err != nil {
			return &sandbox.CheckReadyResponse{
				Ready:  false,
				Reason: fmt.Sprintf("failed to get pod status: %s", err),
			}, nil
		}

		if !isBooted {
			return &sandbox.CheckReadyResponse{
				Ready:  false,
				Reason: fmt.Sprintf("service %s is not running yet", dep),
			}, nil
		}
	}

	for _, folder := range req.GetWaitSpec().GetSyncthingFolders() {
		completion, err := s.syncthingClient.GetCompletion(syncthing.RemoteDeviceID, folder)
		if err != nil {
			return &sandbox.CheckReadyResponse{
				Ready:  false,
				Reason: fmt.Sprintf("failed to get sync status: %s", err),
			}, nil
		}

		if completion.Completion != 100 {
			return &sandbox.CheckReadyResponse{
				Ready:  false,
				Reason: fmt.Sprintf("folder %s is %d%% synced", folder, completion.Completion),
			}, nil
		}
	}

	return &sandbox.CheckReadyResponse{Ready: true}, nil
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
