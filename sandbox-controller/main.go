package main

import (
	"fmt"
	"net"
	"os"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/kelda-inc/blimp/pkg/proto/sandbox"
	"github.com/kelda-inc/blimp/sandbox-controller/dns"

	// Install the gzip compressor.
	_ "google.golang.org/grpc/encoding/gzip"
)

const Port = 9001

func main() {
	namespace := os.Getenv("NAMESPACE")
	if namespace == "" {
		log.Error("NAMESPACE environment variable is required")
		os.Exit(1)
	}

	config, err := rest.InClusterConfig()
	if err != nil {
		log.WithError(err).Error("Get rest config")
		os.Exit(1)
	}

	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.WithError(err).Error("Get kube client")
		os.Exit(1)
	}

	go dns.Run(kubeClient, namespace)

	s := &server{kubeClient: kubeClient}
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

	log.WithField("address", address).Info("Listening for connections..")
	grpcServer := grpc.NewServer()
	sandbox.RegisterManagerServer(grpcServer, s)
	return grpcServer.Serve(lis)
}

type server struct {
	kubeClient kubernetes.Interface
}
