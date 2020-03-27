package main

import (
	"fmt"
	"net"
	"os"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/kelda-inc/blimp/pkg/proto/sandbox"
	"github.com/kelda-inc/blimp/pkg/tunnel"
	"github.com/kelda-inc/blimp/sandbox-controller/dns"
	"github.com/kelda-inc/blimp/sandbox-controller/wait"

	// Install the gzip compressor.
	_ "google.golang.org/grpc/encoding/gzip"
)

const (
	Port     = 9001
	CertPath = "/etc/blimp/certs/cert.pem"
	KeyPath  = "/etc/blimp/certs/key.pem"
)

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

	// TODO: Remove need for kubeClient and just query local Docker daemon.
	go dns.Run(kubeClient, namespace)
	go wait.Run(kubeClient, namespace)

	s := &server{kubeClient: kubeClient, namespace: namespace}
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

	creds, err := credentials.NewServerTLSFromFile(CertPath, KeyPath)
	if err != nil {
		return fmt.Errorf("parse cert: %w", err)
	}

	log.WithField("address", address).Info("Listening for connections..")
	grpcServer := grpc.NewServer(grpc.Creds(creds))
	sandbox.RegisterControllerServer(grpcServer, s)
	return grpcServer.Serve(lis)
}

func (s *server) Tunnel(nsrv sandbox.Controller_TunnelServer) error {
	name, port, err := tunnel.ServerHeader(nsrv)
	if err != nil {
		return err
	}

	// TODO, really bad to make an external call on *each connection*  This
	// must be cached in future, or ideally, pre-computed before we start
	// accepting connections.  If kube hangs, every tcp connection will hang
	// and it will feel supper slow to clients.
	//
	// A cache wouldn't be ideal, because you still would have to make the
	// request in the datapath occaisionally.  I.E. the users first
	// experience with this thing will feel super slow.
	//
	// Another option would be an "updater" go routine that just
	// occaisionally checks and writes the results to a sync.Map that this
	// goroutine accesses.  That's likely best case.
	//
	// Note, we're moving away from kube in the sandbox controller so this
	// issue isn't worth fixing with the current code.  Same issue will
	// occur if we have to request IPs from the docker daemon.  Perhaps
	// cilium or something can give us the info we need up front?  This
	// really isn't fixable until we know the new strategy (but it's bad
	// ...)
	dstPod, err := s.kubeClient.CoreV1().Pods(s.namespace).Get(name, metav1.GetOptions{})
	if err != nil {
		msg := fmt.Sprintf("unknown destination")
		return status.New(codes.OutOfRange, msg).Err()
	}

	dialAddr := fmt.Sprintf("%s:%d", dstPod.Status.PodIP, port)
	stream, err := net.Dial("tcp", dialAddr)
	if err != nil {
		return status.New(codes.Internal, err.Error()).Err()
	}

	tunnel.ServerStream(nsrv, stream)
	return nil
}

type server struct {
	kubeClient kubernetes.Interface
	namespace  string
}
