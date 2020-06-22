package main

import (
	"fmt"
	"net"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"

	"github.com/kelda-inc/blimp/node/finalizer"
	"github.com/kelda-inc/blimp/node/wait"
	"github.com/kelda-inc/blimp/pkg/analytics"
	"github.com/kelda-inc/blimp/pkg/ports"
	"github.com/kelda/blimp/pkg/auth"
	"github.com/kelda/blimp/pkg/errors"
	"github.com/kelda/blimp/pkg/names"
	"github.com/kelda/blimp/pkg/proto/node"
	"github.com/kelda/blimp/pkg/tunnel"

	// Install the gzip compressor.
	_ "google.golang.org/grpc/encoding/gzip"
)

const (
	CertPath = "/etc/blimp/certs/cert.pem"
	KeyPath  = "/etc/blimp/certs/key.pem"
)

func main() {
	myNodeName := os.Getenv("NODE_NAME")
	analytics.Init(analytics.StreamID{
		Source:    "node-controller",
		Namespace: myNodeName,
	})

	if myNodeName == "" {
		log.Error("NODE_NAME environment variable is required")
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

	syncTracker := wait.NewSyncTracker()
	go wait.Run(kubeClient, syncTracker)
	finalizer.Start(kubeClient, myNodeName)

	podInformer := informers.NewSharedInformerFactoryWithOptions(
		kubeClient, 30*time.Second).
		Core().V1().Pods()
	go podInformer.Informer().Run(nil)
	cache.WaitForCacheSync(nil, podInformer.Informer().HasSynced)

	s := &server{
		syncTracker: syncTracker,
		podLister:   podInformer.Lister(),
	}
	addr := fmt.Sprintf("0.0.0.0:%d", ports.NodeControllerInternalPort)
	if err := s.listenAndServe(addr); err != nil {
		log.WithError(err).Error("Unexpected error")
		os.Exit(1)
	}
}

type server struct {
	syncTracker *wait.SyncTracker
	podLister   listers.PodLister
}

func (s *server) listenAndServe(address string) error {
	lis, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}

	creds, err := credentials.NewServerTLSFromFile(CertPath, KeyPath)
	if err != nil {
		return errors.WithContext("parse cert", err)
	}

	log.WithField("address", address).Info("Listening for connections..")
	grpcServer := grpc.NewServer(grpc.Creds(creds), grpc.UnaryInterceptor(errors.UnaryServerInterceptor))
	node.RegisterControllerServer(grpcServer, s)
	return grpcServer.Serve(lis)
}

func (s *server) Tunnel(nsrv node.Controller_TunnelServer) error {
	serviceName, port, namespace, err := tunnel.ServerHeader(nsrv)
	if err != nil {
		return err
	}

	// XXX: We don't hash the name of the syncthing pod when deploying it.
	// This weird special case is a sign that the API between the CLI and the
	// Node Controller is poorly designed. We should revisit this when we
	// redesign the other APIs that refer to service names, such as logs and
	// SSH.
	podName := serviceName
	if serviceName != "syncthing" {
		podName = names.PodName(serviceName)
	}

	dstPod, err := s.podLister.Pods(namespace).Get(podName)
	if err != nil {
		return status.New(codes.OutOfRange, "unknown destination").Err()
	}

	dialAddr := fmt.Sprintf("%s:%d", dstPod.Status.PodIP, port)
	stream, err := net.Dial("tcp", dialAddr)
	if err != nil {
		return status.New(codes.Internal, err.Error()).Err()
	}

	tunnel.ServerStream(nsrv, stream)
	return nil
}

func (s *server) SyncNotifications(srv node.Controller_SyncNotificationsServer) error {
	handshake, err := srv.Recv()
	if err != nil {
		return err
	}

	user, err := auth.ParseIDToken(handshake.GetToken(), auth.DefaultVerifier)
	if err != nil {
		return errors.WithContext("validate token", err)
	}

	return s.syncTracker.RunServer(user.Namespace, srv)
}
