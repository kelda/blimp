package main

import (
	"context"
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
	"github.com/kelda-inc/blimp/node/wait/tracker"
	"github.com/kelda-inc/blimp/pkg/analytics"
	"github.com/kelda-inc/blimp/pkg/auth"
	"github.com/kelda-inc/blimp/pkg/errors"
	"github.com/kelda-inc/blimp/pkg/ports"
	"github.com/kelda-inc/blimp/pkg/proto/node"
	"github.com/kelda-inc/blimp/pkg/tunnel"

	// Install the gzip compressor.
	_ "google.golang.org/grpc/encoding/gzip"
)

const (
	CertPath = "/etc/blimp/certs/cert.pem"
	KeyPath  = "/etc/blimp/certs/key.pem"
)

func main() {
	myNodeName := os.Getenv("NODE_NAME")
	analytics.Init(analytics.DirectPoster{}, analytics.StreamID{
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

	volumeTracker := tracker.NewVolumeTracker()
	go wait.Run(kubeClient, volumeTracker)
	finalizer.Start(kubeClient, myNodeName)

	podInformer := informers.NewSharedInformerFactoryWithOptions(
		kubeClient, 30*time.Second).
		Core().V1().Pods()
	go podInformer.Informer().Run(nil)
	cache.WaitForCacheSync(nil, podInformer.Informer().HasSynced)

	s := &server{
		volumeTracker: volumeTracker,
		podLister:     podInformer.Lister(),
	}
	addr := fmt.Sprintf("0.0.0.0:%d", ports.NodeControllerInternalPort)
	if err := s.listenAndServe(addr); err != nil {
		log.WithError(err).Error("Unexpected error")
		os.Exit(1)
	}
}

type server struct {
	volumeTracker *tracker.VolumeTracker
	podLister     listers.PodLister
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
	name, port, namespace, err := tunnel.ServerHeader(nsrv)
	if err != nil {
		return err
	}

	dstPod, err := s.podLister.Pods(namespace).Get(name)
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

func (s *server) UpdateVolumeHashes(_ context.Context, req *node.UpdateVolumeHashesRequest) (
	*node.UpdateVolumeHashesResponse, error) {

	user, err := auth.ParseIDToken(req.GetToken())
	if err != nil {
		return &node.UpdateVolumeHashesResponse{}, errors.WithContext("validate token", err)
	}

	s.volumeTracker.Set(user.Namespace, req.Hashes)
	return &node.UpdateVolumeHashesResponse{}, nil
}
