package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
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

	"github.com/kelda-inc/blimp/pkg/analytics"
	"github.com/kelda-inc/blimp/pkg/errors"
	"github.com/kelda-inc/blimp/pkg/proto/sandbox"
	"github.com/kelda-inc/blimp/pkg/tunnel"
	"github.com/kelda-inc/blimp/sandbox/sbctl/dns"
	"github.com/kelda-inc/blimp/sandbox/sbctl/wait"
	"github.com/kelda-inc/blimp/sandbox/sbctl/wait/tracker"

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

	analytics.Init(analytics.DirectPoster{}, analytics.StreamID{
		Source:    "sandbox-controller",
		Namespace: namespace,
	})

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

	// Clear the contents of the volume from before `blimp down`.
	for _, path := range os.Args[1:] {
		if err := clearDir(path); err != nil {
			log.WithError(err).WithField("path", path).Fatal("Failed to clear volume contents")
		}
	}

	volumeTracker := tracker.NewVolumeTracker()

	// TODO: Remove need for kubeClient and just query local Docker daemon.
	go dns.Run(kubeClient, namespace)
	go wait.Run(kubeClient, namespace, volumeTracker)

	podInformer := informers.NewSharedInformerFactoryWithOptions(
		kubeClient, 30*time.Second, informers.WithNamespace(namespace)).
		Core().V1().Pods()
	go podInformer.Informer().Run(nil)
	cache.WaitForCacheSync(nil, podInformer.Informer().HasSynced)

	s := &server{
		namespace:     namespace,
		volumeTracker: volumeTracker,
		podLister:     podInformer.Lister(),
	}
	addr := fmt.Sprintf("0.0.0.0:%d", Port)
	if err := s.listenAndServe(addr); err != nil {
		log.WithError(err).Error("Unexpected error")
		os.Exit(1)
	}
}

type server struct {
	namespace     string
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
	sandbox.RegisterControllerServer(grpcServer, s)
	return grpcServer.Serve(lis)
}

func (s *server) Tunnel(nsrv sandbox.Controller_TunnelServer) error {
	name, port, err := tunnel.ServerHeader(s.namespace, nsrv)
	if err != nil {
		return err
	}

	dstPod, err := s.podLister.Pods(s.namespace).Get(name)
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

func (s *server) UpdateVolumeHashes(_ context.Context, req *sandbox.UpdateVolumeHashesRequest) (
	*sandbox.UpdateVolumeHashesResponse, error) {

	s.volumeTracker.Set(req.Hashes)
	return &sandbox.UpdateVolumeHashesResponse{}, nil
}

func clearDir(dir string) error {
	paths, err := ioutil.ReadDir(dir)
	if err != nil {
		return errors.WithContext("read dir", err)
	}

	for _, path := range paths {
		if err := os.RemoveAll(filepath.Join(dir, path.Name())); err != nil {
			return errors.WithContext("remove", err)
		}
	}
	return nil
}
