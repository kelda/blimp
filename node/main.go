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

	"github.com/kelda/blimp/node/wait"
	"github.com/kelda/blimp/pkg/auth"
	"github.com/kelda/blimp/pkg/errors"
	"github.com/kelda/blimp/pkg/expose"
	"github.com/kelda/blimp/pkg/kube"
	"github.com/kelda/blimp/pkg/names"
	"github.com/kelda/blimp/pkg/ports"
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

	podInformer := informers.NewSharedInformerFactoryWithOptions(
		kubeClient, 30*time.Second).
		Core().V1().Pods()
	go podInformer.Informer().Run(nil)
	cache.WaitForCacheSync(nil, podInformer.Informer().HasSynced)

	nsInformer := informers.NewSharedInformerFactoryWithOptions(
		kubeClient, 30*time.Second).
		Core().V1().Namespaces()
	go nsInformer.Informer().Run(nil)
	cache.WaitForCacheSync(nil, nsInformer.Informer().HasSynced)

	s := &server{
		syncTracker: syncTracker,
		podLister:   podInformer.Lister(),
		nsLister:    nsInformer.Lister(),
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
	nsLister    listers.NamespaceLister
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
	msg, err := nsrv.Recv()
	if err != nil {
		return err
	}

	header := msg.GetHeader()
	if header == nil {
		return status.New(codes.Internal, "first message must be a header").Err()
	}

	user, err := auth.AuthorizeRequest(auth.GetAuth(header))
	if err != nil {
		return errors.WithContext("bad token", err)
	}

	// XXX: We don't hash the name of the syncthing pod when deploying it.
	// This weird special case is a sign that the API between the CLI and the
	// Node Controller is poorly designed. We should revisit this when we
	// redesign the other APIs that refer to service names, such as logs and
	// SSH.
	podName := header.Name
	if header.Name != kube.PodNameSyncthing && header.Name != kube.PodNameBuildkitd {
		podName = names.PodName(header.Name)
	}

	dstPod, err := s.podLister.Pods(user.Namespace).Get(podName)
	if err != nil {
		return status.New(codes.OutOfRange, "unknown destination").Err()
	}

	dialAddr := fmt.Sprintf("%s:%d", dstPod.Status.PodIP, header.Port)
	stream, err := net.Dial("tcp", dialAddr)
	if err != nil {
		return status.New(codes.Internal, err.Error()).Err()
	}

	tunnel.ServerStream(nsrv, stream)
	return nil
}

func (s *server) ExposedTunnel(nsrv node.Controller_ExposedTunnelServer) error {
	msg, err := nsrv.Recv()
	if err != nil {
		return status.New(codes.Internal, err.Error()).Err()
	}

	header := msg.GetExposedHeader()
	if header == nil {
		return status.New(codes.Internal, "first message must be a header").Err()
	}

	namespace, err := s.nsLister.Get(header.Namespace)
	if err != nil {
		return status.New(codes.OutOfRange, "unknown destination").Err()
	}

	annotationJson, ok := namespace.Annotations[kube.ExposeAnnotation]
	if !ok {
		// For security, if nothing is exposed, don't leak that the namespace exists.
		return status.New(codes.OutOfRange, "unknown destination").Err()
	}

	annotation, err := expose.ParseJsonAnnotation(annotationJson)
	if err != nil {
		log.WithError(err).Error("Failed to parse expose annotation")
		return status.New(codes.Internal, "failed to parse expose annotation").Err()
	}

	info, ok := annotation[header.Token]
	if !ok {
		return status.New(codes.OutOfRange, "unknown destination").Err()
	}

	podName := names.PodName(info.Service)

	dstPod, err := s.podLister.Pods(header.Namespace).Get(podName)
	if err != nil {
		return status.New(codes.OutOfRange, "unknown destination").Err()
	}

	dialAddr := fmt.Sprintf("%s:%d", dstPod.Status.PodIP, info.Port)
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

	user, err := auth.AuthorizeRequest(auth.GetAuth(handshake))
	if err != nil {
		return errors.WithContext("validate token", err)
	}

	return s.syncTracker.RunServer(user.Namespace, srv)
}
