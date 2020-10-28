package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/Masterminds/semver"
	"github.com/golang/protobuf/proto"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	composeTypes "github.com/kelda/compose-go/types"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/retry"

	"github.com/kelda/blimp/cluster-controller/affinity"
	"github.com/kelda/blimp/cluster-controller/httpapi"
	"github.com/kelda/blimp/cluster-controller/node"
	"github.com/kelda/blimp/cluster-controller/volume"
	"github.com/kelda/blimp/pkg/auth"
	clusterAuth "github.com/kelda/blimp/pkg/auth"
	"github.com/kelda/blimp/pkg/dockercompose"
	"github.com/kelda/blimp/pkg/errors"
	"github.com/kelda/blimp/pkg/expose"
	"github.com/kelda/blimp/pkg/kube"
	"github.com/kelda/blimp/pkg/kubewait"
	"github.com/kelda/blimp/pkg/metadata"
	"github.com/kelda/blimp/pkg/names"
	"github.com/kelda/blimp/pkg/ports"
	protoAuth "github.com/kelda/blimp/pkg/proto/auth"
	"github.com/kelda/blimp/pkg/proto/cluster"
	"github.com/kelda/blimp/pkg/syncthing"
	"github.com/kelda/blimp/pkg/version"
	"k8s.io/apimachinery/pkg/api/resource"

	// Install the gzip compressor.
	_ "google.golang.org/grpc/encoding/gzip"

	// Load the client authentication plugin necessary for connecting to GKE.
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
)

type server struct {
	kubeClient        kubernetes.Interface
	restConfig        *rest.Config
	statusFetcher     *statusFetcher
	certPath, keyPath string
	maxSandboxes      int
}

var (
	// RegistryHostname is set by make, or by the environment variable
	// BLIMP_REGISTRY_HOSTNAME.
	RegistryHostname string

	// LinkProxyBaseHostname is the base hostname for Blimp preview links. It
	// should match base hostname used in the link proxy.
	LinkProxyBaseHostname string
)

// MaxServices is the maximum number of service pods allowed in a single
// sandbox.
const MaxServices = 150

func main() {
	kubeClient, restConfig, err := kube.GetClient()
	if err != nil {
		log.WithError(err).Error("Failed to connect to customer cluster")
		os.Exit(1)
	}

	certPath := flag.String("tls-cert", "", "The path to the PEM-encoded certificate used for encrypting gRPC")
	keyPath := flag.String("tls-key", "", "The path to the PEM-encoded private key used for encrypting gRPC")
	flag.Parse()

	if *certPath == "" || *keyPath == "" {
		log.Fatal("The TLS cert and key are required")
	}

	if registryHostnameVar, ok := os.LookupEnv("BLIMP_REGISTRY_HOSTNAME"); ok {
		RegistryHostname = registryHostnameVar
	}

	if linkProxyBaseHostnameVar, ok := os.LookupEnv("BLIMP_LINK_PROXY_BASE_HOSTNAME"); ok {
		LinkProxyBaseHostname = linkProxyBaseHostnameVar
	}

	maxSandboxes := 100
	if maxSandboxesVar, ok := os.LookupEnv("MAX_SANDBOXES"); ok {
		parsedVar, err := strconv.Atoi(maxSandboxesVar)
		if err != nil {
			log.WithError(err).WithField("MAX_SANDBOXES", maxSandboxesVar).
				Warn("Couldn't parse $MAX_SANDBOXES")
		} else {
			maxSandboxes = parsedVar
		}
	}
	log.Infof("Capping maximum concurrent sandboxes to %d", maxSandboxes)

	s := &server{
		statusFetcher: newStatusFetcher(kubeClient),
		kubeClient:    kubeClient,
		restConfig:    restConfig,
		certPath:      *certPath,
		keyPath:       *keyPath,
		maxSandboxes:  maxSandboxes,
	}
	s.statusFetcher.Start(nil)

	useNodePort := os.Getenv("USE_NODE_PORT_FOR_NODE_CONTROLLER") == "true"
	node.StartControllerBooter(kubeClient, useNodePort)

	if err := s.listenAndServe(); err != nil {
		log.WithError(err).Error("Unexpected error")
		os.Exit(1)
	}
}

func (s *server) listenAndServe() error {
	grpcAddr := fmt.Sprintf(":%d", ports.ClusterManagerGRPCInternalPort)
	httpAddr := fmt.Sprintf(":%d", ports.ClusterManagerHTTPInternalPort)

	// Start the gRPC server.
	grpcLis, err := net.Listen("tcp", grpcAddr)
	if err != nil {
		return err
	}

	grpcCreds, err := credentials.NewServerTLSFromFile(s.certPath, s.keyPath)
	if err != nil {
		return errors.WithContext("parse cert", err)
	}

	grpcServer := grpc.NewServer(grpc.Creds(grpcCreds), grpc.UnaryInterceptor(errors.UnaryServerInterceptor))
	cluster.RegisterManagerServer(grpcServer, s)

	serveGrpcErr := make(chan error, 1)
	go func() {
		serveGrpcErr <- grpcServer.Serve(grpcLis)
	}()

	// Start the HTTP server.
	httpServer, err := httpapi.NewServer(httpAddr, map[string]httpapi.Handler{
		"/api/blimp-up-preview": httpapi.StreamHandler{
			RequestType: &cluster.BlimpUpPreviewRequest{},
			RPC: func(req proto.Message, wss httpapi.WebSocketStream) error {
				shim := &blimpUpPreviewShim{WebSocketStream: wss}
				return s.BlimpUpPreview(req.(*cluster.BlimpUpPreviewRequest), shim)
			},
		},
		"/api/delete-sandbox": httpapi.UnaryHandler{RPC: s.DeleteSandbox},
		"/api/expose":         httpapi.UnaryHandler{RPC: s.Expose},
		"/api/watch-status": httpapi.StreamHandler{
			RequestType: &cluster.GetStatusRequest{},
			RPC: func(req proto.Message, wss httpapi.WebSocketStream) error {
				shim := &watchStatusShim{WebSocketStream: wss}
				return s.WatchStatus(req.(*cluster.GetStatusRequest), shim)
			},
		},
	})
	if err != nil {
		return errors.WithContext("create http api server", err)
	}

	serveHTTPErr := make(chan error, 1)
	go func() {
		serveHTTPErr <- httpServer.ListenAndServe()
	}()

	log.WithField("address", grpcAddr).Info("Listening for grpc connections..")
	log.WithField("address", httpAddr).Info("Listening for http connections..")
	select {
	case err := <-serveHTTPErr:
		return errors.WithContext("serve http", err)
	case err := <-serveGrpcErr:
		return errors.WithContext("serve grpc", err)
	}
}

func (s *server) CheckVersion(ctx context.Context, req *cluster.CheckVersionRequest) (
	*cluster.CheckVersionResponse, error) {

	clientVersionStr := req.GetVersion()
	if clientVersionStr == "latest" || version.Version == "latest" {
		// Running in development, so don't complain about version.
		return &cluster.CheckVersionResponse{
			Version:        version.Version,
			DisplayMessage: "",
			Action:         cluster.CLIAction_OK,
		}, nil
	}

	clientVersion, err := semver.NewVersion(clientVersionStr)
	if err != nil {
		log.WithError(err).WithField("version", clientVersionStr).Warn("Failed to parse client version")
		return &cluster.CheckVersionResponse{
			Version:        version.Version,
			DisplayMessage: "",
			Action:         cluster.CLIAction_OK,
		}, nil
	}

	c, err := semver.NewConstraint(">= 0.13.0")
	if err != nil {
		log.WithError(err).Warn("Failed to create version constraint")
		return &cluster.CheckVersionResponse{
			Version:        version.Version,
			DisplayMessage: "",
			Action:         cluster.CLIAction_OK,
		}, nil
	}

	if !c.Check(clientVersion) {
		return &cluster.CheckVersionResponse{
			Version: version.Version,
			DisplayMessage: "CLI version is incompatible with server. " +
				"Please upgrade by running:\n\n" +
				"curl -fsSL 'https://blimpup.io/get-blimp.sh' | sh\n\n" +
				"Or brew upgrade kelda/tools/blimp",
			Action: cluster.CLIAction_EXIT,
		}, nil
	}

	return &cluster.CheckVersionResponse{
		Version:        version.Version,
		DisplayMessage: "",
		Action:         cluster.CLIAction_OK,
	}, nil
}

func (s *server) AttachToSandbox(ctx context.Context, req *cluster.AttachToSandboxRequest) (
	*cluster.AttachToSandboxResponse, error) {
	log.Info("Start AttachToSandbox")

	// Validate that the user logged in, and get their information.
	user, err := clusterAuth.AuthorizeRequest(clusterAuth.GetAuth(req))
	if err != nil {
		return &cluster.AttachToSandboxResponse{}, err
	}

	_, err = s.kubeClient.CoreV1().Namespaces().Get(user.Namespace, metav1.GetOptions{})
	if err != nil {
		if kerrors.IsNotFound(err) {
			return &cluster.AttachToSandboxResponse{}, errors.NewFriendlyError("Sandbox does not exist")
		}
		return &cluster.AttachToSandboxResponse{}, errors.WithContext("get sandbox", err)
	}

	dnsPod, err := s.getPod(ctx, user.Namespace, "dns", podIsScheduled)
	if err != nil {
		return &cluster.AttachToSandboxResponse{}, errors.WithContext("get sandbox node", err)
	}

	nodeAddress, nodeCert, err := node.GetConnectionInfo(ctx, s.kubeClient, dnsPod.Spec.NodeName)
	if err != nil {
		return &cluster.AttachToSandboxResponse{}, errors.WithContext("get node connection info", err)
	}

	cliCreds, err := s.createCLICreds(ctx, user.Namespace)
	if err != nil {
		return &cluster.AttachToSandboxResponse{}, errors.WithContext("get kube credentials", err)
	}

	return &cluster.AttachToSandboxResponse{
		NodeAddress:     nodeAddress,
		NodeCert:        nodeCert,
		KubeCredentials: &cliCreds,
	}, nil
}

func (s *server) GetBuildkit(ctx context.Context, req *cluster.GetBuildkitRequest) (
	*cluster.GetBuildkitResponse, error) {
	log.Info("Start GetBuildkit")

	// Validate that the user logged in, and get their information.
	user, err := clusterAuth.AuthorizeRequest(clusterAuth.GetAuth(req))
	if err != nil {
		return &cluster.GetBuildkitResponse{}, err
	}

	// Even if this is called at the same time as CreateSandbox, these calls
	// should be okay since they should be idempotent.

	_, err = s.kubeClient.CoreV1().Namespaces().Get(user.Namespace, metav1.GetOptions{})
	if err != nil {
		if !kerrors.IsNotFound(err) {
			return &cluster.GetBuildkitResponse{}, errors.WithContext("get sandbox", err)
		}

		if err := s.createNamespace(ctx, user.Namespace); err != nil {
			return &cluster.GetBuildkitResponse{}, errors.WithContext("create namespace", err)
		}
	}

	if err := createBuildkitd(s.kubeClient, user.Namespace); err != nil {
		return &cluster.GetBuildkitResponse{}, errors.WithContext("deploy buildkitd", err)
	}

	buildkitPod, err := s.getPod(ctx, user.Namespace, kube.PodNameBuildkitd, podIsReady)
	if err != nil {
		return &cluster.GetBuildkitResponse{}, errors.WithContext("buildkit never started", err)
	}

	nodeAddress, nodeCert, err := node.GetConnectionInfo(ctx, s.kubeClient, buildkitPod.Spec.NodeName)
	if err != nil {
		return &cluster.GetBuildkitResponse{}, errors.WithContext("get node connection info", err)
	}

	return &cluster.GetBuildkitResponse{
		NodeAddress: nodeAddress,
		NodeCert:    nodeCert,
	}, nil
}

func (s *server) GetImageNamespace(ctx context.Context, req *cluster.GetImageNamespaceRequest) (
	*cluster.GetImageNamespaceResponse, error) {
	log.Info("Start GetImageNamespace")

	user, err := clusterAuth.AuthorizeRequest(clusterAuth.GetAuth(req))
	if err != nil {
		return &cluster.GetImageNamespaceResponse{}, err
	}

	return &cluster.GetImageNamespaceResponse{
		Namespace: fmt.Sprintf("%s/%s", RegistryHostname, user.Namespace),
	}, nil
}

func (s *server) CreateSandbox(ctx context.Context, req *cluster.CreateSandboxRequest) (
	*cluster.CreateSandboxResponse, error) {
	log.Info("Start CreateSandbox")

	// Validate that the user logged in, and get their information.
	user, err := clusterAuth.AuthorizeRequest(clusterAuth.GetAuth(req))
	if err != nil {
		return &cluster.CreateSandboxResponse{}, err
	}

	dcCfg, err := dockercompose.Unmarshal([]byte(req.GetComposeFile()))
	if err != nil {
		return &cluster.CreateSandboxResponse{}, errors.WithContext("unmarshal compose file", err)
	}

	// If the user has already booted a sandbox, don't count it against the
	// total.  This will allow you to boot if you already have a sandbox
	// namespace, unless the number of sandboxes is OVER the maximum.
	notThisUser, err := labels.NewRequirement("namespace", "!=", []string{user.Namespace})
	if err != nil {
		return &cluster.CreateSandboxResponse{}, errors.WithContext("parse selector requirement", err)
	}
	selector := labels.Set{"blimp.sandbox": "true"}.AsSelector().Add(*notThisUser)
	sandboxes, err := s.statusFetcher.namespaceLister.List(selector)
	if err != nil {
		return &cluster.CreateSandboxResponse{}, errors.WithContext("list namespaces", err)
	}
	if len(sandboxes) >= s.maxSandboxes {
		return &cluster.CreateSandboxResponse{}, errors.NewFriendlyError(
			"Sorry, the Blimp servers are overloaded right now.\n" +
				"Please try again later.")
	}

	composeFileIssues := ValidateComposeFile(dcCfg)
	if len(composeFileIssues) > 0 {
		prettyIssues := ""
		for _, issue := range composeFileIssues {
			prettyIssues += fmt.Sprintf("- %s\n", issue)
		}

		err := errors.NewFriendlyError(
			"We found the following issues with your Docker Compose file:\n" +
				prettyIssues +
				"Please fix these and try blimp up again!")
		return &cluster.CreateSandboxResponse{}, err
	}

	namespace := user.Namespace
	if err := s.createNamespace(ctx, namespace); err != nil {
		return &cluster.CreateSandboxResponse{}, errors.WithContext("create namespace", err)
	}

	// If customer pods are already present in the namespace, don't worry about
	// creating a reservation pod.
	customerPods, err := s.statusFetcher.podLister.Pods(namespace).
		List(labels.Set{"blimp.customerPod": "true"}.AsSelector())
	if err != nil {
		return &cluster.CreateSandboxResponse{}, errors.WithContext("list customer pods", err)
	}

	if len(customerPods) == 0 {
		// Create a pod that has the same resource requests as the pods that
		// will ultimately be deployed, to make sure that the namespace is
		// scheduled on a node that ultimately will be able to handle the
		// workload.
		if err := s.createReservation(user, len(dcCfg.Services)); err != nil {
			return &cluster.CreateSandboxResponse{}, errors.WithContext("deploy reservation", err)
		}

		// Wait until the reservation pod is scheduled before creating the other
		// pods, to make sure that the reservation pod is scheduled first.
		_, err := s.getPod(ctx, namespace, "reservation", podIsScheduled)
		if err != nil {
			pod, getErr := s.kubeClient.CoreV1().Pods(namespace).Get("reservation", metav1.GetOptions{})
			// Specifically handle unscheduled case with a nice error message.
			if getErr == nil && isUnschedulable(pod) {
				return &cluster.CreateSandboxResponse{}, errors.NewFriendlyError(
					"Failed to schedule your sandbox. The blimp servers may be overloaded.")
			}
			return &cluster.CreateSandboxResponse{}, errors.WithContext("get reservation pod", err)
		}
	}

	if err := s.createSyncthing(user, req.GetSyncedFolders()); err != nil {
		return &cluster.CreateSandboxResponse{}, errors.WithContext("deploy syncthing", err)
	}

	if err := createBuildkitd(s.kubeClient, namespace); err != nil {
		return &cluster.CreateSandboxResponse{}, errors.WithContext("deploy buildkitd", err)
	}

	if err := s.deployDNS(user); err != nil {
		return &cluster.CreateSandboxResponse{}, errors.WithContext("deploy dns", err)
	}

	// Wait until the DNS pod is scheduled so that we know what node the other
	// pods in the namespace will get scheduled on.
	dnsPod, err := s.getPod(ctx, namespace, "dns", podIsScheduled)
	if err != nil {
		return &cluster.CreateSandboxResponse{}, errors.WithContext("get dns pod", err)
	}

	nodeAddress, nodeCert, err := node.GetConnectionInfo(ctx, s.kubeClient, dnsPod.Spec.NodeName)
	if err != nil {
		return &cluster.CreateSandboxResponse{}, errors.WithContext("get node controller", err)
	}

	creds := req.GetRegistryCredentials()
	if creds == nil {
		creds = map[string]*cluster.RegistryCredential{}
	}

	blimpRegCred, err := auth.BlimpRegcred(clusterAuth.GetAuth(req))
	if err != nil {
		return &cluster.CreateSandboxResponse{}, errors.WithContext("create Blimp registry credential", err)
	}
	creds[RegistryHostname] = blimpRegCred.ToProtobuf()
	if err := s.createPodRunnerServiceAccount(namespace, creds); err != nil {
		return &cluster.CreateSandboxResponse{}, errors.WithContext("create pod runner service account", err)
	}

	cliCreds, err := s.createCLICreds(ctx, namespace)
	if err != nil {
		return &cluster.CreateSandboxResponse{}, errors.WithContext("get kube credentials", err)
	}

	var featuresMsg string
	unsupportedFeatures := GetUnsupportedFeatures(dcCfg)
	if len(unsupportedFeatures) > 0 {
		featuresMsg = fmt.Sprintf("WARNING: Docker Compose file uses features unsupported by Kelda Blimp: %v\n"+
			"Blimp will attempt to continue to boot.\n"+
			"We're working on reaching full parity with Docker Compose.\n"+
			"Ping us in Slack (http://slack.blimpup.io) to request support for features!",
			unsupportedFeatures)
	}

	// Block the RPC on the buildkit pod starting up so that the CLI doesn't
	// try to build before buildkit is running.
	// We make this check as late as possible so that we can do other work
	// while Kubernetes boots the pod.
	if _, err := s.getPod(ctx, namespace, kube.PodNameBuildkitd, podIsReady); err != nil {
		return &cluster.CreateSandboxResponse{}, errors.WithContext("buildkit never started", err)
	}

	return &cluster.CreateSandboxResponse{
		NodeAddress:     nodeAddress,
		NodeCert:        nodeCert,
		ImageNamespace:  fmt.Sprintf("%s/%s", RegistryHostname, namespace),
		KubeCredentials: &cliCreds,
		Message:         featuresMsg,
	}, nil
}

func (s *server) DeployToSandbox(ctx context.Context, req *cluster.DeployRequest) (*cluster.DeployResponse, error) {
	// Validate that the user logged in, and get their information.
	user, err := clusterAuth.AuthorizeRequest(clusterAuth.GetAuth(req))
	if err != nil {
		return &cluster.DeployResponse{}, err
	}

	dcCfg, err := dockercompose.Unmarshal([]byte(req.GetComposeFile()))
	if err != nil {
		return &cluster.DeployResponse{}, err
	}

	namespace := user.Namespace
	dnsPod, err := s.getPod(ctx, namespace, "dns", podIsReady)
	if err != nil {
		return &cluster.DeployResponse{}, errors.WithContext("get dns server's IP", err)
	}

	nodeControllerIP, err := node.GetNodeControllerInternalIP(s.kubeClient, dnsPod.Spec.NodeName)
	if err != nil {
		return &cluster.DeployResponse{}, errors.WithContext("get node controller's IP", err)
	}

	customerPods, configMaps, err := toPods(user, dnsPod.Status.PodIP, nodeControllerIP, dcCfg, req.BuiltImages)
	if err != nil {
		return &cluster.DeployResponse{}, errors.WithContext("make pod specs", err)
	}

	// TODO: Garbage collect config maps.
	for _, configMap := range configMaps {
		if err := kube.DeployConfigMap(s.kubeClient, configMap); err != nil {
			return &cluster.DeployResponse{}, errors.WithContext("create configmap", err)
		}
	}

	log.WithField("namespace", namespace).
		WithField("numPods", len(customerPods)).
		Info("Deploying customer pods")
	if err := s.deployCustomerPods(namespace, customerPods); err != nil {
		return &cluster.DeployResponse{}, errors.WithContext("boot customer pods", err)
	}
	return &cluster.DeployResponse{}, nil
}

func (s *server) createNamespace(ctx context.Context, namespace string) error {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: namespace,
			Labels: map[string]string{
				// Referenced by the network policy.
				"namespace":     namespace,
				"blimp.sandbox": "true",
			},
		},
	}

	policy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns.Name,
			Name:      "namespace",
		},
		Spec: networkingv1.NetworkPolicySpec{
			// TODO: Restrict Egress as well.
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					From: []networkingv1.NetworkPolicyPeer{

						// Allow traffic any pod in the same namespace.
						// Pods in this namespace can also communicate with the
						// node controller since we don't have an ingress rule
						// for the blimp-system namespace.
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"namespace": ns.Name,
								},
							},
						},

						// Allow the node controllers to forward traffic to
						// customer pods.
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"namespace": node.NodeControllerNamespace,
								},
							},
						},
					},
				},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
			},
		},
	}

	namespaceClient := s.kubeClient.CoreV1().Namespaces()
	existingNs, err := namespaceClient.Get(ns.Name, metav1.GetOptions{})
	switch {
	case err == nil:
		if existingNs.Status.Phase == corev1.NamespaceTerminating {
			return errors.NewFriendlyError(
				"Aborting deployment because sandbox is terminating.\n" +
					"This is a transient error caused by `blimp down` not completing yet.\n" +
					"Try again in 30 seconds.")
		}
	case !kerrors.IsNotFound(err):
		return errors.WithContext("get namespace", err)
	default:
		// We only create the namespace if it doesn't already exist.
		if _, err := namespaceClient.Create(ns); err != nil {
			return errors.WithContext("create namespace", err)
		}
	}

	networkingClient := s.kubeClient.NetworkingV1().NetworkPolicies(ns.Name)
	if _, err := networkingClient.Get(policy.Name, metav1.GetOptions{}); kerrors.IsNotFound(err) {
		if _, err := networkingClient.Create(policy); err != nil {
			return errors.WithContext("create network policy", err)
		}
	} else if err != nil {
		return errors.WithContext("get network policy", err)
	}

	if err := volume.CreatePVC(ctx, s.kubeClient, namespace); err != nil {
		return errors.WithContext("create persistent volume claim", err)
	}

	// Wait for the default service account to exist before returning.
	// Pods will fail to deploy to the namespace until the account exists.
	ctx, _ = context.WithTimeout(ctx, 3*time.Minute)
	err = kubewait.WaitForObject(ctx,
		kubewait.ServiceAccountGetter(s.kubeClient, namespace, "default"),
		s.kubeClient.CoreV1().ServiceAccounts(namespace).Watch,
		func(saIntf interface{}) bool {
			return true
		})
	if err != nil {
		return errors.WithContext("wait for default service account", err)
	}
	return nil
}

func (s *server) getPod(ctx context.Context, namespace, name string, cond podCondition) (pod *corev1.Pod, err error) {
	ctx, _ = context.WithTimeout(ctx, 3*time.Minute)
	err = kubewait.WaitForObject(ctx,
		kubewait.PodGetter(s.kubeClient, namespace, name),
		s.kubeClient.CoreV1().Pods(namespace).Watch,
		func(podIntf interface{}) bool {
			pod = podIntf.(*corev1.Pod)
			return cond(pod)
		})
	if err != nil {
		return nil, err
	}

	return pod, nil
}

func (s *server) createReservation(user auth.User, numServices int) error {
	cpu := resource.MustParse(
		fmt.Sprintf("%d%s", cpuRequest*numServices, cpuRequestUnits))
	memory := resource.MustParse(
		fmt.Sprintf("%d%s", memoryRequest*numServices, memoryRequestUnits))

	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: user.Namespace,
			Name:      "reservation",
			Labels: map[string]string{
				"service":                     "reservation",
				affinity.ColocateNamespaceKey: user.Namespace,
				// We set blimp.customerPod=true so that the pod will get
				// cleaned up when the actual sandbox is deployed.
				"blimp.customerPod": "true",
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "reservation",
				Image: version.ReservationImage,
				Resources: corev1.ResourceRequirements{
					Requests: corev1.ResourceList{
						"cpu":    cpu,
						"memory": memory,
					},
				},
			}},
			Affinity: affinity.ForUser(user),
		},
	}

	if err := kube.DeployPod(s.kubeClient, pod, kube.DeployPodOptions{}); err != nil {
		return errors.WithContext("deploy pod", err)
	}
	return nil
}

func (s *server) createSyncthing(user auth.User, syncedFolders map[string]string) error {
	mount := corev1.VolumeMount{
		Name:      volume.PersistentVolume.Name,
		MountPath: "/pv",
	}

	idPathMap := map[string]string{}
	for id, src := range syncedFolders {
		idPathMap[id] = filepath.Join(mount.MountPath, volume.BindVolumeDir(src))
	}

	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: user.Namespace,
			Name:      kube.PodNameSyncthing,
			Labels: map[string]string{
				"service":                     kube.PodNameSyncthing,
				affinity.ColocateNamespaceKey: user.Namespace,
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:         kube.PodNameSyncthing,
				Image:        version.SyncthingImage,
				Args:         syncthing.MapToArgs(idPathMap),
				VolumeMounts: []corev1.VolumeMount{mount},
				Resources: corev1.ResourceRequirements{
					Limits: corev1.ResourceList{
						"cpu":    resource.MustParse("1"),
						"memory": resource.MustParse("1Gi"),
					},
					Requests: corev1.ResourceList{
						"cpu":    resource.MustParse("100m"),
						"memory": resource.MustParse("100Mi"),
					},
				},
			}},
			Volumes:  []corev1.Volume{volume.PersistentVolume},
			Affinity: affinity.ForUser(user),
		},
	}

	opts := kube.DeployPodOptions{
		Sanitizers: []kube.Sanitizer{kube.SanitizeIgnoreNodeAffinity},
	}
	if err := kube.DeployPod(s.kubeClient, pod, opts); err != nil {
		return errors.WithContext("deploy pod", err)
	}
	return nil
}

func (s *server) deployDNS(user auth.User) error {
	namespace := user.Namespace
	serviceAccount := corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "dns",
			Namespace: namespace,
		},
	}

	role := rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      "dns-role",
		},
		Rules: []rbacv1.PolicyRule{
			// List all pods in the namespace.
			{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"get", "list", "watch"},
			},
		},
	}
	if err := kube.DeployServiceAccount(s.kubeClient, serviceAccount, role); err != nil {
		return errors.WithContext("create dns service account", err)
	}

	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      "dns",
			Labels: map[string]string{
				"service":                     "dns",
				affinity.ColocateNamespaceKey: namespace,
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "dns",
				Env: []corev1.EnvVar{
					{
						Name: "NAMESPACE",
						ValueFrom: &corev1.EnvVarSource{
							FieldRef: &corev1.ObjectFieldSelector{
								FieldPath: "metadata.namespace",
							},
						},
					},
				},
				Image: version.DNSImage,
				Resources: corev1.ResourceRequirements{
					Limits: corev1.ResourceList{
						"cpu":    resource.MustParse("1"),
						"memory": resource.MustParse("1Gi"),
					},
					Requests: corev1.ResourceList{
						"cpu":    resource.MustParse("100m"),
						"memory": resource.MustParse("100Mi"),
					},
				},
			}},
			Affinity:           affinity.ForUser(user),
			ServiceAccountName: serviceAccount.Name,
		},
	}

	opts := kube.DeployPodOptions{
		Sanitizers: []kube.Sanitizer{kube.SanitizeIgnoreNodeAffinity},
	}
	if err := kube.DeployPod(s.kubeClient, pod, opts); err != nil {
		return errors.WithContext("deploy pod", err)
	}
	return nil
}

func (s *server) createCLICreds(ctx context.Context, namespace string) (cluster.KubeCredentials, error) {
	serviceAccount := corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      "blimp-client",
		},
	}

	role := rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      "blimp-client",
		},
		Rules: []rbacv1.PolicyRule{
			// Needed for `blimp logs`.
			{
				APIGroups: []string{""},
				Resources: []string{"pods/log"},
				Verbs:     []string{"get", "list"},
			},

			// Needed for `blimp ssh` and `blimp cp`.
			{
				APIGroups: []string{""},
				Resources: []string{"pods/exec"},
				Verbs:     []string{"create"},
			},

			// Get needed for `blimp cp`. Get and watch needed for `blimp logs`.
			{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"get", "watch"},
			},
		},
	}

	if err := kube.DeployServiceAccount(s.kubeClient, serviceAccount, role); err != nil {
		return cluster.KubeCredentials{}, errors.WithContext("create service account", err)
	}

	// Wait until the ServiceAccount's secret is populated.
	var secretName string
	ctx, _ = context.WithTimeout(ctx, 3*time.Minute)
	err := kubewait.WaitForObject(ctx,
		kubewait.ServiceAccountGetter(s.kubeClient, namespace, serviceAccount.Name),
		s.kubeClient.CoreV1().ServiceAccounts(namespace).Watch,
		func(saIntf interface{}) bool {
			sa := saIntf.(*corev1.ServiceAccount)

			if len(sa.Secrets) == 1 {
				secretName = sa.Secrets[0].Name
				return true
			}
			return false
		})
	if err != nil {
		return cluster.KubeCredentials{}, errors.WithContext("wait for service account secret", err)
	}

	secret, err := s.kubeClient.CoreV1().Secrets(namespace).
		Get(secretName, metav1.GetOptions{})
	if err != nil {
		return cluster.KubeCredentials{}, errors.WithContext("get token", err)
	}

	token, ok := secret.Data["token"]
	if !ok {
		return cluster.KubeCredentials{}, errors.New("missing token")
	}

	caCrt, ok := secret.Data["ca.crt"]
	if !ok {
		return cluster.KubeCredentials{}, errors.New("missing CA")
	}

	return cluster.KubeCredentials{
		Host:      s.restConfig.Host,
		CaCrt:     string(caCrt),
		Token:     string(token),
		Namespace: namespace,
	}, nil
}

// toDockerAuthConfig converts the given registry credentials into the
// dockerconfig format that's used by Kubernetes image pull secrets.
func toDockerAuthConfig(creds map[string]*cluster.RegistryCredential) (string, error) {
	type credential struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	auths := map[string]credential{}
	for host, cred := range creds {
		auths[host] = credential{cred.Username, cred.Password}
	}

	dockerConfig, err := json.Marshal(map[string]map[string]credential{"auths": auths})
	return string(dockerConfig), err
}

func (s *server) createPodRunnerServiceAccount(namespace string,
	registryCredentials map[string]*cluster.RegistryCredential) error {
	dockerAuthConfig, err := toDockerAuthConfig(registryCredentials)
	if err != nil {
		return errors.WithContext("marshal docker auth config", err)
	}

	secret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			// TODO: Variable, shared with toPods.
			Name:      "registry-auth",
			Namespace: namespace,
		},
		Type: corev1.SecretTypeDockerConfigJson,
		StringData: map[string]string{
			corev1.DockerConfigJsonKey: dockerAuthConfig,
		},
	}

	serviceAccount := corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod-runner",
			Namespace: namespace,
		},
		ImagePullSecrets: []corev1.LocalObjectReference{
			{Name: secret.Name},
		},
	}

	secretClient := s.kubeClient.CoreV1().Secrets(namespace)
	currSecret, err := secretClient.Get(secret.Name, metav1.GetOptions{})
	if err == nil {
		secret.ResourceVersion = currSecret.ResourceVersion
		if _, err := secretClient.Update(&secret); err != nil {
			return errors.WithContext("update regcred secret", err)
		}
	} else if _, err := secretClient.Create(&secret); err != nil {
		return errors.WithContext("create regcred secret", err)
	}

	return kube.DeployServiceAccount(s.kubeClient, serviceAccount)
}

func (s *server) deployCustomerPods(namespace string, desired []corev1.Pod) error {
	currPods, err := s.kubeClient.CoreV1().Pods(namespace).List(metav1.ListOptions{
		LabelSelector: "blimp.customerPod=true",
	})
	if err != nil {
		return errors.WithContext("list", err)
	}

	// TODO: Parallelize
	desiredNames := map[string]struct{}{}
	for _, pod := range desired {
		opts := kube.DeployPodOptions{
			Sanitizers: []kube.Sanitizer{
				kube.SanitizeIgnoreInitContainerImages,
				kube.SanitizeIgnoreNodeAffinity,
			},
		}
		if err := kube.DeployPod(s.kubeClient, pod, opts); err != nil {
			return errors.WithContext("create", err)
		}
		desiredNames[pod.Name] = struct{}{}
	}

	// Delete any stale pods.
	for _, pod := range currPods.Items {
		if _, ok := desiredNames[pod.Name]; !ok {
			if err := kube.DeletePod(s.kubeClient, pod.Namespace, pod.Name); err != nil {
				return errors.WithContext("delete", err)
			}
		}
	}
	return nil
}

func (s *server) DeleteSandbox(ctx context.Context, req *cluster.DeleteSandboxRequest) (
	*cluster.DeleteSandboxResponse, error) {
	user, err := clusterAuth.AuthorizeRequest(clusterAuth.GetAuth(req))
	if err != nil {
		return &cluster.DeleteSandboxResponse{}, err
	}

	_, err = s.kubeClient.CoreV1().Namespaces().Get(user.Namespace, metav1.GetOptions{})
	if err != nil {
		if kerrors.IsNotFound(err) {
			return &cluster.DeleteSandboxResponse{}, errors.NewFriendlyError("Sandbox does not exist")
		}
		return &cluster.DeleteSandboxResponse{}, errors.WithContext("get sandbox", err)
	}

	if req.DeleteVolumes {
		if err := volume.PermanentlyDeletePVC(s.kubeClient, user.Namespace); err != nil {
			return &cluster.DeleteSandboxResponse{}, errors.WithContext("delete persistent volume", err)
		}
	}

	// Give the pods 10 seconds to shut down (rather than the default of 30
	// seconds). This gives applications a chance to flush their state to disk
	// to avoid data loss/corruption in volumes.
	pods, err := s.kubeClient.CoreV1().Pods(user.Namespace).List(metav1.ListOptions{})
	if err == nil {
		for _, pod := range pods.Items {
			ten := int64(10)
			err = s.kubeClient.CoreV1().Pods(user.Namespace).Delete(pod.Name, &metav1.DeleteOptions{
				GracePeriodSeconds: &ten,
			})
			if err != nil {
				log.WithField("namespace", user.Namespace).
					WithField("pod", pod.Name).
					WithError(err).
					Warn("Failed to delete pod during sandbox teardown")
			}
		}
	}

	if err := s.kubeClient.CoreV1().Namespaces().Delete(user.Namespace, nil); err != nil {
		return &cluster.DeleteSandboxResponse{}, err
	}

	return &cluster.DeleteSandboxResponse{}, nil
}

func (s *server) GetStatus(ctx context.Context, req *cluster.GetStatusRequest) (*cluster.GetStatusResponse, error) {
	user, err := clusterAuth.AuthorizeRequest(clusterAuth.GetAuth(req))
	if err != nil {
		return &cluster.GetStatusResponse{}, err
	}

	status, err := s.statusFetcher.Get(user.Namespace)
	if err != nil {
		return &cluster.GetStatusResponse{}, err
	}

	return &cluster.GetStatusResponse{Status: &status}, nil
}

func (s *server) WatchStatus(req *cluster.GetStatusRequest, stream cluster.Manager_WatchStatusServer) error {
	user, err := clusterAuth.AuthorizeRequest(clusterAuth.GetAuth(req))
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	trig := s.statusFetcher.Watch(ctx, user.Namespace)

	for {
		status, err := s.statusFetcher.Get(user.Namespace)
		if err != nil {
			return err
		}

		if err := stream.Send(&cluster.GetStatusResponse{Status: &status}); err != nil {
			return err
		}

		<-trig
	}
}

func (s *server) Restart(ctx context.Context, req *cluster.RestartRequest) (*cluster.RestartResponse, error) {
	user, err := clusterAuth.AuthorizeRequest(clusterAuth.GetAuth(req))
	if err != nil {
		return &cluster.RestartResponse{}, err
	}

	podName := names.ToDNS1123(req.GetService())
	currPod, err := s.kubeClient.CoreV1().Pods(user.Namespace).
		Get(podName, metav1.GetOptions{})
	if err != nil {
		return &cluster.RestartResponse{}, errors.WithContext("get current pod", err)
	}

	newPod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: user.Namespace,
			Labels:    currPod.Labels,
		},
		Spec: currPod.Spec,
	}
	for k, v := range currPod.Annotations {
		if contains(metadata.CustomPodAnnotations, k) {
			if newPod.Annotations == nil {
				newPod.Annotations = map[string]string{}
			}
			newPod.Annotations[k] = v
		}
	}

	// Since we are setting ForceRestart, we don't both adding any Sanitizers here.
	err = kube.DeployPod(s.kubeClient, newPod, kube.DeployPodOptions{ForceRestart: true})
	if err != nil {
		return &cluster.RestartResponse{}, errors.WithContext("deploy new pod", err)
	}

	return &cluster.RestartResponse{}, nil
}

func (s *server) TagImages(req *cluster.TagImagesRequest, stream cluster.Manager_TagImagesServer) error {
	user, err := clusterAuth.AuthorizeRequest(clusterAuth.GetAuth(req))
	if err != nil {
		return errors.WithContext("authenticate token", err)
	}

	log.WithField("namespace", user.Namespace).Info("TagImages called")

	regCreds := req.GetRegistryCredentials()
	if regCreds == nil {
		regCreds = map[string]*cluster.RegistryCredential{}
	}

	blimpRegCred, err := auth.BlimpRegcred(clusterAuth.GetAuth(req))
	if err != nil {
		return errors.WithContext("create Blimp registry credential", err)
	}
	regCreds[RegistryHostname] = blimpRegCred.ToProtobuf()

	ctx, cancel := context.WithCancel(stream.Context())

	responses := make(chan cluster.TagImagesResponse)
	for _, tagRequest := range req.GetTagRequests() {
		go func(tagRequest cluster.TagImageRequest) {
			err := s.pushImage(tagRequest.GetImage(), tagRequest.GetTag(), clusterAuth.GetAuth(req), regCreds)
			if err != nil {
				log.WithError(err).WithField("image", tagRequest.GetImage()).WithField("namespace", user.Namespace).
					Info("image tag failed")

				response := cluster.TagImagesResponse{
					Error:   errors.Marshal(errors.WithContext("Failed to tag image", err)),
					Service: tagRequest.GetService(),
				}
				select {
				case responses <- response:
				case <-ctx.Done():
				}

				return
			}
			log.WithField("image", tagRequest.GetImage()).WithField("namespace", user.Namespace).
				Info("TagImage finished")
			response := cluster.TagImagesResponse{
				Service: tagRequest.GetService(),
			}

			select {
			case responses <- response:
			case <-ctx.Done():
			}
		}(*tagRequest)
	}

	for numSent := 0; numSent < len(req.GetTagRequests()); numSent++ {
		response, more := <-responses
		if !more {
			// We never close the channel, so we wouldn't expect this. But just
			// in case, we return to avoid a tight loop.
			return errors.New("responses channel closed")
		}

		if err := stream.Send(&response); err != nil {
			cancel()
			log.WithError(err).Info("error on tagimages send")
			return err
		}
	}
	return nil
}

func (s *server) pushImage(oldName, newName string, blimpAuth *protoAuth.BlimpAuth,
	creds map[string]*cluster.RegistryCredential) error {

	ref, err := name.ParseReference(oldName)
	if err != nil {
		return errors.WithContext("parse image reference", err)
	}

	regCred := authn.Anonymous
	// We have to pick the right auth to use.
	for registry, cred := range creds {
		if cred.GetUsername() == "" && cred.GetPassword() == "" {
			continue
		}

		refRegistry := ref.Context().Registry

		// Specially handle index.docker.io.
		// This doesn't actually make sense, but is correct. See
		// https://github.com/google/go-containerregistry/pull/456#issuecomment-499233027.
		if registry == authn.DefaultAuthKey && refRegistry.Name() == name.DefaultRegistry {
			regCred = &authn.Basic{
				Username: cred.GetUsername(),
				Password: cred.GetPassword(),
			}
			break
		}

		// Usually hostnames from auth config do not have a scheme (http/https)
		// specified, but it seems like sometimes they do. We try both.
		if registry == refRegistry.Name() ||
			registry == fmt.Sprintf("%s://%s", refRegistry.Scheme(), refRegistry.Name()) {
			regCred = &authn.Basic{
				Username: cred.GetUsername(),
				Password: cred.GetPassword(),
			}
			break
		}
	}

	image, err := remote.Image(ref, remote.WithAuth(regCred))
	if err != nil {
		return errors.WithContext("creating pull image ref", err)
	}

	newRef, err := name.ParseReference(newName)
	if err != nil {
		return errors.WithContext("parse new image reference", err)
	}

	if newRef.Context().RegistryStr() != RegistryHostname {
		return errors.New("illegal registry %q", newRef.Context().RegistryStr())
	}

	regcred, err := auth.BlimpRegcred(blimpAuth)
	if err != nil {
		return errors.WithContext("create Blimp registry credential", err)
	}
	err = remote.Write(newRef, image, remote.WithAuth(regcred.ToContainerRegistry()))
	if err != nil {
		return errors.WithContext("push image", err)
	}

	return nil
}

func (s *server) Expose(ctx context.Context, req *cluster.ExposeRequest) (
	*cluster.ExposeResponse, error) {
	user, err := clusterAuth.AuthorizeRequest(clusterAuth.GetAuth(req))
	if err != nil {
		return &cluster.ExposeResponse{}, err
	}

	if req.Port < 1 || req.Port > 65535 {
		return &cluster.ExposeResponse{}, errors.NewFriendlyError("Port must be between 1 and 65535")
	}

	namespacesClient := s.kubeClient.CoreV1().Namespaces()
	_, err = namespacesClient.Get(user.Namespace, metav1.GetOptions{})
	if err != nil {
		if kerrors.IsNotFound(err) {
			return &cluster.ExposeResponse{}, errors.NewFriendlyError("Sandbox does not exist")
		}
		return &cluster.ExposeResponse{}, errors.WithContext("get sandbox", err)
	}

	exposeInfo := expose.ExposeInfo{
		Service: req.Service,
		Port:    int(req.Port),
	}

	// Secret should be 8 hex digits, so between 0x00000000 and 0xffffffff
	secretNum, err := rand.Int(rand.Reader, big.NewInt(0x100000000))
	if err != nil {
		return &cluster.ExposeResponse{}, errors.WithContext("generate secret", err)
	}
	secret := fmt.Sprintf("%08x", secretNum)

	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		namespace, err := namespacesClient.Get(user.Namespace, metav1.GetOptions{})
		if err != nil {
			return err
		}

		if namespace.Annotations == nil {
			namespace.Annotations = map[string]string{}
		}

		annotation := expose.ExposeAnnotation{}
		annotationJson, ok := namespace.Annotations[kube.ExposeAnnotation]
		if ok {
			annotation, err = expose.ParseJsonAnnotation(annotationJson)
			if err != nil {
				return err
			}
		}

		annotation[secret] = exposeInfo
		annotationJson, err = annotation.ToJson()
		if err != nil {
			return err
		}
		namespace.Annotations[kube.ExposeAnnotation] = annotationJson

		_, err = namespacesClient.Update(namespace)
		return err
	})
	if err != nil {
		return &cluster.ExposeResponse{}, errors.WithContext("update sandbox", err)
	}

	return &cluster.ExposeResponse{
		Link: fmt.Sprintf("https://%s%s.%s/", user.Namespace, secret, LinkProxyBaseHostname),
	}, nil
}

func (s *server) Unexpose(ctx context.Context, req *cluster.UnexposeRequest) (
	*cluster.UnexposeResponse, error) {
	user, err := clusterAuth.AuthorizeRequest(clusterAuth.GetAuth(req))
	if err != nil {
		return &cluster.UnexposeResponse{}, err
	}

	namespacesClient := s.kubeClient.CoreV1().Namespaces()
	_, err = namespacesClient.Get(user.Namespace, metav1.GetOptions{})
	if err != nil {
		if kerrors.IsNotFound(err) {
			return &cluster.UnexposeResponse{}, errors.NewFriendlyError("Sandbox does not exist")
		}
		return &cluster.UnexposeResponse{}, errors.WithContext("get sandbox", err)
	}

	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		namespace, err := namespacesClient.Get(user.Namespace, metav1.GetOptions{})
		if err != nil {
			return err
		}

		if namespace.Annotations == nil {
			return nil
		}

		delete(namespace.Annotations, kube.ExposeAnnotation)

		_, err = namespacesClient.Update(namespace)
		return err
	})
	if err != nil {
		return &cluster.UnexposeResponse{}, errors.WithContext("update sandbox", err)
	}

	return &cluster.UnexposeResponse{}, nil
}

func toPods(
	user auth.User,
	dnsIP,
	nodeControllerIP string,
	cfg composeTypes.Project,
	builtImages map[string]string,
) (
	pods []corev1.Pod,
	configMaps []corev1.ConfigMap,
	err error,
) {
	if len(cfg.Services) > MaxServices {
		return nil, nil, errors.NewFriendlyError(
			"Blimp supports a maximum of %d services, but %d are defined.",
			MaxServices, len(cfg.Services))
	}

	b, err := newPodBuilder(user, dnsIP, nodeControllerIP, builtImages, cfg.Services, cfg.Volumes)
	if err != nil {
		return nil, nil, errors.WithContext("make pod builder", err)
	}

	for _, svc := range cfg.Services {
		p, cm, err := b.ToPod(svc)
		if err != nil {
			return nil, nil, err
		}

		pods = append(pods, p)
		configMaps = append(configMaps, cm...)
	}

	return pods, configMaps, nil
}

type podCondition func(*corev1.Pod) bool

func podIsReady(pod *corev1.Pod) bool {
	for _, cond := range pod.Status.Conditions {
		if cond.Type == corev1.PodReady && cond.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

func podIsScheduled(pod *corev1.Pod) bool {
	return pod.Spec.NodeName != ""
}

func contains(slc []string, exp string) bool {
	for _, x := range slc {
		if x == exp {
			return true
		}
	}
	return false
}
