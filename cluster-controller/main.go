package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Masterminds/semver"
	composeTypes "github.com/kelda/compose-go/types"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/retry"

	"github.com/kelda-inc/blimp/cluster-controller/node"
	"github.com/kelda-inc/blimp/pkg/analytics"
	"github.com/kelda-inc/blimp/pkg/auth"
	"github.com/kelda-inc/blimp/pkg/dockercompose"
	"github.com/kelda-inc/blimp/pkg/errors"
	"github.com/kelda-inc/blimp/pkg/hash"
	"github.com/kelda-inc/blimp/pkg/kube"
	"github.com/kelda-inc/blimp/pkg/ports"
	"github.com/kelda-inc/blimp/pkg/proto/cluster"
	"github.com/kelda-inc/blimp/pkg/syncthing"
	"github.com/kelda-inc/blimp/pkg/version"
	"github.com/kelda-inc/blimp/pkg/volume"

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
}

// Set by make.
var RegistryHostname string

const (
	ContainerNameCopyBusybox               = "copy-busybox"
	ContainerNameCopyVCP                   = "copy-vcp"
	ContainerNameInitializeVolumeFromImage = "vcp"
	ContainerNameWaitDependsOn             = "wait-depends-on"
	ContainerNameWaitInitialSync           = "wait-sync"
)

// MaxServices is the maximum number of service pods allowed in a single
// sandbox.
const MaxServices = 150

func main() {
	analytics.Init(analytics.DirectPoster{}, analytics.StreamID{
		Source: "manager",
	})

	kubeClient, restConfig, err := getKubeClient()
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

	s := &server{
		statusFetcher: newStatusFetcher(kubeClient),
		kubeClient:    kubeClient,
		restConfig:    restConfig,
		certPath:      *certPath,
		keyPath:       *keyPath,
	}
	s.statusFetcher.Start()

	node.StartControllerBooter(kubeClient)

	addr := fmt.Sprintf("0.0.0.0:%d", ports.ClusterManagerInternalPort)
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

	creds, err := credentials.NewServerTLSFromFile(s.certPath, s.keyPath)
	if err != nil {
		return errors.WithContext("parse cert", err)
	}

	log.WithField("address", address).Info("Listening for connections..")
	grpcServer := grpc.NewServer(grpc.Creds(creds), grpc.UnaryInterceptor(errors.UnaryServerInterceptor))
	cluster.RegisterManagerServer(grpcServer, s)
	return grpcServer.Serve(lis)
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

	c, err := semver.NewConstraint(">= 0.12.0")
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
				"curl -fsSL 'https://kelda.io/get-blimp.sh' | sh\n\n" +
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

func (s *server) ProxyAnalytics(ctx context.Context, req *cluster.ProxyAnalyticsRequest) (
	*cluster.ProxyAnalyticsResponse, error) {
	return &cluster.ProxyAnalyticsResponse{}, analytics.DirectPoster{}.Post(req.GetBody())
}

func (s *server) CreateSandbox(ctx context.Context, req *cluster.CreateSandboxRequest) (*cluster.CreateSandboxResponse, error) {
	log.Info("Start CreateSandbox")

	// Validate that the user logged in, and get their information.
	user, err := auth.ParseIDToken(req.GetToken())
	if err != nil {
		return &cluster.CreateSandboxResponse{}, err
	}

	dcCfg, err := dockercompose.Unmarshal([]byte(req.GetComposeFile()))
	if err != nil {
		return &cluster.CreateSandboxResponse{}, errors.WithContext("unmarshal compose file", err)
	}

	analytics.Log.
		WithField("namespace", user.Namespace).
		WithField("serviceNames", dcCfg.ServiceNames()).
		WithField("composeHash", hash.DnsCompliant(req.GetComposeFile())).
		Info("Parsed CreateSandbox request")

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
	if len(sandboxes) >= maxSandboxes {
		analytics.Log.
			WithField("namespace", user.Namespace).
			WithField("numSandboxes", len(sandboxes)).
			WithField("maxSandboxes", maxSandboxes).
			Info("Hit maxSandboxes")

		return &cluster.CreateSandboxResponse{}, errors.NewFriendlyError(
			"Sorry, the Blimp servers are overloaded right now.\n" +
				"Please try again later.")
	}

	namespace := user.Namespace
	if err := s.createNamespace(ctx, namespace); err != nil {
		return &cluster.CreateSandboxResponse{}, errors.WithContext("create namespace", err)
	}

	if err := s.createSyncthing(namespace, req.GetSyncedFolders()); err != nil {
		return &cluster.CreateSandboxResponse{}, errors.WithContext("deploy syncthing", err)
	}

	if err := s.deployDNS(namespace); err != nil {
		return &cluster.CreateSandboxResponse{}, errors.WithContext("deploy dns", err)
	}

	// Wait until the DNS pod is scheduled so that we know what node the other
	// pods in the namespace will get scheduled on.
	dnsPod, err := s.getDNSPod(ctx, namespace, podIsScheduled)
	if err != nil {
		return &cluster.CreateSandboxResponse{}, errors.WithContext("get dns pod", err)
	}

	if err := s.addVolumeFinalizer(namespace, dnsPod.Spec.NodeName); err != nil {
		return &cluster.CreateSandboxResponse{}, errors.WithContext("add volume finalizer", err)
	}

	nodeAddress, nodeCert, err := node.GetConnectionInfo(ctx, s.kubeClient, dnsPod.Spec.NodeName)
	if err != nil {
		return &cluster.CreateSandboxResponse{}, errors.WithContext("get node controller", err)
	}

	creds := req.GetRegistryCredentials()
	if creds == nil {
		creds = map[string]*cluster.RegistryCredential{}
	}

	creds[RegistryHostname] = &cluster.RegistryCredential{
		Username: "_blimp_access_token",
		Password: req.GetToken(),
	}
	if err := s.createPodRunnerServiceAccount(namespace, creds); err != nil {
		return &cluster.CreateSandboxResponse{}, errors.WithContext("create pod runner service account", err)
	}

	cliCreds, err := s.createCLICreds(ctx, namespace)
	if err != nil {
		return &cluster.CreateSandboxResponse{}, errors.WithContext("get kube credentials", err)
	}

	var featuresMsg string
	unsupportedFeatures := dockercompose.GetUnsupportedFeatures(dcCfg)
	if len(unsupportedFeatures) > 0 {
		featuresMsg = fmt.Sprintf("WARNING: Docker Compose file uses features unsupported by Kelda Blimp: %v\n"+
			"Blimp will attempt to continue to boot.\n"+
			"We're working on reaching full parity with Docker Compose.\n"+
			"Ping us in Slack (http://slack.kelda.io) to request support for features!",
			unsupportedFeatures)

		analytics.Log.
			WithField("namespace", user.Namespace).
			WithField("unsupportedFeatures", unsupportedFeatures).
			Warn("Used unsupported feature")
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
	user, err := auth.ParseIDToken(req.GetToken())
	if err != nil {
		return &cluster.DeployResponse{}, err
	}

	dcCfg, err := dockercompose.Unmarshal([]byte(req.GetComposeFile()))
	if err != nil {
		return &cluster.DeployResponse{}, err
	}

	namespace := user.Namespace
	dnsPod, err := s.getDNSPod(ctx, namespace, podIsRunning)
	if err != nil {
		return &cluster.DeployResponse{}, errors.WithContext("get dns server's IP", err)
	}

	nodeControllerIP, err := node.GetNodeControllerInternalIP(s.kubeClient, dnsPod.Spec.NodeName)
	if err != nil {
		return &cluster.DeployResponse{}, errors.WithContext("get node controller's IP", err)
	}

	customerPods, configMaps, err := toPods(namespace, dnsPod.Status.PodIP, nodeControllerIP, dcCfg, req.BuiltImages)
	if err != nil {
		return &cluster.DeployResponse{}, errors.WithContext("make pod specs", err)
	}

	// TODO: Garbage collect config maps.
	for _, configMap := range configMaps {
		if err := kube.DeployConfigMap(s.kubeClient, configMap); err != nil {
			return &cluster.DeployResponse{}, errors.WithContext("create configmap", err)
		}
	}

	log.WithField("namespace", user.Namespace).
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

	// No need to re-create the namespace if it already exists.
	namespaceClient := s.kubeClient.CoreV1().Namespaces()
	if existingNs, err := namespaceClient.Get(ns.Name, metav1.GetOptions{}); err == nil {
		if existingNs.Status.Phase == corev1.NamespaceTerminating {
			return errors.NewFriendlyError(
				"Aborting deployment because sandbox is terminating.\n" +
					"This is a transient error caused by `blimp down` not completing yet.\n" +
					"Try again in 30 seconds.")
		}

		return nil
	}

	if _, err := namespaceClient.Create(ns); err != nil {
		return err
	}

	networkingClient := s.kubeClient.NetworkingV1().NetworkPolicies(ns.Name)
	if _, err := networkingClient.Get(policy.Name, metav1.GetOptions{}); err == nil {
		return nil
	}

	if _, err := networkingClient.Create(policy); err != nil {
		return errors.WithContext("create network policy", err)
	}

	// Wait for the default service account to exist before returning.
	// Pods will fail to deploy to the namespace until the account exists.
	ctx, _ = context.WithTimeout(ctx, 3*time.Minute)
	err := kube.WaitForObject(ctx,
		kube.ServiceAccountGetter(s.kubeClient, namespace, "default"),
		s.kubeClient.CoreV1().ServiceAccounts(namespace).Watch,
		func(saIntf interface{}) bool {
			return true
		})
	if err != nil {
		return errors.WithContext("wait for default service account", err)
	}
	return nil
}

// addVolumeFinalizer adds a finalizer to the given namespace signaling that
// the given namespace shouldn't be considered terminated until the specified
// node has cleaned up the volumes.
func (s *server) addVolumeFinalizer(namespace, node string) error {
	namespaceClient := s.kubeClient.CoreV1().Namespaces()
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		curr, err := namespaceClient.Get(namespace, metav1.GetOptions{})
		if err != nil {
			return err
		}

		finalizer := kube.VolumeFinalizer(node)
		if contains(curr.Finalizers, finalizer) {
			return nil
		}

		curr.Finalizers = append(curr.Finalizers, finalizer)
		_, err = namespaceClient.Finalize(curr)
		return err
	})
	return err
}

func (s *server) getDNSPod(ctx context.Context, namespace string, cond podCondition) (pod *corev1.Pod, err error) {
	ctx, _ = context.WithTimeout(ctx, 3*time.Minute)
	err = kube.WaitForObject(ctx,
		kube.PodGetter(s.kubeClient, namespace, "dns"),
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

func (s *server) createSyncthing(namespace string, syncedFolders map[string]string) error {
	volume := volume.BindVolumeRoot(namespace)
	mount := corev1.VolumeMount{
		Name:      volume.Name,
		MountPath: "/bind",
	}

	idPathMap := map[string]string{}
	for id, src := range syncedFolders {
		idPathMap[id] = filepath.Join("/bind", src)
	}

	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      "syncthing",
			Labels: map[string]string{
				"service":        "syncthing",
				"blimp.customer": namespace,
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:            "syncthing",
				Image:           version.SyncthingImage,
				ImagePullPolicy: "Always",
				Args:            syncthing.MapToArgs(idPathMap),
				VolumeMounts:    []corev1.VolumeMount{mount},
			}},
			Volumes:  []corev1.Volume{volume},
			Affinity: sameNodeAffinity(namespace),
		},
	}

	if err := kube.DeployPod(s.kubeClient, pod); err != nil {
		return errors.WithContext("deploy pod", err)
	}
	return nil
}

func (s *server) deployDNS(namespace string) error {
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
				"service":        "dns",
				"blimp.customer": namespace,
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
				Image:           version.DNSImage,
				ImagePullPolicy: "Always",
			}},
			Affinity:           sameNodeAffinity(namespace),
			ServiceAccountName: serviceAccount.Name,
		},
	}

	if err := kube.DeployPod(s.kubeClient, pod); err != nil {
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

			// Needed for `blimp cp`.
			{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"get"},
			},
		},
	}

	if err := kube.DeployServiceAccount(s.kubeClient, serviceAccount, role); err != nil {
		return cluster.KubeCredentials{}, errors.WithContext("create service account", err)
	}

	// Wait until the ServiceAccount's secret is populated.
	var secretName string
	ctx, _ = context.WithTimeout(ctx, 3*time.Minute)
	err := kube.WaitForObject(ctx,
		kube.ServiceAccountGetter(s.kubeClient, namespace, serviceAccount.Name),
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

func (s *server) createPodRunnerServiceAccount(namespace string, registryCredentials map[string]*cluster.RegistryCredential) error {
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
			corev1.DockerConfigJsonKey: string(dockerAuthConfig),
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
	} else {
		if _, err := secretClient.Create(&secret); err != nil {
			return errors.WithContext("create regcred secret", err)
		}
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
		if err := kube.DeployPod(s.kubeClient, pod); err != nil {
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

func (s *server) DeleteSandbox(ctx context.Context, req *cluster.DeleteSandboxRequest) (*cluster.DeleteSandboxResponse, error) {
	user, err := auth.ParseIDToken(req.GetToken())
	if err != nil {
		return &cluster.DeleteSandboxResponse{}, err
	}

	// Terminate the pods in the sandbox immediately so that `blimp down` feels
	// fast. This doesn't give the container a chance to gracefully shutdown,
	// but it probably doesn't matter since these are development containers,
	// and all the sandbox's state is going to be purged anyways.
	pods, err := s.kubeClient.CoreV1().Pods(user.Namespace).List(metav1.ListOptions{})
	if err == nil {
		for _, pod := range pods.Items {
			zero := int64(0)
			err = s.kubeClient.CoreV1().Pods(user.Namespace).Delete(pod.Name, &metav1.DeleteOptions{
				GracePeriodSeconds: &zero,
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
	user, err := auth.ParseIDToken(req.GetToken())
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
	user, err := auth.ParseIDToken(req.GetToken())
	if err != nil {
		return err
	}

	trig, stop := s.statusFetcher.Watch(user.Namespace)
	defer close(stop)

	for {
		status, err := s.statusFetcher.Get(user.Namespace)
		if err != nil {
			return err
		}

		if err := stream.Send(&cluster.GetStatusResponse{Status: &status}); err != nil {
			return err
		}

		select {
		case <-trig:
		}
	}
}

func toPods(
	namespace,
	dnsIP,
	nodeControllerIP string,
	cfg composeTypes.Config,
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

	serviceToAliases := make(map[string][]string)
	aliasToService := make(map[string]string)
	for _, svc := range cfg.Services {
		for _, link := range svc.Links {
			var svcToBeAliased, alias string
			switch linkParts := strings.Split(link, ":"); len(linkParts) {
			// A link without an alias. Nothing for us to do.
			case 1:
				continue
			case 2:
				svcToBeAliased = linkParts[0]
				alias = linkParts[1]
			default:
				log.WithField("link", link).Warn("Link in unexpected format. Skipping.")
				continue
			}

			// Error if two services are using the same alias for different services.
			if svcPresent, added := aliasToService[alias]; added && svcPresent != svcToBeAliased {
				return nil, nil, errors.NewFriendlyError(
					"links error: service %s and %s are using %s to refer to different services",
					svcPresent, svcToBeAliased, alias)
			}

			aliasToService[alias] = svcToBeAliased
			serviceToAliases[svcToBeAliased] = append(serviceToAliases[svcToBeAliased], alias)
		}
	}

	for _, svc := range cfg.Services {
		b := newPodBuilder(namespace, dnsIP, nodeControllerIP, builtImages)
		p, cm, err := b.ToPod(svc, serviceToAliases)
		if err != nil {
			return nil, nil, err
		}

		pods = append(pods, p)
		configMaps = append(configMaps, cm...)
	}

	return pods, configMaps, nil
}

func sameNodeAffinity(namespace string) *corev1.Affinity {
	return &corev1.Affinity{
		PodAffinity: &corev1.PodAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
				{
					LabelSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"blimp.customer": namespace,
						},
					},
					TopologyKey: corev1.LabelHostname,
				},
			},
		},
	}
}

// getKubeClient gets a Kubernetes client connected to the cluster defined in
// the local kubeconfig.
func getKubeClient() (kubernetes.Interface, *rest.Config, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	kubeConfig := clientcmd.
		NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{})

	restConfig, err := kubeConfig.ClientConfig()
	if err != nil {
		return nil, nil, errors.WithContext("get rest config", err)
	}

	// Increase the default throttling configuration from 5 queries per second
	// to 100 queries per second. This speeds up concurrent boots, since we
	// make so many requests to check and deploy objects.
	restConfig.QPS = 100
	restConfig.Burst = 100

	kubeClient, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, nil, errors.WithContext("new kube client", err)
	}

	return kubeClient, restConfig, nil
}

type podCondition func(*corev1.Pod) bool

func podIsRunning(pod *corev1.Pod) bool {
	return pod.Status.Phase == corev1.PodRunning
}

func podIsScheduled(pod *corev1.Pod) bool {
	return pod.Spec.NodeName != ""
}

func mapToSlice(set map[string]struct{}) (slc []string) {
	for str := range set {
		slc = append(slc, str)
	}
	sort.Strings(slc)
	return slc
}

func contains(slc []string, exp string) bool {
	for _, x := range slc {
		if x == exp {
			return true
		}
	}
	return false
}
