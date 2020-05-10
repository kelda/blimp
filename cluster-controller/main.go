package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/Masterminds/semver"
	composeTypes "github.com/compose-spec/compose-go/types"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/kelda-inc/blimp/pkg/analytics"
	"github.com/kelda-inc/blimp/pkg/auth"
	"github.com/kelda-inc/blimp/pkg/dockercompose"
	"github.com/kelda-inc/blimp/pkg/errors"
	"github.com/kelda-inc/blimp/pkg/hash"
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

const (
	Port        = 9000
	SandboxPort = 9001
)

// Set by make.
var RegistryHostname string

const (
	ContainerNameCopyBusybox               = "copy-busybox"
	ContainerNameCopyVCP                   = "copy-vcp"
	ContainerNameInitializeVolumeFromImage = "vcp"
	ContainerNameWaitDependsOn             = "wait-depends-on"
	ContainerNameWaitInitialSync           = "wait-sync"
)

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

	c, err := semver.NewConstraint(">= 0.10.0")
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

	namespace := user.Namespace
	if err := s.createNamespace(namespace); err != nil {
		return &cluster.CreateSandboxResponse{}, errors.WithContext("create namespace", err)
	}

	if err := s.createSyncthing(namespace, req.GetSyncedFolders()); err != nil {
		return &cluster.CreateSandboxResponse{}, errors.WithContext("deploy syncthing", err)
	}

	sandboxAddress, sandboxCert, err := s.createSandboxManager(namespace, dcCfg)
	if err != nil {
		return &cluster.CreateSandboxResponse{}, errors.WithContext("deploy customer manager", err)
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

	cliCreds, err := s.createCLICreds(namespace)
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
		SandboxAddress:  sandboxAddress,
		SandboxCert:     sandboxCert,
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
	sandboxControllerIP, err := s.getSandboxControllerIP(namespace)
	if err != nil {
		return &cluster.DeployResponse{}, errors.WithContext("get sandbox controller's internal IP", err)
	}

	customerPods, configMaps, err := toPods(namespace, sandboxControllerIP, dcCfg, req.BuiltImages)
	if err != nil {
		return &cluster.DeployResponse{}, errors.WithContext("make pod specs", err)
	}

	// TODO: Garbage collect config maps.
	for _, configMap := range configMaps {
		if err := s.updateConfigMap(configMap); err != nil {
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

func (s *server) createNamespace(namespace string) error {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: namespace,
			Labels: map[string]string{
				// Referenced by the network policy.
				"namespace": namespace,
			},
		},
	}

	namespaceNetworkPolicy := &networkingv1.NetworkPolicy{
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
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"namespace": ns.Name,
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

	sandboxControllerNetworkPolicy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns.Name,
			Name:      "sandbox-manager",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"service": "sandbox-manager",
				},
			},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					From: []networkingv1.NetworkPolicyPeer{

						// Allow traffic from all IPs so that the load balancer
						// can forward public connections to the pod.
						// The above network policy also allows traffic from
						// other pods in the same namespace.
						{
							IPBlock: &networkingv1.IPBlock{
								CIDR: "0.0.0.0/0",
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
	if _, err := namespaceClient.Get(ns.Name, metav1.GetOptions{}); err == nil {
		return nil
	}

	if _, err := namespaceClient.Create(ns); err != nil {
		return err
	}

	networkingClient := s.kubeClient.NetworkingV1().NetworkPolicies(ns.Name)
	for _, policy := range []*networkingv1.NetworkPolicy{namespaceNetworkPolicy, sandboxControllerNetworkPolicy} {
		if _, err := networkingClient.Get(policy.Name, metav1.GetOptions{}); err == nil {
			continue
		}

		if _, err := networkingClient.Create(policy); err != nil {
			return errors.WithContext("create network policy", err)
		}
	}
	return nil
}

func (s *server) getSandboxControllerIP(namespace string) (string, error) {
	var internalIP string
	err := waitForObject(
		podGetter(s.kubeClient, namespace, "sandbox-manager"),
		s.kubeClient.CoreV1().Pods(namespace).Watch,
		func(podIntf interface{}) bool {
			pod := podIntf.(*corev1.Pod)

			// Wait for the pod to be ready to accept connections.
			for _, container := range pod.Status.ContainerStatuses {
				if !container.Ready {
					return false
				}
			}

			if pod.Status.PodIP != "" {
				internalIP = pod.Status.PodIP
				return true
			}
			return false
		})
	if err != nil {
		return "", err
	}

	return internalIP, nil
}

func (s *server) createSandboxManager(namespace string, cfg composeTypes.Config) (sandboxAddr, certPEM string, err error) {
	serviceAccount := corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sandbox-manager",
			Namespace: namespace,
		},
	}

	role := rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      "sandbox-manager-role",
		},
		Rules: []rbacv1.PolicyRule{
			// TODO: Limit access.
			{
				APIGroups: []string{"*"},
				Resources: []string{"*"},
				Verbs:     []string{"*"},
			},
		},
	}

	bindVolumeRoot := volume.BindVolumeRoot(namespace)
	volumes := []corev1.Volume{
		{
			Name: "cert",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: "sandbox-cert",
				},
			},
		},
		bindVolumeRoot,
	}
	volumeMounts := []corev1.VolumeMount{
		{
			Name:      "cert",
			MountPath: "/etc/blimp/certs",
		},
		{
			Name:      bindVolumeRoot.Name,
			MountPath: "/bind",
		},
	}

	// Collect the volumes that need to be reset.
	resetPaths := map[string]struct{}{}
	for _, svc := range cfg.Services {
		for _, vol := range svc.Volumes {
			if vol.Type != composeTypes.VolumeTypeVolume {
				continue
			}

			kubeVol := volume.GetVolume(namespace, vol.Source)
			path := kubeVol.VolumeSource.HostPath.Path
			if _, ok := resetPaths[path]; ok {
				continue
			}

			volumes = append(volumes, kubeVol)
			volumeMounts = append(volumeMounts, corev1.VolumeMount{
				Name:      kubeVol.Name,
				MountPath: path,
			})
			resetPaths[path] = struct{}{}
		}
	}

	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      "sandbox-manager",
			Labels: map[string]string{
				"service":        "sandbox-manager",
				"blimp.customer": namespace,
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:            "sandbox-manager",
					Image:           version.SandboxControllerImage,
					ImagePullPolicy: "Always",
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
					Args:         mapToSlice(resetPaths),
					VolumeMounts: volumeMounts,
					ReadinessProbe: &corev1.Probe{
						Handler: corev1.Handler{
							TCPSocket: &corev1.TCPSocketAction{
								Port: intstr.FromInt(SandboxPort),
							},
						},

						// Give the sandbox controller some time to startup.
						InitialDelaySeconds: 5,
					},
				},
			},
			Volumes:            volumes,
			Affinity:           sameNodeAffinity(namespace),
			ServiceAccountName: serviceAccount.Name,
		},
	}

	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sandbox",
			Namespace: namespace,
		},
		Spec: corev1.ServiceSpec{
			Type:     corev1.ServiceTypeLoadBalancer,
			Selector: pod.Labels,
			Ports: []corev1.ServicePort{
				{
					Port:       443,
					TargetPort: intstr.FromInt(SandboxPort),
				},
			},
		},
	}

	// Create the Service first so that we can generate a certificate for the
	// sandbox's public IP.
	servicesClient := s.kubeClient.CoreV1().Services(namespace)
	if _, err := servicesClient.Get(service.Name, metav1.GetOptions{}); err != nil {
		_, err := servicesClient.Create(service)
		if err != nil {
			return "", "", errors.WithContext("create service", err)
		}
	}

	var publicIP string
	err = waitForObject(
		serviceGetter(s.kubeClient, namespace, service.Name),
		s.kubeClient.CoreV1().Services(namespace).Watch,
		func(svcIntf interface{}) bool {
			svc := svcIntf.(*corev1.Service)

			ingress := svc.Status.LoadBalancer.Ingress
			if len(ingress) == 1 && ingress[0].IP != "" {
				publicIP = ingress[0].IP
				return true
			}
			return false
		})
	if err != nil {
		return "", "", errors.WithContext("wait for public IP", err)
	}

	// Generate new certificates for the sandbox controller if it's the first
	// time deploying the controller.
	secretsClient := s.kubeClient.CoreV1().Secrets(namespace)
	certSecret, err := secretsClient.Get("sandbox-cert", metav1.GetOptions{})
	if err != nil {
		cert, key, err := newSelfSignedCert(publicIP)
		if err != nil {
			return "", "", errors.WithContext("generate cert", err)
		}

		certSecret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "sandbox-cert",
				Namespace: namespace,
			},
			Data: map[string][]byte{
				"cert.pem": cert,
				"key.pem":  key,
			},
		}
		if _, err := secretsClient.Create(certSecret); err != nil {
			return "", "", errors.WithContext("create cert secret", err)
		}
	}

	if err := s.createServiceAccount(serviceAccount, role); err != nil {
		return "", "", err
	}

	if err := s.deployPod(pod); err != nil {
		return "", "", errors.WithContext("deploy", err)
	}

	return fmt.Sprintf("%s:443", publicIP), string(certSecret.Data["cert.pem"]), nil
}

func newSelfSignedCert(ip string) (pemCert, pemKey []byte, err error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, errors.WithContext("create private key", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, errors.WithContext("generate serial number", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Kelda Blimp Sandbox Controller"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * time.Hour * 24),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP(ip)},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, errors.WithContext("create certificate", err)
	}

	var certOut bytes.Buffer
	if err := pem.Encode(&certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return nil, nil, errors.WithContext("pem encode certificate", err)
	}

	var keyOut bytes.Buffer
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, errors.WithContext("marshal private key", err)
	}
	if err := pem.Encode(&keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		return nil, nil, errors.WithContext("pem encode private key", err)
	}

	return certOut.Bytes(), keyOut.Bytes(), nil
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

	if err := s.deployPod(pod); err != nil {
		return errors.WithContext("deploy pod", err)
	}
	return nil
}

func (s *server) createCLICreds(namespace string) (cluster.KubeCredentials, error) {
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

	if err := s.createServiceAccount(serviceAccount, role); err != nil {
		return cluster.KubeCredentials{}, errors.WithContext("create service account", err)
	}

	// Wait until the ServiceAccount's secret is populated.
	var secretName string
	err := waitForObject(
		serviceAccountGetter(s.kubeClient, namespace, serviceAccount.Name),
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

func (s *server) updateConfigMap(configMap corev1.ConfigMap) error {
	configMapClient := s.kubeClient.CoreV1().ConfigMaps(configMap.Namespace)
	currConfigMap, err := configMapClient.Get(configMap.Name, metav1.GetOptions{})
	if err == nil {
		configMap.ResourceVersion = currConfigMap.ResourceVersion
		if _, err := configMapClient.Update(&configMap); err != nil {
			return errors.WithContext("update configMap", err)
		}
	} else {
		if _, err := configMapClient.Create(&configMap); err != nil {
			return errors.WithContext("create configMap", err)
		}
	}
	return nil
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

	return s.createServiceAccount(serviceAccount)
}

func (s *server) createServiceAccount(serviceAccount corev1.ServiceAccount, roles ...rbacv1.Role) error {
	saClient := s.kubeClient.CoreV1().ServiceAccounts(serviceAccount.Namespace)

	// Create the service account.
	currServiceAccount, err := saClient.Get(serviceAccount.Name, metav1.GetOptions{})
	if exists := err == nil; exists {
		serviceAccount.ResourceVersion = currServiceAccount.ResourceVersion
		// Copy over secrets, otherwise Kubernetes will create a duplicate token.
		serviceAccount.Secrets = currServiceAccount.Secrets
		_, err = saClient.Update(&serviceAccount)
	} else {
		_, err = saClient.Create(&serviceAccount)
	}
	if err != nil {
		return errors.WithContext("service account", err)
	}

	for _, role := range roles {
		if err := s.createRole(role); err != nil {
			return errors.WithContext("create role", err)
		}

		binding := rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("%s-%s", serviceAccount.Name, role.Name),
				Namespace: serviceAccount.Namespace,
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      serviceAccount.Name,
					Namespace: serviceAccount.Namespace,
				},
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "Role",
				Name:     role.Name,
			},
		}
		if err := s.createRoleBinding(binding); err != nil {
			return errors.WithContext("create role", err)
		}
	}
	return nil
}

func (s *server) createRole(role rbacv1.Role) error {
	c := s.kubeClient.RbacV1().Roles(role.Namespace)
	currRole, err := c.Get(role.Name, metav1.GetOptions{})
	if exists := err == nil; exists {
		role.ResourceVersion = currRole.ResourceVersion
		_, err = c.Update(&role)
	} else {
		_, err = c.Create(&role)
	}
	return err
}

func (s *server) createRoleBinding(binding rbacv1.RoleBinding) error {
	c := s.kubeClient.RbacV1().RoleBindings(binding.Namespace)
	currBinding, err := c.Get(binding.Name, metav1.GetOptions{})
	if exists := err == nil; exists {
		binding.ResourceVersion = currBinding.ResourceVersion
		_, err = c.Update(&binding)
	} else {
		_, err = c.Create(&binding)
	}
	return err
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
		if err := s.deployPod(pod); err != nil {
			return errors.WithContext("create", err)
		}
		desiredNames[pod.Name] = struct{}{}
	}

	// Delete any stale pods.
	for _, pod := range currPods.Items {
		if _, ok := desiredNames[pod.Name]; !ok {
			if err := s.deletePod(pod.Namespace, pod.Name); err != nil {
				return errors.WithContext("delete", err)
			}
		}
	}
	return nil
}

func (s *server) deployPod(pod corev1.Pod) error {
	// Add an annotation to track the spec that was used to deploy the pod.
	// This way, we can avoid recreating pods when the underlying spec hasn't
	// changed.
	applyAnnotation, err := runtime.Encode(unstructured.UnstructuredJSONScheme, &pod)
	if err != nil {
		return errors.WithContext("make apply annotation", err)
	}

	if pod.Annotations == nil {
		pod.Annotations = map[string]string{}
	}
	pod.Annotations["blimp.appliedObject"] = string(applyAnnotation)

	// Get the current pod, if it exists.
	podClient := s.kubeClient.CoreV1().Pods(pod.Namespace)
	curr, err := podClient.Get(pod.Name, metav1.GetOptions{})
	if err != nil && !kerrors.IsNotFound(err) {
		return errors.WithContext("get pod", err)
	}

	// If the pod already exists.
	if err == nil {
		// If the currently deployed pod is already up to date, we don't have
		// to do anything.
		if curr.Annotations["blimp.appliedObject"] == pod.Annotations["blimp.appliedObject"] {
			return nil
		}

		// Delete the existing pod before we recreate it.
		if err := s.deletePod(pod.Namespace, pod.Name); err != nil {
			return errors.WithContext("delete pod", err)
		}
	}

	if _, err := podClient.Create(&pod); err != nil {
		return errors.WithContext("create pod", err)
	}
	return nil
}

func (s *server) deletePod(namespace, name string) error {
	podClient := s.kubeClient.CoreV1().Pods(namespace)
	if err := podClient.Delete(name, metav1.NewDeleteOptions(0)); err != nil {
		return err
	}

	podWatcher, err := podClient.Watch(metav1.ListOptions{})
	if err != nil {
		return errors.WithContext("watch pods", err)
	}

	defer podWatcher.Stop()
	for range podWatcher.ResultChan() {
		currPods, err := podClient.List(metav1.ListOptions{})
		if err != nil {
			return errors.WithContext("list pods", err)
		}

		foundPod := false
		for _, pod := range currPods.Items {
			if pod.Name == name {
				foundPod = true
				break
			}
		}

		if !foundPod {
			return nil
		}
	}
	return nil
}

func (s *server) DeleteSandbox(ctx context.Context, req *cluster.DeleteSandboxRequest) (*cluster.DeleteSandboxResponse, error) {
	user, err := auth.ParseIDToken(req.GetToken())
	if err != nil {
		return &cluster.DeleteSandboxResponse{}, err
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
	managerIP string,
	cfg composeTypes.Config,
	builtImages map[string]string,
) (
	pods []corev1.Pod,
	configMaps []corev1.ConfigMap,
	err error,
) {
	for _, svc := range cfg.Services {
		b := newPodBuilder(namespace, managerIP, builtImages)
		p, cm := b.ToPod(svc)
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

func waitForObject(
	objectGetter func() (interface{}, error),
	watchFn func(metav1.ListOptions) (watch.Interface, error),
	validator func(interface{}) bool) error {

	// Wait until the ServiceAccount's secret is populated.
	watcher, err := watchFn(metav1.ListOptions{})
	if err != nil {
		return errors.WithContext("watch", err)
	}
	defer watcher.Stop()

	watcherChan := watcher.ResultChan()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		obj, err := objectGetter()
		if err != nil {
			return errors.WithContext("get", err)
		}

		if validator(obj) {
			return nil
		}

		select {
		case <-watcherChan:
		case <-ticker.C:
		}
	}
}

func podGetter(kubeClient kubernetes.Interface, namespace, name string) func() (interface{}, error) {
	return func() (interface{}, error) {
		return kubeClient.CoreV1().Pods(namespace).Get(name, metav1.GetOptions{})
	}
}

func serviceAccountGetter(kubeClient kubernetes.Interface, namespace, name string) func() (interface{}, error) {
	return func() (interface{}, error) {
		return kubeClient.CoreV1().ServiceAccounts(namespace).Get(name, metav1.GetOptions{})
	}
}

func serviceGetter(kubeClient kubernetes.Interface, namespace, name string) func() (interface{}, error) {
	return func() (interface{}, error) {
		return kubeClient.CoreV1().Services(namespace).Get(name, metav1.GetOptions{})
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

	kubeClient, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, nil, errors.WithContext("new kube client", err)
	}

	return kubeClient, restConfig, nil
}

func mapToSlice(set map[string]struct{}) (slc []string) {
	for str := range set {
		slc = append(slc, str)
	}
	sort.Strings(slc)
	return slc
}
