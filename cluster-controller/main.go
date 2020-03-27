package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/kelda-inc/blimp/pkg/auth"
	"github.com/kelda-inc/blimp/pkg/dockercompose"
	"github.com/kelda-inc/blimp/pkg/proto/cluster"
	"github.com/kelda-inc/blimp/pkg/version"

	// Install the gzip compressor.
	_ "google.golang.org/grpc/encoding/gzip"

	// Load the client authentication plugin necessary for connecting to GKE.
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
)

type server struct {
	kubeClient        kubernetes.Interface
	restConfig        *rest.Config
	certPath, keyPath string
}

const (
	Port        = 9000
	SandboxPort = 9001
)

// Set by make.
var RegistryHostname string

func main() {
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
		kubeClient: kubeClient,
		restConfig: restConfig,
		certPath:   *certPath,
		keyPath:    *keyPath,
	}
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
		return fmt.Errorf("parse cert: %w", err)
	}

	log.WithField("address", address).Info("Listening for connections..")
	grpcServer := grpc.NewServer(grpc.Creds(creds))
	cluster.RegisterManagerServer(grpcServer, s)
	return grpcServer.Serve(lis)
}

func (s *server) CreateSandbox(ctx context.Context, req *cluster.CreateSandboxRequest) (*cluster.CreateSandboxResponse, error) {
	// Validate that the user logged in, and get their information.
	user, err := auth.ParseIDToken(req.GetToken())
	if err != nil {
		return &cluster.CreateSandboxResponse{}, err
	}

	namespace := user.Namespace
	if err := s.createNamespace(namespace); err != nil {
		return &cluster.CreateSandboxResponse{}, fmt.Errorf("create namespace: %w", err)
	}

	if err := s.createSyncthing(namespace); err != nil {
		return &cluster.CreateSandboxResponse{}, fmt.Errorf("deploy syncthing: %w", err)
	}

	sandboxManagerIP, sandboxCert, err := s.createSandboxManager(namespace)
	if err != nil {
		return &cluster.CreateSandboxResponse{}, fmt.Errorf("deploy customer manager: %w", err)
	}

	if err := s.createPodRunnerServiceAccount(namespace, req.GetToken()); err != nil {
		return &cluster.CreateSandboxResponse{}, fmt.Errorf("create pod runner service account: %w", err)
	}

	cliCreds, err := s.createCLICreds(namespace)
	if err != nil {
		return &cluster.CreateSandboxResponse{}, fmt.Errorf("get kube credentials: %w", err)
	}

	return &cluster.CreateSandboxResponse{
		SandboxAddress:  fmt.Sprintf("%s:%d", sandboxManagerIP, SandboxPort),
		SandboxCert:     sandboxCert,
		ImageNamespace:  fmt.Sprintf("%s/%s", RegistryHostname, namespace),
		KubeCredentials: &cliCreds,
	}, nil
}

func (s *server) DeployToSandbox(ctx context.Context, req *cluster.DeployRequest) (*cluster.DeployResponse, error) {
	// Validate that the user logged in, and get their information.
	user, err := auth.ParseIDToken(req.GetToken())
	if err != nil {
		return &cluster.DeployResponse{}, err
	}

	dcCfg, err := dockercompose.Parse([]byte(req.GetComposeFile()))
	if err != nil {
		// TODO: Error within response.
		return &cluster.DeployResponse{}, err
	}

	namespace := user.Namespace
	dnsIP, err := s.getDNSIP(namespace)
	if err != nil {
		return &cluster.DeployResponse{}, fmt.Errorf("get dns server's IP: %w", err)
	}

	customerPods := toPods(namespace, dnsIP, dcCfg, req.BuiltImages)
	if err := s.deployCustomerPods(namespace, customerPods); err != nil {
		return &cluster.DeployResponse{}, fmt.Errorf("boot customer pods: %w", err)
	}
	return &cluster.DeployResponse{}, nil
}

func (s *server) createNamespace(namespace string) error {
	// No need to re-create the namespace if it already exists.
	namespaceClient := s.kubeClient.CoreV1().Namespaces()
	if _, err := namespaceClient.Get(namespace, metav1.GetOptions{}); err == nil {
		return nil
	}

	_, err := namespaceClient.Create(&corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: namespace,
		},
	})
	return err
}

func (s *server) getDNSIP(namespace string) (string, error) {
	var internalIP string
	err := waitForObject(
		podGetter(s.kubeClient, namespace, "sandbox-manager"),
		s.kubeClient.CoreV1().Pods(namespace).Watch,
		func(podIntf interface{}) bool {
			pod := podIntf.(*corev1.Pod)

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

func (s *server) createSandboxManager(namespace string) (publicIP, certPEM string, err error) {
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

	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      "sandbox-manager",
			Labels: map[string]string{
				"service": "sandbox-manager",
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
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "cert",
							MountPath: "/etc/blimp/certs",
						},
					},
				},
			},
			Volumes: []corev1.Volume{
				{
					Name: "cert",
					VolumeSource: corev1.VolumeSource{
						Secret: &corev1.SecretVolumeSource{
							SecretName: "sandbox-cert",
						},
					},
				},
			},
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
				{Port: SandboxPort},
			},
		},
	}

	// Create the Service first so that we can generate a certificate for the
	// sandbox's public IP.
	servicesClient := s.kubeClient.CoreV1().Services(namespace)
	if _, err := servicesClient.Get(service.Name, metav1.GetOptions{}); err != nil {
		_, err := servicesClient.Create(service)
		if err != nil {
			return "", "", fmt.Errorf("create service: %w", err)
		}
	}

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
		return "", "", fmt.Errorf("wait for public IP: %w", err)
	}

	// Generate new certificates for the sandbox controller if it's the first
	// time deploying the controller.
	secretsClient := s.kubeClient.CoreV1().Secrets(namespace)
	certSecret, err := secretsClient.Get("sandbox-cert", metav1.GetOptions{})
	if err != nil {
		cert, key, err := newSelfSignedCert(publicIP)
		if err != nil {
			return "", "", fmt.Errorf("generate cert: %s", err)
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
			return "", "", fmt.Errorf("create cert secret: %s", err)
		}
	}

	if err := s.createServiceAccount(serviceAccount, role); err != nil {
		return "", "", err
	}

	if err := s.deployPod(pod); err != nil {
		return "", "", fmt.Errorf("deploy: %w", err)
	}

	return publicIP, string(certSecret.Data["cert.pem"]), nil
}

func newSelfSignedCert(ip string) (pemCert, pemKey []byte, err error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("create private key: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("generate serial number: %w", err)
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
		return nil, nil, fmt.Errorf("create certificate: %w", err)
	}

	var certOut bytes.Buffer
	if err := pem.Encode(&certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return nil, nil, fmt.Errorf("pem encode certificate: %w", err)
	}

	var keyOut bytes.Buffer
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal private key: %w", err)
	}
	if err := pem.Encode(&keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		return nil, nil, fmt.Errorf("pem encode private key: %w", err)
	}

	return certOut.Bytes(), keyOut.Bytes(), nil
}

func (s *server) createSyncthing(namespace string) error {
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      "syncthing",
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:            "syncthing",
				Image:           version.SyncthingImage,
				ImagePullPolicy: "Always",
			}},
		},
	}

	return s.deployPod(pod)
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
			// TODO: Limit access.
			{
				APIGroups: []string{"*"},
				Resources: []string{"*"},
				Verbs:     []string{"*"},
			},
		},
	}

	if err := s.createServiceAccount(serviceAccount, role); err != nil {
		return cluster.KubeCredentials{}, fmt.Errorf("create service account: %w", err)
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
		return cluster.KubeCredentials{}, fmt.Errorf("wait for service account secret: %w", err)
	}

	secret, err := s.kubeClient.CoreV1().Secrets(namespace).
		Get(secretName, metav1.GetOptions{})
	if err != nil {
		return cluster.KubeCredentials{}, fmt.Errorf("get token: %w", err)
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

func (s *server) createPodRunnerServiceAccount(namespace, idToken string) error {
	secret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			// TODO: Variable, shared with toPods.
			Name:      "build-registry-auth",
			Namespace: namespace,
		},
		Type: corev1.SecretTypeDockerConfigJson,
		StringData: map[string]string{
			corev1.DockerConfigJsonKey: fmt.Sprintf(
				`{"auths":{"https://%s":{"username":"ignored","password":%q}}}`,
				RegistryHostname, idToken),
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
			return fmt.Errorf("update regcred secret: %w", err)
		}
	} else {
		if _, err := secretClient.Create(&secret); err != nil {
			return fmt.Errorf("create regcred secret: %w", err)
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
		return fmt.Errorf("service account: %w", err)
	}

	for _, role := range roles {
		if err := s.createRole(role); err != nil {
			return fmt.Errorf("create role: %w", err)
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
			return fmt.Errorf("create role: %w", err)
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
		return fmt.Errorf("list: %w", err)
	}

	// TODO: Parallelize
	desiredNames := map[string]struct{}{}
	for _, pod := range desired {
		if err := s.deployPod(pod); err != nil {
			return fmt.Errorf("create: %w", err)
		}
		desiredNames[pod.Name] = struct{}{}
	}

	// Delete any stale pods.
	for _, pod := range currPods.Items {
		if _, ok := desiredNames[pod.Name]; !ok {
			if err := s.deletePod(pod.Namespace, pod.Name); err != nil {
				return fmt.Errorf("delete: %w", err)
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
		return fmt.Errorf("make apply annotation: %w", err)
	}

	if pod.Annotations == nil {
		pod.Annotations = map[string]string{}
	}
	pod.Annotations["blimp.appliedObject"] = string(applyAnnotation)

	// Get the current pod, if it exists.
	podClient := s.kubeClient.CoreV1().Pods(pod.Namespace)
	curr, err := podClient.Get(pod.Name, metav1.GetOptions{})
	if err != nil && !kerrors.IsNotFound(err) {
		return fmt.Errorf("get pod: %w", err)
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
			return fmt.Errorf("delete pod: %w", err)
		}
	}

	if _, err := podClient.Create(&pod); err != nil {
		return fmt.Errorf("create pod: %w", err)
	}
	return nil
}

func (s *server) deletePod(namespace, name string) error {
	podClient := s.kubeClient.CoreV1().Pods(namespace)
	if err := podClient.Delete(name, nil); err != nil {
		return err
	}

	podWatcher, err := podClient.Watch(metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("watch pods: %w", err)
	}

	defer podWatcher.Stop()
	for range podWatcher.ResultChan() {
		currPods, err := podClient.List(metav1.ListOptions{})
		if err != nil {
			return fmt.Errorf("list pods: %w", err)
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

	status, err := s.getSandboxStatus(user.Namespace)
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

	watcher, err := s.kubeClient.CoreV1().Pods(user.Namespace).Watch(metav1.ListOptions{})
	if err != nil {
		return err
	}
	defer watcher.Stop()

	trig := watcher.ResultChan()
	for {
		status, err := s.getSandboxStatus(user.Namespace)
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

func (s *server) getSandboxStatus(namespace string) (cluster.SandboxStatus, error) {
	pods, err := s.kubeClient.CoreV1().Pods(namespace).List(metav1.ListOptions{
		LabelSelector: "blimp.customerPod=true",
	})
	if err != nil {
		return cluster.SandboxStatus{}, err
	}

	services := map[string]*cluster.ServiceStatus{}
	for _, pod := range pods.Items {
		phase := string(pod.Status.Phase)
		if len(pod.Status.ContainerStatuses) == 1 {
			containerStatus := pod.Status.ContainerStatuses[0]
			switch {
			case containerStatus.State.Waiting != nil && containerStatus.State.Waiting.Message != "":
				phase += ": " + containerStatus.State.Waiting.Message
			case containerStatus.State.Terminated != nil && containerStatus.State.Terminated.Message != "":
				phase += ": " + containerStatus.State.Waiting.Message
			}
		}
		services[pod.Name] = &cluster.ServiceStatus{
			Phase: phase,
		}
	}
	return cluster.SandboxStatus{Services: services}, nil
}

func toPods(namespace, dnsServer string, cfg dockercompose.Config, builtImages map[string]string) (pods []corev1.Pod) {
	for name, svc := range cfg.Services {
		image := svc.Image
		if svc.Build != nil {
			image = builtImages[name]
			// TODO: Error if image DNE.
		}

		// Volumes are backed by a directory on the node's filesystem.
		var volumes []corev1.Volume
		var volumeMounts []corev1.VolumeMount
		for _, desired := range svc.Volumes {
			if desired.Type != "volume" {
				log.WithField("type", desired.Type).
					WithField("source", desired.Source).
					Warn("Skipping unsupported volume type")
				continue
			}

			hostPathType := corev1.HostPathDirectoryOrCreate
			volumes = append(volumes, corev1.Volume{
				Name: desired.Source,
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: fmt.Sprintf("/var/blimp/volumes/%s/%s", namespace, desired.Source),
						Type: &hostPathType,
					},
				},
			})

			volumeMounts = append(volumeMounts, corev1.VolumeMount{
				Name:      desired.Source,
				MountPath: desired.Target,
			})
		}

		var envVars []corev1.EnvVar
		for k, v := range svc.Environment {
			envVars = append(envVars, corev1.EnvVar{
				Name:  k,
				Value: v,
			})
		}

		// TODO: Resources
		pod := corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: namespace,
				Name:      name,
				Labels: map[string]string{
					"blimp.service":     name,
					"blimp.customerPod": "true",
					"blimp.customer":    namespace,
				},
			},
			Spec: corev1.PodSpec{
				InitContainers: []corev1.Container{
					{
						Name:  "depends-on-waiter",
						Image: version.DependsOnImage,
						Args:  svc.DependsOn,
					},
				},
				Containers: []corev1.Container{
					{
						Name:         name,
						Image:        image,
						Command:      svc.Entrypoint,
						Args:         svc.Command,
						VolumeMounts: volumeMounts,
						Env:          envVars,
					},
				},
				DNSPolicy: corev1.DNSNone,
				DNSConfig: &corev1.PodDNSConfig{
					Nameservers: []string{dnsServer},
					// TODO: There's Searches and Options, look into how to replicate these.
				},
				ImagePullSecrets: []corev1.LocalObjectReference{
					{Name: "build-registry-auth"},
				},
				Volumes:            volumes,
				ServiceAccountName: "pod-runner",
				Affinity: &corev1.Affinity{
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
				},
			},
		}
		pods = append(pods, pod)
	}

	return pods
}

func waitForObject(
	objectGetter func() (interface{}, error),
	watchFn func(metav1.ListOptions) (watch.Interface, error),
	validator func(interface{}) bool) error {

	// Wait until the ServiceAccount's secret is populated.
	watcher, err := watchFn(metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("watch: %w", err)
	}
	defer watcher.Stop()

	watcherChan := watcher.ResultChan()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		obj, err := objectGetter()
		if err != nil {
			return fmt.Errorf("get: %w", err)
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
		return nil, nil, fmt.Errorf("get rest config: %w", err)
	}

	kubeClient, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("new kube client: %w", err)
	}

	return kubeClient, restConfig, nil
}
