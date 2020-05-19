package node

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"

	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/kelda-inc/blimp/pkg/errors"
	"github.com/kelda-inc/blimp/pkg/kube"
	"github.com/kelda-inc/blimp/pkg/ports"
	"github.com/kelda-inc/blimp/pkg/version"
	"github.com/kelda-inc/blimp/pkg/volume"
)

const NodeControllerNamespace = "blimp-system"

type booter struct {
	lister     listers.NodeLister
	kubeClient kubernetes.Interface
}

// StartControllerBooter starts a watcher that watches for new Kubernetes
// nodes, and deploys a Blimp Node Controller onto them.
func StartControllerBooter(kubeClient kubernetes.Interface) {
	for {
		_, err := kubeClient.CoreV1().Namespaces().Create(&corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: NodeControllerNamespace,
				Labels: map[string]string{
					// Used by the network policy to allow node controllers to
					// forward traffic to customer pods.
					"namespace": NodeControllerNamespace,
				},
			},
		})
		if err == nil || kerrors.IsAlreadyExists(err) {
			break
		}

		log.WithError(err).
			WithField("namespace", NodeControllerNamespace).
			Error("Failed to create namespace. Retrying in 15 seconds.")
		time.Sleep(15 * time.Second)
	}

	factory := informers.NewSharedInformerFactory(kubeClient, 30*time.Second).Core().V1().Nodes()
	informer := factory.Informer()

	b := booter{
		kubeClient: kubeClient,
		lister:     factory.Lister(),
	}

	sync := func(obj interface{}) {
		node, ok := obj.(*corev1.Node)
		if !ok {
			log.WithField("obj", obj).
				Warn("Unexpected non-Node object")
			return
		}

		if err := b.ensureDeployed(node.Name); err != nil {
			log.WithField("node", node).WithError(err).Error("Failed to deploy node controller")
		}
	}
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    sync,
		DeleteFunc: sync,
		UpdateFunc: func(_, intf interface{}) {
			sync(intf)
		},
	})

	go informer.Run(nil)
	cache.WaitForCacheSync(nil, informer.HasSynced)
}

func (booter *booter) ensureDeployed(node string) error {
	pods, err := booter.kubeClient.CoreV1().Pods(NodeControllerNamespace).
		List(metav1.ListOptions{
			LabelSelector: fmt.Sprintf("service=node-controller,node=%s", node),
		})
	if err != nil {
		return errors.WithContext("get current pods", err)
	}

	// If the node already has a controller, there's nothing else for us to do.
	if len(pods.Items) != 0 {
		return nil
	}

	log.WithField("node", node).Info("Deploying node controller")
	if err := booter.deployNodeController(node); err != nil {
		return errors.WithContext("deploy node controller", err)
	}
	return nil
}

func (booter *booter) deployNodeController(node string) error {
	serviceAccount := corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "node-controller",
			Namespace: NodeControllerNamespace,
		},
	}

	role := rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node-controller-role",
		},
		Rules: []rbacv1.PolicyRule{
			// List all pods in the cluster. Used for tunneling and boot
			// blocking.
			{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"get", "list", "watch"},
			},

			// List all namespaces, and update their finalizers. Used for the
			// volume deletion finalizer.
			{
				APIGroups: []string{""},
				Resources: []string{"namespaces"},
				Verbs:     []string{"get", "list", "watch"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"namespaces/finalize"},
				Verbs:     []string{"update"},
			},
		},
	}

	hostPathType := corev1.HostPathDirectoryOrCreate
	volumes := []corev1.Volume{
		{
			Name: "cert",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: certSecretName(node),
				},
			},
		},
		{
			Name: "blimp-volumes",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: volume.VolumeRoot,
					Type: &hostPathType,
				},
			},
		},
	}
	volumeMounts := []corev1.VolumeMount{
		{
			Name:      "cert",
			MountPath: "/etc/blimp/certs",
		},
		{
			Name:      "blimp-volumes",
			MountPath: volume.VolumeRoot,
		},
	}

	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: NodeControllerNamespace,
			Name:      nodeControllerName(node),
			Labels: map[string]string{
				"service": "node-controller",
				"node":    node,
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:            "node-controller",
					Image:           version.NodeControllerImage,
					ImagePullPolicy: "Always",
					VolumeMounts:    volumeMounts,
					ReadinessProbe: &corev1.Probe{
						Handler: corev1.Handler{
							TCPSocket: &corev1.TCPSocketAction{
								Port: intstr.FromInt(ports.NodeControllerInternalPort),
							},
						},

						// Give the node controller some time to startup.
						InitialDelaySeconds: 5,
					},
					Env: []corev1.EnvVar{
						{
							Name:  "NODE_NAME",
							Value: node,
						},
					},
				},
			},
			Volumes:            volumes,
			ServiceAccountName: serviceAccount.Name,
			NodeName:           node,
		},
	}

	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      nodeControllerName(node),
			Namespace: NodeControllerNamespace,
		},
		Spec: corev1.ServiceSpec{
			Type:     corev1.ServiceTypeLoadBalancer,
			Selector: pod.Labels,
			Ports: []corev1.ServicePort{
				{
					Port:       ports.NodeControllerPublicPort,
					TargetPort: intstr.FromInt(ports.NodeControllerInternalPort),
				},
			},
		},
	}

	// Create the Service first so that we can generate a certificate for the
	// Node Controller's public IP.
	servicesClient := booter.kubeClient.CoreV1().Services(NodeControllerNamespace)
	if _, err := servicesClient.Get(service.Name, metav1.GetOptions{}); err != nil {
		_, err := servicesClient.Create(service)
		if err != nil {
			return errors.WithContext("create service", err)
		}
	}

	var publicIP string
	ctx, _ := context.WithTimeout(context.Background(), 3*time.Minute)
	err := kube.WaitForObject(ctx,
		kube.ServiceGetter(booter.kubeClient, NodeControllerNamespace, service.Name),
		booter.kubeClient.CoreV1().Services(NodeControllerNamespace).Watch,
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
		return errors.WithContext("wait for public IP", err)
	}

	// Generate new certificates for the Node Controller if it's the first
	// time deploying the controller.
	secretsClient := booter.kubeClient.CoreV1().Secrets(NodeControllerNamespace)
	_, err = secretsClient.Get(certSecretName(node), metav1.GetOptions{})
	if err != nil {
		cert, key, err := newSelfSignedCert(publicIP)
		if err != nil {
			return errors.WithContext("generate cert", err)
		}

		certSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      certSecretName(node),
				Namespace: NodeControllerNamespace,
				Annotations: map[string]string{
					"host": fmt.Sprintf("%s:%d", publicIP, ports.NodeControllerPublicPort),
				},
			},
			Data: map[string][]byte{
				"cert.pem": cert,
				"key.pem":  key,
			},
		}
		if _, err := secretsClient.Create(certSecret); err != nil {
			return errors.WithContext("create cert secret", err)
		}
	}

	if err := kube.DeployClusterServiceAccount(booter.kubeClient, serviceAccount, role); err != nil {
		return err
	}

	if err := kube.DeployPod(booter.kubeClient, pod); err != nil {
		return errors.WithContext("deploy", err)
	}

	return nil
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
			Organization: []string{"Kelda Blimp Node Controller"},
		},
		// Set the NotBefore date to a bit earlier to allow for clients who
		// have slow clocks.
		NotBefore:             time.Now().Add(-1 * 24 * time.Hour),
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
