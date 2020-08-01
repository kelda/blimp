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
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/retry"
	"k8s.io/client-go/util/workqueue"

	"github.com/kelda-inc/blimp/pkg/kube"
	"github.com/kelda-inc/blimp/pkg/ports"
	"github.com/kelda-inc/blimp/pkg/version"
	"github.com/kelda/blimp/pkg/errors"
	"github.com/kelda/blimp/pkg/kubewait"
)

const (
	NodeControllerNamespace = kube.BlimpNamespace

	// maxRetries is the maximum number of times to retry deploying a node
	// controller before giving up.
	maxRetries = 4

	// numWorkers is the max number of node controllers to deploy in parallel.
	numWorkers = 4
)

var dnsTaint = corev1.Taint{
	Key:    "blimp.nodeDNSPending",
	Value:  "true",
	Effect: corev1.TaintEffectNoSchedule,
}

type booter struct {
	nodeInformer cache.SharedIndexInformer
	kubeClient   kubernetes.Interface
	workqueue    workqueue.RateLimitingInterface
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

	informer := informers.NewSharedInformerFactory(kubeClient, 30*time.Second).
		Core().V1().Nodes().Informer()

	b := booter{
		kubeClient:   kubeClient,
		nodeInformer: informer,
		workqueue:    workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
	}

	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			key, err := cache.MetaNamespaceKeyFunc(obj)
			if err == nil {
				b.workqueue.Add(key)
			}
		},
	})

	go informer.Run(nil)
	cache.WaitForCacheSync(nil, informer.HasSynced)

	for i := 0; i < numWorkers; i++ {
		go func() {
			for !b.runWorker() {
			}
		}()
	}
}

func (booter *booter) runWorker() (shutdown bool) {
	key, shutdown := booter.workqueue.Get()
	if shutdown {
		return true
	}
	defer booter.workqueue.Done(key)

	obj, found, err := booter.nodeInformer.GetIndexer().GetByKey(key.(string))
	if err != nil {
		log.WithError(err).WithField("key", key).Error("Failed to get node")
		booter.requeue(key)
		return false
	}

	// The node was deleted, so there's nothing to do.
	if !found {
		booter.workqueue.Forget(key)
		return false
	}

	node, ok := obj.(*corev1.Node)
	if !ok {
		log.WithField("obj", obj).
			Warn("Unexpected non-Node object")
		return false
	}

	log.WithField("node", node.Name).Info("Deploying node controller")
	err = booter.deployNodeController(node.Name)
	if err == nil {
		log.WithField("node", node.Name).Info("Successfully deployed node controller")
		return false
	}

	log.WithField("node", node.Name).
		WithError(err).
		Error("Failed to deploy node controller")

	// Try deploying again later.
	booter.requeue(key)
	return false
}

func (booter *booter) requeue(key interface{}) {
	if booter.workqueue.NumRequeues(key) < maxRetries {
		booter.workqueue.AddRateLimited(key)
	} else {
		log.WithField("key", key).Warn(
			"Too many node controller deployment failures. Not requeueing.")
		booter.workqueue.Forget(key)
	}
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

	volumes := []corev1.Volume{
		{
			Name: "cert",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: certSecretName(node),
				},
			},
		},
	}
	volumeMounts := []corev1.VolumeMount{
		{
			Name:      "cert",
			MountPath: "/etc/blimp/certs",
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
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							"cpu":    resource.MustParse("250m"),
							"memory": resource.MustParse("1Gi"),
						},
						Limits: corev1.ResourceList{
							"cpu":    resource.MustParse("2"),
							"memory": resource.MustParse("4Gi"),
						},
					},
				},
			},
			Volumes:            volumes,
			ServiceAccountName: serviceAccount.Name,
			NodeName:           node,
			Tolerations: []corev1.Toleration{
				{
					Key:      dnsTaint.Key,
					Operator: corev1.TolerationOpExists,
					Effect:   dnsTaint.Effect,
				},
			},
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
	newService := false
	servicesClient := booter.kubeClient.CoreV1().Services(NodeControllerNamespace)
	if _, err := servicesClient.Get(service.Name, metav1.GetOptions{}); err != nil {
		newService = true
		_, err := servicesClient.Create(service)
		if err != nil {
			return errors.WithContext("create service", err)
		}
	}

	var certIPs []net.IP
	var certHostnames []string
	var host string
	// EKS can take ~3 minutes in some cases.
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Minute)
	err := kubewait.WaitForObject(ctx,
		kubewait.ServiceGetter(booter.kubeClient, NodeControllerNamespace, service.Name),
		booter.kubeClient.CoreV1().Services(NodeControllerNamespace).Watch,
		func(svcIntf interface{}) bool {
			svc := svcIntf.(*corev1.Service)

			ingress := svc.Status.LoadBalancer.Ingress
			if len(ingress) == 1 {
				if ingress[0].IP != "" {
					certIPs = []net.IP{net.ParseIP(ingress[0].IP)}
					host = ingress[0].IP
					return true
				}
				if ingress[0].Hostname != "" {
					certHostnames = []string{ingress[0].Hostname}
					host = ingress[0].Hostname
					return true
				}
			}
			return false
		})
	if err != nil {
		return errors.WithContext("wait for public IP", err)
	}

	// Add a taint to the node if the service is hostname-based. We will remove
	// the taint once DNS records for the service are available. This will keep
	// sandboxes from being scheduled to the node without being able to connect
	// to the node controller.
	if len(certHostnames) > 0 {
		if newService {
			hasTaint, err := nodeHasTaint(booter.kubeClient, node, dnsTaint)
			if err != nil {
				return err
			}

			if !hasTaint {
				err := updateNode(booter.kubeClient, node,
					func(node corev1.Node) corev1.Node {
						node.Spec.Taints = append(node.Spec.Taints, dnsTaint)
						return node
					})
				if err != nil {
					return errors.WithContext("add DNS taint", err)
				}
			}
		}

		// Watch for DNS to become available, and then remove the corresponding
		// taint. We do this in a goroutine because it can take several minutes,
		// and it's mostly just waiting around.
		go booter.watchDNSTaint(node, host)
	}

	// Generate new certificates for the Node Controller if it's the first
	// time deploying the controller.
	secretsClient := booter.kubeClient.CoreV1().Secrets(NodeControllerNamespace)
	_, err = secretsClient.Get(certSecretName(node), metav1.GetOptions{})
	if err != nil {
		cert, key, err := newSelfSignedCert(certIPs, certHostnames)
		if err != nil {
			return errors.WithContext("generate cert", err)
		}

		certSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      certSecretName(node),
				Namespace: NodeControllerNamespace,
				Annotations: map[string]string{
					"host": fmt.Sprintf("%s:%d", host, ports.NodeControllerPublicPort),
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

	if err := kube.DeployPod(booter.kubeClient, pod, kube.DeployPodOptions{}); err != nil {
		return errors.WithContext("deploy", err)
	}

	return nil
}

func (booter *booter) watchDNSTaint(node, hostname string) {
	// Wait until we see a DNS record for the hostname.
	for {
		// Check to see if we still have the taint. If not, we can be done.
		hasTaint, err := nodeHasTaint(booter.kubeClient, node, dnsTaint)
		if err != nil {
			log.WithField("node", node).WithError(err).Error(
				"Failed to check taint.")
			return
		}
		if !hasTaint {
			return
		}

		_, err = net.LookupIP(hostname)
		if err == nil {
			// We have DNS!
			log.WithField("node", node).WithField("hostname", hostname).Debug(
				"Found a DNS record for node controller LB.")
			break
		}

		// We only really expect to get a temporary error, or NXDOMAIN. If we
		// see something else, that's not a good sign.
		dnsErr, ok := err.(*net.DNSError)
		if !ok {
			log.WithField("node", node).WithField("hostname", hostname).WithError(err).Error(
				"Unknown error type while resolving DNS.")
			return
		}
		if !dnsErr.IsNotFound && !dnsErr.Temporary() {
			log.WithField("node", node).WithField("hostname", hostname).WithError(err).Error(
				"Unexpected error while resolving DNS.")
			return
		}

		time.Sleep(30 * time.Second)
	}

	// AWS ELB DNS has 60s negative TTL, so we wait a little longer than that to
	// make sure negative caches should be gone.
	time.Sleep(90 * time.Second)

	log.WithField("node", node).Info("Removing DNS taint.")

	// Remove the taint.
	err := updateNode(booter.kubeClient, node,
		func(node corev1.Node) corev1.Node {
			var newTaints []corev1.Taint
			for _, taint := range node.Spec.Taints {
				if taint.Key != dnsTaint.Key {
					newTaints = append(newTaints, taint)
				}
			}
			node.Spec.Taints = newTaints
			return node
		})
	if err != nil {
		log.WithField("node", node).WithField("hostname", hostname).WithError(err).Warn(
			"Failed to remove node DNS taint.")
	}
}

func newSelfSignedCert(ips []net.IP, dnsNames []string) (pemCert, pemKey []byte, err error) {
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
		IPAddresses:           ips,
		DNSNames:              dnsNames,
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

func nodeHasTaint(kubeClient kubernetes.Interface, name string,
	taint corev1.Taint) (bool, error) {

	node, err := kubeClient.CoreV1().Nodes().Get(name, metav1.GetOptions{})
	if err != nil {
		return false, errors.WithContext("get node to check taint", err)
	}

	for _, nodeTaint := range node.Spec.Taints {
		if nodeTaint == taint {
			return true, nil
		}
	}
	return false, nil
}

func updateNode(kubeClient kubernetes.Interface, name string,
	update func(corev1.Node) corev1.Node) error {

	nodesClient := kubeClient.CoreV1().Nodes()
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		node, err := nodesClient.Get(name, metav1.GetOptions{})
		if err != nil {
			return errors.WithContext("update get", err)
		}

		newNode := update(*node)
		_, err = nodesClient.Update(&newNode)
		return err
	})
}
