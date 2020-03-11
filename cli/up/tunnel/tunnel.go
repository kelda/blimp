package tunnel

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"

	"github.com/kelda-inc/blimp/pkg/dockercompose"
)

type Tunnel struct {
	Service string
	dockercompose.PortMapping
}

func Run(kubeClient kubernetes.Interface, restConfig *rest.Config, namespace string, tunnels []Tunnel) {
	podsClient := kubeClient.CoreV1().Pods(namespace)
	watcher, err := podsClient.Watch(metav1.ListOptions{
		LabelSelector: "blimp.customerPod=true",
	})
	if err != nil {
		log.WithError(err).Error("Failed to watch pods")
		return
	}
	defer watcher.Stop()

	runningTunnels := map[Tunnel]struct{}{}
	ticker := time.NewTimer(30 * time.Second)
	podsChanged := watcher.ResultChan()
	for {
		select {
		case <-podsChanged:
		case <-ticker.C:
		}

		for _, tunnel := range tunnels {
			if _, ok := runningTunnels[tunnel]; ok {
				continue
			}

			pod, err := kubeClient.CoreV1().Pods(namespace).Get(tunnel.Service, metav1.GetOptions{})
			if err != nil {
				if !kerrors.IsNotFound(err) {
					log.WithError(err).Error("Failed to get pod")
				}
				continue
			}

			if pod.Status.Phase != corev1.PodRunning {
				continue
			}

			go func(tunnel Tunnel) {
				// TODO: Handle errors: reopen if tunnel crashes, etc.
				log.WithField("tunnel", tunnel).Info("Starting tunnel")
				if err := runTunnel(kubeClient, restConfig, namespace, pod.Name, tunnel.HostPort, tunnel.ContainerPort); err != nil {
					log.WithError(err).Error("Failed to start tunnel")
				}
			}(tunnel)

			runningTunnels[tunnel] = struct{}{}
		}
	}
}

func runTunnel(kubeClient kubernetes.Interface, restConfig *rest.Config, namespace, pod string, hostPort, containerPort int) error {
	client := kubeClient.CoreV1().RESTClient()
	u := client.Post().
		Resource("pods").
		Namespace(namespace).
		Name(pod).
		SubResource("portforward").URL()

	transport, upgrader, err := spdy.RoundTripperFor(restConfig)
	if err != nil {
		return err
	}
	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport}, "POST", u)

	ports := []string{fmt.Sprintf("%d:%d", hostPort, containerPort)}
	forwarder, err := portforward.New(dialer, ports, nil, nil,
		ioutil.Discard, ioutil.Discard)
	if err != nil {
		return err
	}

	return forwarder.ForwardPorts()
}
