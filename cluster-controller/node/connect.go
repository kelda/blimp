package node

import (
	"context"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/kelda-inc/blimp/pkg/errors"
	"github.com/kelda-inc/blimp/pkg/kube"
)

// GetConnectionInfo returns the information the CLI needs to connect to the
// Node Controller running on `node`.
func GetConnectionInfo(ctx context.Context, kubeClient kubernetes.Interface, node string) (addr string, cert string, err error) {
	// Block until the Node Controller is ready to accept connections.
	// This is required so that we can be certain that the certificate for the
	// controller exists, and so that we know that the CLI's requests to the
	// node controller will succeed.
	ctx, _ = context.WithTimeout(ctx, 3*time.Minute)
	err = kube.WaitForObject(ctx,
		kube.PodGetter(kubeClient, NodeControllerNamespace, nodeControllerName(node)),
		kubeClient.CoreV1().Pods(NodeControllerNamespace).Watch,
		func(podIntf interface{}) bool {
			pod := podIntf.(*corev1.Pod)

			// Wait for the pod to be ready to accept connections.
			for _, container := range pod.Status.ContainerStatuses {
				if !container.Ready {
					return false
				}
			}
			return true
		})
	if err != nil {
		return "", "", errors.WithContext("get node controller pod", err)
	}

	certSecret, err := kubeClient.CoreV1().Secrets(NodeControllerNamespace).Get(
		certSecretName(node), metav1.GetOptions{})
	if err != nil {
		return "", "", errors.WithContext("get TLS certificate", err)
	}

	return certSecret.Annotations["host"], string(certSecret.Data["cert.pem"]), nil
}

// GetNodeControllerInternalIP returns the IP at which other pods in the
// cluster can communicate with the Node Controller.
func GetNodeControllerInternalIP(kubeClient kubernetes.Interface, node string) (string, error) {
	podName := nodeControllerName(node)
	pod, err := kubeClient.CoreV1().Pods(NodeControllerNamespace).
		Get(podName, metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	return pod.Status.PodIP, nil
}
