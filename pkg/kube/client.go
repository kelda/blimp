package kube

import (
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/kelda/blimp/pkg/errors"
)

// GetClient gets a Kubernetes client connected to the cluster defined in the
// local kubeconfig.
func GetClient() (kubernetes.Interface, *rest.Config, error) {
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
