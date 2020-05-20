package kube

import (
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"

	"github.com/kelda-inc/blimp/pkg/errors"
)

func WaitForObject(
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

func PodGetter(kubeClient kubernetes.Interface, namespace, name string) func() (interface{}, error) {
	return func() (interface{}, error) {
		return kubeClient.CoreV1().Pods(namespace).Get(name, metav1.GetOptions{})
	}
}

func ServiceAccountGetter(kubeClient kubernetes.Interface, namespace, name string) func() (interface{}, error) {
	return func() (interface{}, error) {
		return kubeClient.CoreV1().ServiceAccounts(namespace).Get(name, metav1.GetOptions{})
	}
}

func ServiceGetter(kubeClient kubernetes.Interface, namespace, name string) func() (interface{}, error) {
	return func() (interface{}, error) {
		return kubeClient.CoreV1().Services(namespace).Get(name, metav1.GetOptions{})
	}
}
