package kube

import (
	"context"
	"time"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"

	"github.com/kelda/blimp/pkg/errors"
)

func WaitForObject(
	ctx context.Context,
	objectGetter func() (interface{}, error),
	watchFn func(metav1.ListOptions) (watch.Interface, error),
	validator func(interface{}) bool) error {

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
		if err != nil && !kerrors.IsNotFound(err) {
			return errors.WithContext("get", err)
		}

		if !kerrors.IsNotFound(err) && validator(obj) {
			return nil
		}

		select {
		case <-watcherChan:
		case <-ticker.C:
		case <-ctx.Done():
			return errors.New("cancelled")
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
