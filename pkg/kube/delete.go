package kube

import (
	"time"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/kelda/blimp/pkg/errors"
)

func DeletePod(kubeClient kubernetes.Interface, namespace, name string) error {
	podClient := kubeClient.CoreV1().Pods(namespace)
	if err := podClient.Delete(name, metav1.NewDeleteOptions(0)); err != nil {
		return err
	}

	podWatcher, err := podClient.Watch(metav1.ListOptions{})
	if err != nil {
		return errors.WithContext("watch pods", err)
	}
	defer podWatcher.Stop()
	watcherChan := podWatcher.ResultChan()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		_, err := podClient.Get(name, metav1.GetOptions{})
		switch {
		case kerrors.IsNotFound(err):
			return nil
		case err != nil:
			return errors.WithContext("get pod", err)
		}

		select {
		case <-ticker.C:
		case <-watcherChan:
		}
	}
}
