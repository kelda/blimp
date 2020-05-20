package kube

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/kelda-inc/blimp/pkg/errors"
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
