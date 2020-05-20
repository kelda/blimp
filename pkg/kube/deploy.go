package kube

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"

	"github.com/kelda-inc/blimp/pkg/errors"
)

func DeployRole(kubeClient kubernetes.Interface, role rbacv1.Role) error {
	c := kubeClient.RbacV1().Roles(role.Namespace)
	currRole, err := c.Get(role.Name, metav1.GetOptions{})
	if exists := err == nil; exists {
		role.ResourceVersion = currRole.ResourceVersion
		_, err = c.Update(&role)
	} else {
		_, err = c.Create(&role)
	}
	return err
}

func DeployRoleBinding(kubeClient kubernetes.Interface, binding rbacv1.RoleBinding) error {
	c := kubeClient.RbacV1().RoleBindings(binding.Namespace)
	currBinding, err := c.Get(binding.Name, metav1.GetOptions{})
	if exists := err == nil; exists {
		binding.ResourceVersion = currBinding.ResourceVersion
		_, err = c.Update(&binding)
	} else {
		_, err = c.Create(&binding)
	}
	return err
}

func DeployPod(kubeClient kubernetes.Interface, pod corev1.Pod) error {
	// Add an annotation to track the spec that was used to deploy the pod.
	// This way, we can avoid recreating pods when the underlying spec hasn't
	// changed.
	applyAnnotation, err := runtime.Encode(unstructured.UnstructuredJSONScheme, &pod)
	if err != nil {
		return errors.WithContext("make apply annotation", err)
	}

	if pod.Annotations == nil {
		pod.Annotations = map[string]string{}
	}
	pod.Annotations["blimp.appliedObject"] = string(applyAnnotation)

	// Get the current pod, if it exists.
	podClient := kubeClient.CoreV1().Pods(pod.Namespace)
	curr, err := podClient.Get(pod.Name, metav1.GetOptions{})
	if err != nil && !kerrors.IsNotFound(err) {
		return errors.WithContext("get pod", err)
	}

	// If the pod already exists.
	if err == nil {
		// If the currently deployed pod is already up to date, we don't have
		// to do anything.
		if curr.Annotations["blimp.appliedObject"] == pod.Annotations["blimp.appliedObject"] {
			return nil
		}

		// Delete the existing pod before we recreate it.
		if err := DeletePod(kubeClient, pod.Namespace, pod.Name); err != nil {
			return errors.WithContext("delete pod", err)
		}
	}

	if _, err := podClient.Create(&pod); err != nil {
		return errors.WithContext("create pod", err)
	}
	return nil
}

func DeployServiceAccount(kubeClient kubernetes.Interface, serviceAccount corev1.ServiceAccount, roles ...rbacv1.Role) error {
	saClient := kubeClient.CoreV1().ServiceAccounts(serviceAccount.Namespace)

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
		return errors.WithContext("service account", err)
	}

	for _, role := range roles {
		if err := DeployRole(kubeClient, role); err != nil {
			return errors.WithContext("create role", err)
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
		if err := DeployRoleBinding(kubeClient, binding); err != nil {
			return errors.WithContext("create role", err)
		}
	}
	return nil
}

func DeployConfigMap(kubeClient kubernetes.Interface, configMap corev1.ConfigMap) error {
	configMapClient := kubeClient.CoreV1().ConfigMaps(configMap.Namespace)
	currConfigMap, err := configMapClient.Get(configMap.Name, metav1.GetOptions{})
	if err == nil {
		configMap.ResourceVersion = currConfigMap.ResourceVersion
		if _, err := configMapClient.Update(&configMap); err != nil {
			return errors.WithContext("update configMap", err)
		}
	} else {
		if _, err := configMapClient.Create(&configMap); err != nil {
			return errors.WithContext("create configMap", err)
		}
	}
	return nil
}
