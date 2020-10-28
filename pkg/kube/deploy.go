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

	"github.com/kelda/blimp/pkg/errors"
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

func DeployClusterRole(kubeClient kubernetes.Interface, role rbacv1.ClusterRole) error {
	c := kubeClient.RbacV1().ClusterRoles()
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

func DeployClusterRoleBinding(kubeClient kubernetes.Interface, binding rbacv1.ClusterRoleBinding) error {
	c := kubeClient.RbacV1().ClusterRoleBindings()
	currBinding, err := c.Get(binding.Name, metav1.GetOptions{})
	if exists := err == nil; exists {
		binding.ResourceVersion = currBinding.ResourceVersion
		_, err = c.Update(&binding)
	} else {
		_, err = c.Create(&binding)
	}
	return err
}

type Sanitizer func(desired, curr *corev1.Pod) *corev1.Pod

type DeployPodOptions struct {
	ForceRestart bool
	Sanitizers   []Sanitizer
}

func DeployPod(kubeClient kubernetes.Interface, pod corev1.Pod, opts DeployPodOptions) error {
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
		if !opts.ForceRestart {
			// Make a copy to avoid modifying the desired pod, since that pod is used
			// to deploy.
			sanitized := (&pod).DeepCopy()
			for _, sanitize := range opts.Sanitizers {
				sanitized = sanitize(sanitized, curr)
			}
			annot, err := runtime.Encode(unstructured.UnstructuredJSONScheme, sanitized)
			if err != nil {
				return errors.WithContext("make apply annotation", err)
			}

			if string(annot) == curr.Annotations["blimp.appliedObject"] {
				return nil
			}
		}

		// Delete the existing pod before we recreate it.
		if err := DeletePod(kubeClient, pod.Namespace, pod.Name); err != nil {
			return errors.WithContext("delete pod", err)
		}
	}

	// Add an annotation to track the spec that was used to deploy the pod.
	// This way, we can avoid recreating pods when the underlying spec hasn't
	// changed.
	// We can't just use podClient.Update and let Kubernetes handle it because
	// some of the PodSpec fields are immutable.
	applyAnnotation, err := runtime.Encode(unstructured.UnstructuredJSONScheme, &pod)
	if err != nil {
		return errors.WithContext("make apply annotation", err)
	}

	if pod.Annotations == nil {
		pod.Annotations = map[string]string{}
	}
	pod.Annotations["blimp.appliedObject"] = string(applyAnnotation)

	if _, err := podClient.Create(&pod); err != nil {
		return errors.WithContext("create pod", err)
	}
	return nil
}

func DeployServiceAccount(kubeClient kubernetes.Interface, sa corev1.ServiceAccount, roles ...rbacv1.Role) error {
	return deployServiceAccount(kubeClient, sa, roles, nil)
}

func DeployClusterServiceAccount(kubeClient kubernetes.Interface, sa corev1.ServiceAccount,
	roles ...rbacv1.ClusterRole) error {
	return deployServiceAccount(kubeClient, sa, nil, roles)
}

func deployServiceAccount(kubeClient kubernetes.Interface, serviceAccount corev1.ServiceAccount,
	namespaceRoles []rbacv1.Role, clusterRoles []rbacv1.ClusterRole) error {

	// Create the service account.
	saClient := kubeClient.CoreV1().ServiceAccounts(serviceAccount.Namespace)
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

	for _, role := range namespaceRoles {
		if err := DeployRole(kubeClient, role); err != nil {
			return errors.WithContext("create role", err)
		}

		meta, subjects, roleRef := roleBindingForRole(serviceAccount, "Role", role.Name)
		binding := rbacv1.RoleBinding{
			ObjectMeta: meta,
			Subjects:   subjects,
			RoleRef:    roleRef,
		}
		if err := DeployRoleBinding(kubeClient, binding); err != nil {
			return errors.WithContext("create role", err)
		}
	}

	for _, role := range clusterRoles {
		if err := DeployClusterRole(kubeClient, role); err != nil {
			return errors.WithContext("create role", err)
		}

		meta, subjects, roleRef := roleBindingForRole(serviceAccount, "ClusterRole", role.Name)
		binding := rbacv1.ClusterRoleBinding{
			ObjectMeta: meta,
			Subjects:   subjects,
			RoleRef:    roleRef,
		}
		if err := DeployClusterRoleBinding(kubeClient, binding); err != nil {
			return errors.WithContext("create role", err)
		}
	}

	return nil
}

func roleBindingForRole(sa corev1.ServiceAccount, roleKind, roleName string) (
	metav1.ObjectMeta, []rbacv1.Subject, rbacv1.RoleRef) {
	meta := metav1.ObjectMeta{
		Name:      fmt.Sprintf("%s-%s", sa.Name, roleName),
		Namespace: sa.Namespace,
	}
	subjects := []rbacv1.Subject{
		{
			Kind:      "ServiceAccount",
			Name:      sa.Name,
			Namespace: sa.Namespace,
		},
	}
	roleRef := rbacv1.RoleRef{
		APIGroup: "rbac.authorization.k8s.io",
		Kind:     roleKind,
		Name:     roleName,
	}

	return meta, subjects, roleRef
}

func DeployConfigMap(kubeClient kubernetes.Interface, configMap corev1.ConfigMap) error {
	configMapClient := kubeClient.CoreV1().ConfigMaps(configMap.Namespace)
	currConfigMap, err := configMapClient.Get(configMap.Name, metav1.GetOptions{})
	if err == nil {
		configMap.ResourceVersion = currConfigMap.ResourceVersion
		if _, err := configMapClient.Update(&configMap); err != nil {
			return errors.WithContext("update configMap", err)
		}
	} else if _, err := configMapClient.Create(&configMap); err != nil {
		return errors.WithContext("create configMap", err)
	}
	return nil
}

func SanitizeIgnoreInitContainerImages(desired, curr *corev1.Pod) *corev1.Pod {
	currImages := map[string]string{}
	for _, c := range curr.Spec.InitContainers {
		currImages[c.Name] = c.Image
	}

	for i, c := range desired.Spec.InitContainers {
		desired.Spec.InitContainers[i].Image = currImages[c.Name]
	}

	return desired
}

func SanitizeIgnoreNodeAffinity(desired, curr *corev1.Pod) *corev1.Pod {
	if curr.Spec.Affinity == nil || curr.Spec.Affinity.NodeAffinity == nil {
		// Remove NodeAffinity from desired.
		if desired.Spec.Affinity != nil {
			desired.Spec.Affinity.NodeAffinity = nil
		}
		return desired
	}

	if desired.Spec.Affinity == nil {
		desired.Spec.Affinity = &corev1.Affinity{}
	}
	desired.Spec.Affinity.NodeAffinity = curr.Spec.Affinity.NodeAffinity.DeepCopy()

	return desired
}
