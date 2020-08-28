package main

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/kelda-inc/blimp/cluster-controller/affinity"
	"github.com/kelda-inc/blimp/pkg/kube"
	"github.com/kelda-inc/blimp/pkg/version"
	"github.com/kelda/blimp/pkg/errors"
)

func createBuildkitd(kubeClient kubernetes.Interface, namespace string) error {
	runAsUser := int64(1000)
	runAsGroup := int64(1000)
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      kube.PodNameBuildkitd,
			Labels: map[string]string{
				"service": kube.PodNameBuildkitd,
				// Note that the buildkit pod doesn't have the blimp.customer
				// label set, since that's used to force pods to run on the same
				// node. If it were set for buildkit, the affinity rule for
				// running buildkit on a dedicated node would conflict with the
				// rule to run customer pods on the same node.
			},
			Annotations: map[string]string{
				"container.apparmor.security.beta.kubernetes.io/buildkitd": "unconfined",
				"container.seccomp.security.alpha.kubernetes.io/buildkitd": "unconfined",
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  kube.PodNameBuildkitd,
				Image: version.BuildkitdImage,
				Args: []string{
					"--addr",
					"tcp://0.0.0.0:1234",
					"--oci-worker-no-process-sandbox",
				},
				SecurityContext: &corev1.SecurityContext{
					RunAsUser:  &runAsUser,
					RunAsGroup: &runAsGroup,
				},
				Resources: corev1.ResourceRequirements{
					Limits: corev1.ResourceList{
						"cpu":    resource.MustParse("1"),
						"memory": resource.MustParse("2Gi"),
					},
					Requests: corev1.ResourceList{
						"cpu":    resource.MustParse("100m"),
						"memory": resource.MustParse("100Mi"),
					},
				},
				// XXX: We should persist the disk used for build cache, so that
				// re-building after `blimp down` can still hit the build cache.
				// When adding this, we should be careful that the readiness
				// probe does not cause high CPU usage in the systemd process.
				ReadinessProbe: &corev1.Probe{
					Handler: corev1.Handler{
						Exec: &corev1.ExecAction{
							Command: []string{
								"buildctl",
								"--addr",
								"tcp://localhost:1234",
								"debug",
								"workers",
							},
						},
					},

					PeriodSeconds:       30,
					InitialDelaySeconds: 5,
				},
			}},
			Affinity:      affinity.OnBuilderNode,
			RestartPolicy: corev1.RestartPolicyAlways,
		},
	}

	if err := kube.DeployPod(kubeClient, pod, kube.DeployPodOptions{}); err != nil {
		return errors.WithContext("deploy pod", err)
	}
	return nil
}
