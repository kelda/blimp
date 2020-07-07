package kube

import (
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	fakeKube "k8s.io/client-go/kubernetes/fake"
	kubeTesting "k8s.io/client-go/testing"
)

func TestDeployPod(t *testing.T) {
	namespace := "namespace"
	resource := schema.GroupVersionResource{Version: "v1", Resource: "pods"}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod",
			Namespace: namespace,
		},
		Spec: corev1.PodSpec{
			InitContainers: []corev1.Container{
				{
					Name:  "init",
					Image: "init-image",
				},
			},
			Containers: []corev1.Container{
				{
					Name:  "container",
					Image: "container-image",
				},
			},
		},
	}

	changedInitContainerImage := pod.DeepCopy()
	changedInitContainerImage.Spec.InitContainers[0].Image = "changed-image"

	changedInitContainerImageAndCommand := changedInitContainerImage.DeepCopy()
	changedInitContainerImageAndCommand.Spec.InitContainers[0].Command = []string{"changed", "command"}

	tests := []struct {
		name         string
		toDeploy     *corev1.Pod
		opts         DeployPodOptions
		existingPods []*corev1.Pod
		expActions   []kubeTesting.Action
	}{
		{
			name:     "NoUpdateStrictMatch",
			toDeploy: pod,
			existingPods: []*corev1.Pod{
				pod,
			},
			expActions: []kubeTesting.Action{
				kubeTesting.NewGetAction(resource, namespace, pod.Name),
			},
		},
		{
			name:     "UpdateForce",
			toDeploy: pod,
			existingPods: []*corev1.Pod{
				pod,
			},
			opts: DeployPodOptions{
				ForceRestart: true,
			},
			expActions: []kubeTesting.Action{
				kubeTesting.NewGetAction(resource, namespace, pod.Name),
				kubeTesting.NewDeleteAction(resource, namespace, pod.Name),
				kubeTesting.NewWatchAction(resource, namespace, metav1.ListOptions{}),
				kubeTesting.NewGetAction(resource, namespace, pod.Name),
				kubeTesting.NewCreateAction(resource, namespace, withAnnotation(pod)),
			},
		},
		{
			name:     "NoUpdateVersionDiff",
			toDeploy: changedInitContainerImage,
			existingPods: []*corev1.Pod{
				pod,
			},
			opts: DeployPodOptions{
				Sanitize: SanitizeIgnoreInitContainerImages,
			},
			expActions: []kubeTesting.Action{
				kubeTesting.NewGetAction(resource, namespace, pod.Name),
			},
		},
		{
			name:     "UpdateChangedNoSanitization",
			toDeploy: changedInitContainerImage,
			existingPods: []*corev1.Pod{
				pod,
			},
			expActions: []kubeTesting.Action{
				kubeTesting.NewGetAction(resource, namespace, pod.Name),
				kubeTesting.NewDeleteAction(resource, namespace, pod.Name),
				kubeTesting.NewWatchAction(resource, namespace, metav1.ListOptions{}),
				kubeTesting.NewGetAction(resource, namespace, pod.Name),
				kubeTesting.NewCreateAction(resource, namespace, withAnnotation(changedInitContainerImage)),
			},
		},
		{
			name:     "UpdateChangedWithSanitization",
			toDeploy: changedInitContainerImageAndCommand,
			existingPods: []*corev1.Pod{
				pod,
			},
			opts: DeployPodOptions{
				Sanitize: SanitizeIgnoreInitContainerImages,
			},
			expActions: []kubeTesting.Action{
				kubeTesting.NewGetAction(resource, namespace, pod.Name),
				kubeTesting.NewDeleteAction(resource, namespace, pod.Name),
				kubeTesting.NewWatchAction(resource, namespace, metav1.ListOptions{}),
				kubeTesting.NewGetAction(resource, namespace, pod.Name),
				kubeTesting.NewCreateAction(resource, namespace, withAnnotation(changedInitContainerImageAndCommand)),
			},
		},
		{
			name:     "FirstDeploy",
			toDeploy: pod,
			expActions: []kubeTesting.Action{
				kubeTesting.NewGetAction(resource, namespace, pod.Name),
				kubeTesting.NewCreateAction(resource, namespace, withAnnotation(pod)),
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			var existingPods []runtime.Object
			for _, pod := range test.existingPods {
				existingPods = append(existingPods, withAnnotation(pod))
			}
			kubeClient := fakeKube.NewSimpleClientset(existingPods...)

			toDeploy := test.toDeploy.DeepCopy()
			assert.NoError(t, DeployPod(kubeClient, *toDeploy, test.opts))
			assert.Equal(t, test.expActions, kubeClient.Actions())
		})
	}
}

func withAnnotation(pod *corev1.Pod) *corev1.Pod {
	annot, err := runtime.Encode(unstructured.UnstructuredJSONScheme, pod)
	if err != nil {
		panic(err)
	}

	pod = pod.DeepCopy()
	if pod.Annotations == nil {
		pod.Annotations = map[string]string{}
	}
	pod.Annotations["blimp.appliedObject"] = string(annot)
	return pod
}
