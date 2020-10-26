package main

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	fakeKube "k8s.io/client-go/kubernetes/fake"

	"github.com/kelda-inc/blimp/pkg/kube"
	"github.com/kelda/blimp/pkg/proto/cluster"
)

func TestGetStatus(t *testing.T) {
	tests := []struct {
		name        string
		namespace   string
		mockObjects []runtime.Object
		exp         cluster.SandboxStatus
	}{
		{
			name:      "CreateContainerError",
			namespace: "namespace",
			mockObjects: []runtime.Object{
				&corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: "namespace",
					},
				},
				&corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "namespace",
						Name:      "web",
						Labels: map[string]string{
							"blimp.customerPod": "true",
							"blimp.service":     "web",
						},
					},
					Status: corev1.PodStatus{
						ContainerStatuses: []corev1.ContainerStatus{
							{
								State: corev1.ContainerState{
									Waiting: &corev1.ContainerStateWaiting{
										Reason:  "CreateContainerError",
										Message: "context deadline exceeded",
									},
								},
							},
						},
					},
				},
			},
			exp: cluster.SandboxStatus{
				Phase: cluster.SandboxStatus_RUNNING,
				Services: map[string]*cluster.ServiceStatus{
					"web": {
						Phase: cluster.ServicePhase_PENDING,
						Msg: fmt.Sprintf(createContainerErrorTemplate,
							"CreateContainerError", "context deadline exceeded"),
					},
				},
			},
		},
		{
			name:      "InitCreateContainerError",
			namespace: "namespace",
			mockObjects: []runtime.Object{
				&corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: "namespace",
					},
				},
				&corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "namespace",
						Name:      "web",
						Labels: map[string]string{
							"blimp.customerPod": "true",
							"blimp.service":     "web",
						},
					},
					Status: corev1.PodStatus{
						InitContainerStatuses: []corev1.ContainerStatus{
							{
								Name: kube.ContainerNameWaitDependsOn,
								State: corev1.ContainerState{
									Waiting: &corev1.ContainerStateWaiting{
										Reason:  "CreateContainerError",
										Message: "context deadline exceeded",
									},
								},
							},
						},
					},
				},
			},
			exp: cluster.SandboxStatus{
				Phase: cluster.SandboxStatus_RUNNING,
				Services: map[string]*cluster.ServiceStatus{
					"web": {
						Phase: cluster.ServicePhase_PENDING,
						Msg: fmt.Sprintf(createContainerErrorTemplate,
							"CreateContainerError", "context deadline exceeded"),
					},
				},
			},
		},
		{
			name:      "Evicted",
			namespace: "namespace",
			mockObjects: []runtime.Object{
				&corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: "namespace",
					},
				},
				&corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "namespace",
						Name:      "web",
						Labels: map[string]string{
							"blimp.customerPod": "true",
							"blimp.service":     "web",
						},
					},
					Status: corev1.PodStatus{
						Phase:  corev1.PodFailed,
						Reason: "Evicted",
						Message: "The node was low on resource: memory. " +
							"Container nuxtpublic-8c9fd51e73 was using 819944Ki, which exceeds its request of 50Mi.",
					},
				},
			},
			exp: cluster.SandboxStatus{
				Phase: cluster.SandboxStatus_RUNNING,
				Services: map[string]*cluster.ServiceStatus{
					"web": {
						Phase: cluster.ServicePhase_EXITED,
						Msg: "The node was low on resource: memory. " +
							"Container nuxtpublic-8c9fd51e73 was using 819944Ki, which exceeds its request of 50Mi.",
						HasStarted: true,
					},
				},
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			kubeClient := fakeKube.NewSimpleClientset(test.mockObjects...)

			sf := newStatusFetcher(kubeClient)

			stop := make(chan struct{})
			defer close(stop)
			sf.Start(stop)

			actual, err := sf.Get(test.namespace)
			assert.NoError(t, err)
			assert.Equal(t, test.exp, actual)
		})
	}
}
