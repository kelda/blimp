package main

import (
	"context"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/kelda-inc/blimp/pkg/kube"
	"github.com/kelda-inc/blimp/pkg/version"
	"github.com/kelda/blimp/pkg/auth"
	"github.com/kelda/blimp/pkg/names"
	"github.com/kelda/blimp/pkg/proto/cluster"
)

func createCLINamespace(kubeClient kubernetes.Interface) {
	for {
		_, err := kubeClient.CoreV1().Namespaces().Create(&corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: kube.PreviewCLINamespace,
			},
		})
		if err == nil || kerrors.IsAlreadyExists(err) {
			break
		}

		log.WithError(err).
			WithField("namespace", kube.PreviewCLINamespace).
			Error("Failed to create namespace. Retrying in 15 seconds.")
		time.Sleep(15 * time.Second)
	}
}

func (s *server) BlimpUpPreview(ctx context.Context, req *cluster.BlimpUpPreviewRequest) (*cluster.BlimpUpPreviewResponse, error) {
	user, err := auth.ParseIDToken(req.GetToken(), auth.DefaultVerifier)
	if err != nil {
		return &cluster.BlimpUpPreviewResponse{}, err
	}

	// XXX: This should probably be a Deployment rather than a Pod so that the
	// CLI will get redeployed if the pod gets unscheduled. However, the
	// behavior of reattaching the Blimp CLI is undefined, and we don't need
	// the CLI to be running after it completes the initial boot anyways.
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      names.PodName(fmt.Sprintf("blimp-cli-%s", user.Namespace)),
			Namespace: kube.PreviewCLINamespace,
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "blimp-cli",
				Image: version.CLIImage,
				Resources: corev1.ResourceRequirements{
					Requests: corev1.ResourceList{
						"cpu":    resource.MustParse("100m"),
						"memory": resource.MustParse("100Mi"),
					},
					Limits: corev1.ResourceList{
						"cpu":    resource.MustParse("1"),
						"memory": resource.MustParse("1Gi"),
					},
				},
				Env: []corev1.EnvVar{
					{
						Name:  "BLIMP_TOKEN",
						Value: req.GetToken(),
					},
					{
						Name:  "GIT_REPO",
						Value: req.GetRepo(),
					},
				},
				Args: []string{
					"blimp", "up",
				},
			}},
			RestartPolicy: corev1.RestartPolicyNever,
		},
	}

	return &cluster.BlimpUpPreviewResponse{}, kube.DeployPod(s.kubeClient, pod, kube.DeployPodOptions{})
}
