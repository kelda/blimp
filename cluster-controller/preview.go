package main

import (
	"fmt"
	"io"
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
	"github.com/kelda/blimp/pkg/errors"
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

func (s *server) BlimpUpPreview(req *cluster.BlimpUpPreviewRequest, srv cluster.Manager_BlimpUpPreviewServer) error {
	user, err := auth.ParseIDToken(req.GetToken(), auth.DefaultVerifier)
	if err != nil {
		return err
	}

	blimpCmd := []string{"blimp", "up", "-d", "--disable-status-output"}
	for _, f := range req.GetComposeFiles() {
		blimpCmd = append(blimpCmd, "-f", f)
	}

	env := []corev1.EnvVar{
		{
			Name:  "BLIMP_TOKEN",
			Value: req.GetToken(),
		},
		{
			Name:  "GIT_REPO",
			Value: req.GetRepo(),
		},
	}
	for k, v := range req.GetEnv() {
		env = append(env, corev1.EnvVar{Name: k, Value: v})
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
				Env:  env,
				Args: blimpCmd,
			}},
			RestartPolicy: corev1.RestartPolicyNever,
		},
	}

	err = kube.DeployPod(s.kubeClient, pod, kube.DeployPodOptions{})
	if err != nil {
		return srv.Send(&cluster.BlimpUpPreviewResponse{
			Error: errors.Marshal(errors.WithContext("start cli", err)),
		})
	}

	started := func(pod *corev1.Pod) bool {
		return pod.Status.Phase == corev1.PodRunning ||
			pod.Status.Phase == corev1.PodSucceeded ||
			pod.Status.Phase == corev1.PodFailed
	}
	if _, err := s.getPod(srv.Context(), pod.Namespace, pod.Name, started); err != nil {
		return srv.Send(&cluster.BlimpUpPreviewResponse{
			Error: errors.Marshal(errors.WithContext("cli never started", err)),
		})
	}

	// Even if the CLI exited, still send the CLI logs so that the user has
	// more info.
	msg := &cluster.BlimpUpPreviewResponse{StartedCli: true}
	if err := srv.Send(msg); err != nil {
		return errors.WithContext("send", err)
	}

	logsReq := s.kubeClient.CoreV1().Pods(pod.Namespace).
		GetLogs(pod.Name, &corev1.PodLogOptions{Follow: true})
	logsStream, err := logsReq.Stream()
	if err != nil {
		return errors.WithContext("start logs stream", err)
	}
	defer logsStream.Close()

	output := make([]byte, 16*1024)
	for {
		n, err := logsStream.Read(output)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}

		msg := &cluster.BlimpUpPreviewResponse{Output: output[:n]}
		if err := srv.Send(msg); err != nil {
			return errors.WithContext("start logs stream", err)
		}
	}
}
