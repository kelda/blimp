package logs

import (
	"errors"
	"fmt"
	"io"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kelda-inc/blimp/cli/authstore"
)

func New() *cobra.Command {
	var opts corev1.PodLogOptions
	cmd := &cobra.Command{
		Use: "logs",
		Run: func(_ *cobra.Command, args []string) {
			if len(args) != 1 {
				fmt.Fprintf(os.Stderr, "Exactly one service is required")
				os.Exit(1)
			}

			if err := run(args[0], opts); err != nil {
				log.Fatal(err)
			}
		},
	}

	cmd.Flags().BoolVarP(&opts.Follow, "follow", "f", false,
		"Specify if the logs should be streamed.")
	cmd.Flags().BoolVarP(&opts.Previous, "previous", "p", false,
		"If true, print the logs for the previous instance of the container if it crashed.")

	return cmd
}

func run(svc string, opts corev1.PodLogOptions) error {
	auth, err := authstore.New()
	if err != nil {
		return fmt.Errorf("parse auth config: %w", err)
	}

	if auth.AuthToken == "" {
		fmt.Fprintln(os.Stderr, "Not logged in. Please run `blimp login`.")
		return nil
	}

	kubeClient, _, err := auth.KubeClient()
	if err != nil {
		return fmt.Errorf("get kube client: %w", err)
	}

	pod, err := kubeClient.CoreV1().Pods(auth.KubeNamespace).Get(svc, metav1.GetOptions{})
	if err != nil {
		if kerrors.IsNotFound(err) {
			return fmt.Errorf("No service named %q. Check the output of `blimp ps` for a list of available services.", svc)
		}
		return fmt.Errorf("get service: %w", err)
	}

	if pod.Status.Phase == corev1.PodPending &&
		len(pod.Status.ContainerStatuses) == 1 &&
		pod.Status.ContainerStatuses[0].RestartCount == 0 {
		return errors.New("service booting")
	}

	logsReq := kubeClient.CoreV1().
		Pods(auth.KubeNamespace).
		GetLogs(svc, &opts)
	logsStream, err := logsReq.Stream()
	if err != nil {
		return fmt.Errorf("read logs: %w", err)
	}
	defer logsStream.Close()

	if _, err := io.Copy(os.Stdout, logsStream); err != nil {
		return fmt.Errorf("write logs: %w", err)
	}
	return nil
}
