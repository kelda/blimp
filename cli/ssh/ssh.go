package ssh

import (
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh/terminal"
	core "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"

	"github.com/kelda-inc/blimp/cli/authstore"
)

func New() *cobra.Command {
	return &cobra.Command{
		Use: "ssh",
		Run: func(_ *cobra.Command, args []string) {
			if len(args) != 1 {
				fmt.Fprintf(os.Stderr, "Exactly one service is required")
				os.Exit(1)
			}

			if err := run(args[0]); err != nil {
				log.Fatal(err)
			}
		},
	}
}

func run(svc string) error {
	auth, err := authstore.New()
	if err != nil {
		return fmt.Errorf("parse auth config: %w", err)
	}

	if auth.AuthToken == "" {
		fmt.Fprintln(os.Stderr, "Not logged in. Please run `blimp login`.")
		return nil
	}

	kubeClient, restConfig, err := auth.KubeClient()
	if err != nil {
		return fmt.Errorf("get kube client: %w", err)
	}

	// Put the terminal into raw mode to prevent it echoing characters twice.
	oldState, err := terminal.MakeRaw(0)
	if err != nil {
		return fmt.Errorf("set terminal mode: %w", err)
	}

	defer func() {
		_ = terminal.Restore(0, oldState)
	}()

	execOpts := core.PodExecOptions{
		Command: []string{"sh"},
		Stdin:   true,
		Stdout:  true,
		Stderr:  true,
		TTY:     true,
	}
	streamOpts := remotecommand.StreamOptions{
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
		Tty:    true,
	}

	req := kubeClient.CoreV1().RESTClient().Post().
		Resource("pods").
		SubResource("exec").
		Name(svc).
		Namespace(auth.KubeNamespace).
		VersionedParams(&execOpts, scheme.ParameterCodec)
	exec, err := remotecommand.NewSPDYExecutor(restConfig, "POST", req.URL())
	if err != nil {
		return fmt.Errorf("setup remote shell: %w", err)
	}

	err = exec.Stream(streamOpts)
	if err != nil {
		return fmt.Errorf("stream: %w", err)
	}
	return nil
}
