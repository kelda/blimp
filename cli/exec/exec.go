package exec

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh/terminal"
	core "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"

	"github.com/kelda-inc/blimp/cli/authstore"
	"github.com/kelda-inc/blimp/pkg/errors"
	"github.com/kelda-inc/blimp/pkg/kube"
)

func New() *cobra.Command {
	usageMsg := "exec [-h | --help ] SERVICE CMD [ARGS...]"
	helpMsg := "Run a command in a service." +
		"\n\n" +
		"Usage: blimp " + usageMsg + "\n"

	execCmd := cobra.Command{
		Use:   usageMsg,
		Short: "Run a command in a service",
		// This allows the flags passed in to be used by the CMD to be executed and
		// not the exec command.
		DisableFlagParsing:    true,
		DisableFlagsInUseLine: true,
		Run: func(_ *cobra.Command, args []string) {
			if args[0] == "--help" || args[0] == "-h" {
				fmt.Fprintf(os.Stdout, helpMsg)
				os.Exit(1)
			}

			if len(args) < 2 {
				fmt.Fprintf(os.Stderr, "Service and command need to be defined\n")
				os.Exit(1)
			}

			if err := run(args[0], args[1], args[2:]); err != nil {
				errors.HandleFatalError(err)
			}
		},
	}
	execCmd.SetHelpTemplate(helpMsg)
	return &execCmd
}

func run(svc, cmd string, cmdArguments []string) error {
	auth, err := authstore.New()
	if err != nil {
		return errors.WithContext("parse auth config", err)
	}

	if auth.AuthToken == "" {
		fmt.Fprintln(os.Stderr, "Not logged in. Please run `blimp login`.")
		return nil
	}

	kubeClient, restConfig, err := auth.KubeClient()
	if err != nil {
		return errors.WithContext("get kube client", err)
	}

	// Put the terminal into raw mode to prevent it echoing characters twice.
	oldState, err := terminal.MakeRaw(0)
	if err != nil {
		return errors.WithContext("set terminal mode", err)
	}

	defer func() {
		_ = terminal.Restore(0, oldState)
	}()

	execOpts := core.PodExecOptions{
		Command: append([]string{cmd}, cmdArguments...),
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
		Name(kube.PodName(svc)).
		Namespace(auth.KubeNamespace).
		VersionedParams(&execOpts, scheme.ParameterCodec)
	exec, err := remotecommand.NewSPDYExecutor(restConfig, "POST", req.URL())
	if err != nil {
		return errors.WithContext("setup remote shell", err)
	}

	err = exec.Stream(streamOpts)
	if err != nil {
		return errors.WithContext("stream", err)
	}
	return nil
}
