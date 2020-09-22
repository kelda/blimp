package exec

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh/terminal"
	core "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"

	"github.com/kelda/blimp/cli/authstore"
	"github.com/kelda/blimp/cli/manager"
	"github.com/kelda/blimp/pkg/errors"
	"github.com/kelda/blimp/pkg/names"
)

func New() *cobra.Command {
	var disableTTY bool
	execCmd := cobra.Command{
		Short: "Run a command in a service",
		Run: func(_ *cobra.Command, args []string) {
			if len(args) < 2 {
				fmt.Fprintf(os.Stderr, "Service and command need to be defined\n")
				os.Exit(1)
			}

			if err := run(args[0], args[1], args[2:], !disableTTY); err != nil {
				errors.HandleFatalError(err)
			}
		},
		Use: "exec [options] SERVICE CMD [ARGS...]",
		// Don't append [flags] to the end of the usage string. We already have
		// it hardcoded since the options must come before the positional
		// arguments.
		DisableFlagsInUseLine: true,
	}
	execCmd.Flags().BoolVarP(&disableTTY, "disable-tty", "T", false,
		"Disable pseudo-tty allocation. By default 'blimp exec' allocates a TTY.")
	execCmd.Flags().SetInterspersed(false)
	return &execCmd
}

func run(svc, cmd string, cmdArguments []string, enableTTY bool) error {
	auth, err := authstore.New()
	if err != nil {
		return errors.WithContext("parse auth config", err)
	}

	if auth.AuthToken == "" {
		fmt.Fprintln(os.Stderr, "Not logged in. Please run `blimp login`.")
		return nil
	}

	// Make sure the pod is actually booted.
	err = manager.CheckServiceRunning(svc, auth.AuthToken)
	if err != nil {
		return err
	}

	kubeClient, restConfig, err := auth.KubeClient()
	if err != nil {
		return errors.WithContext("get kube client", err)
	}

	// Put the terminal into raw mode to prevent it echoing characters twice.
	tty := enableTTY && terminal.IsTerminal(int(os.Stdin.Fd()))
	if tty {
		oldState, err := terminal.MakeRaw(int(os.Stdin.Fd()))
		if err != nil {
			return errors.WithContext("set terminal mode", err)
		}

		defer func() {
			_ = terminal.Restore(int(os.Stdin.Fd()), oldState)
		}()
	}

	execOpts := core.PodExecOptions{
		Command: append([]string{cmd}, cmdArguments...),
		Stdin:   true,
		Stdout:  true,
		Stderr:  true,
		TTY:     tty,
	}
	streamOpts := remotecommand.StreamOptions{
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
		Tty:    tty,
	}

	req := kubeClient.CoreV1().RESTClient().Post().
		Resource("pods").
		SubResource("exec").
		Name(names.PodName(svc)).
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
