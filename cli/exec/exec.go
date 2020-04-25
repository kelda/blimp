package exec

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
	usageMsg := "exec [-h | --help ] SERVICE CMD [ARGS...]"
	helpMsg := "Run a command in a service." +
		"\n\n" +
		"Usage: blimp " + usageMsg + "\n"

	execCmd := cobra.Command{
		Use:                   usageMsg,
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
				log.Fatal(err)
			}
		},
	}
	execCmd.SetHelpTemplate(helpMsg)
	return &execCmd
}

func run(svc, cmd string, cmdArguments []string) error {
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
