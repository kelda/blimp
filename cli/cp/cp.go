package cp

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/kubectl/pkg/scheme"

	"github.com/kelda-inc/blimp/cli/authstore"
	"github.com/kelda-inc/blimp/cli/cp/kubectlcp"
	"github.com/kelda-inc/blimp/pkg/errors"
)

func New() *cobra.Command {
	return &cobra.Command{
		Use:   "cp SRC DST",
		Short: "Copy files to and from services ",
		Long: `To copy FROM a container:
	blimp cp SERVICE:SRC_PATH DEST_PATH

To copy TO a container:
	blimp cp SRC_PATH SERVICE:DEST_PATH`,
		Run: func(_ *cobra.Command, args []string) {
			if len(args) != 2 {
				fmt.Fprintf(os.Stderr, "Dest path and src path need to be defined")
				os.Exit(1)
			}

			if err := run(args[0], args[1]); err != nil {
				errors.HandleFatalError(err)
			}
		},
	}
}

func run(src, dst string) error {
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

	// Required by `kubectlcp` to access the Kubernetes API.
	restConfig.GroupVersion = &schema.GroupVersion{Group: "", Version: "v1"}
	restConfig.APIPath = "/api"
	restConfig.NegotiatedSerializer = scheme.Codecs.WithoutConversion()

	o := &kubectlcp.CopyOptions{
		IOStreams: genericclioptions.IOStreams{
			Out:    os.Stdout,
			In:     os.Stdin,
			ErrOut: os.Stderr,
		},
		Namespace:    auth.KubeNamespace,
		Clientset:    kubeClient,
		ClientConfig: restConfig,
	}
	return o.Run([]string{src, dst})
}
