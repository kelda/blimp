package down

import (
	"context"
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/kelda-inc/blimp/cli/authstore"
	"github.com/kelda-inc/blimp/cli/manager"
	"github.com/kelda-inc/blimp/pkg/errors"
	"github.com/kelda-inc/blimp/pkg/proto/cluster"
)

func New() *cobra.Command {
	return &cobra.Command{
		Use:   "down",
		Short: "Delete your cloud sandbox",
		Long: `Delete your cloud sandbox.

All containers and volumes are removed.`,
		Run: func(_ *cobra.Command, args []string) {
			auth, err := authstore.New()
			if err != nil {
				log.WithError(err).Fatal("Failed to parse local authentication store")
			}

			// TODO: Prompt to login again if token is expired.
			if auth.AuthToken == "" {
				fmt.Fprintln(os.Stderr, "Not logged in. Please run `blimp login`.")
				os.Exit(1)
			}

			if err := run(auth.AuthToken); err != nil {
				errors.HandleFatalError(err)
			}
		},
	}
}

func run(authToken string) error {
	_, err := manager.C.DeleteSandbox(context.Background(), &cluster.DeleteSandboxRequest{
		Token: authToken,
	})
	if err == nil {
		fmt.Println("Sandbox deletion successfully started")
	}
	return err
}
