package down

import (
	"context"
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/kelda-inc/blimp/cli/authstore"
	"github.com/kelda-inc/blimp/cli/util"
	"github.com/kelda-inc/blimp/pkg/auth"
	"github.com/kelda-inc/blimp/pkg/proto/cluster"
)

func New() *cobra.Command {
	return &cobra.Command{
		Use: "down",
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
				log.Fatal(err)
			}
		},
	}
}

func run(authToken string) error {
	conn, err := util.Dial(util.ManagerHost, auth.ClusterManagerCert)
	if err != nil {
		return err
	}
	defer conn.Close()

	clusterManager := cluster.NewManagerClient(conn)
	_, err = clusterManager.DeleteSandbox(context.Background(), &cluster.DeleteSandboxRequest{
		Token: authToken,
	})
	if err == nil {
		fmt.Println("Sandbox deletion successfully started")
	}
	return err
}
