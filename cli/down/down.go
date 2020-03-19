package down

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/encoding/gzip"

	"github.com/kelda-inc/blimp/cli/authstore"
	"github.com/kelda-inc/blimp/cli/util"
	"github.com/kelda-inc/blimp/pkg/proto/cluster"
)

func New() *cobra.Command {
	return &cobra.Command{
		Use: "down",
		Run: func(_ *cobra.Command, args []string) {
			auth, err := authstore.New()
			if err != nil {
				panic(err)
				//return fmt.Errorf("parse auth config: %w", err)
			}

			// TODO: Prompt to login again if token is expired.
			if auth.AuthToken == "" {
				fmt.Fprintln(os.Stderr, "Not logged in. Please run `blimp login`.")
				os.Exit(1)
			}

			if err := run(auth.AuthToken); err != nil {
				util.HandleFatalError("Unexpected error", err)
			}
		},
	}
}

func run(authToken string) error {
	conn, err := grpc.Dial(util.ManagerHost,
		// TODO: Encrypt
		grpc.WithInsecure(),
		grpc.WithDefaultCallOptions(grpc.UseCompressor(gzip.Name)))
	if err != nil {
		return err
	}
	defer conn.Close()

	clusterManager := cluster.NewManagerClient(conn)
	_, err = clusterManager.Delete(context.Background(), &cluster.DeleteRequest{
		Token: authToken,
	})
	if err == nil {
		fmt.Println("Sandbox deletion successfully started")
	}
	return err
}
