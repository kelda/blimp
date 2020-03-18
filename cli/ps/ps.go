package ps

import (
	"context"
	"fmt"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/encoding/gzip"

	"github.com/kelda-inc/blimp/cli/authstore"
	"github.com/kelda-inc/blimp/cli/util"
	"github.com/kelda-inc/blimp/pkg/proto/cluster"
)

func New() *cobra.Command {
	return &cobra.Command{
		Use: "ps",
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
	status, err := clusterManager.GetStatus(context.Background(), &cluster.GetStatusRequest{
		Token: authToken,
	})
	if err != nil {
		return err
	}

	printStatus(*status.Status)
	return nil
}

func printStatus(status cluster.SandboxStatus) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 4, ' ', 0)
	defer w.Flush()
	fmt.Fprintln(w, "SERVICE\tSTATUS")

	var serviceNames []string
	for name := range status.Services {
		serviceNames = append(serviceNames, name)
	}
	sort.Strings(serviceNames)

	for _, name := range serviceNames {
		svc := status.Services[name]
		fmt.Fprintf(w, "%s\t%s\n", name, svc.Phase)
	}
}
