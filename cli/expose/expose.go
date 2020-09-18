package expose

import (
	"context"
	"fmt"
	"os"
	"strconv"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/kelda/blimp/cli/authstore"
	"github.com/kelda/blimp/cli/manager"
	"github.com/kelda/blimp/pkg/errors"
	"github.com/kelda/blimp/pkg/proto/cluster"
)

func New() *cobra.Command {
	var unexpose bool
	cobraCmd := &cobra.Command{
		Use:   "expose SERVICE PORT",
		Short: "Expose a service port over the internet",
		Long: `Expose an HTTP service over a publicly-available domain.
PORT should be the port on SERVICE's container that should be exposed, which
might be different from the port you use locally.`,
		Run: func(_ *cobra.Command, args []string) {
			auth, err := authstore.New()
			if err != nil {
				log.WithError(err).Fatal("Failed to parse local authentication store")
			}

			if auth.AuthToken == "" {
				fmt.Fprintln(os.Stderr, "Not logged in. Please run `blimp login`.")
				os.Exit(1)
			}

			if unexpose {
				if len(args) > 0 {
					fmt.Fprintln(os.Stderr, "`blimp expose --rm` automatcially removes all exposed ports.\n"+
						"Please do not pass any arguments.")
					os.Exit(1)
				}
				if err := runUnexpose(auth.AuthToken); err != nil {
					errors.HandleFatalError(err)
				}
				return
			}

			if len(args) != 2 {
				fmt.Fprintln(os.Stderr, "Please specify a service and port to expose. For example,\n"+
					"to expose port 8080 on the \"web\" service, run `blimp expose web 8080`.")
				os.Exit(1)
			}

			port, err := strconv.Atoi(args[1])
			if err != nil {
				fmt.Fprintln(os.Stderr, "%q does not look like a valid port number.", args[1])
				os.Exit(1)
			}

			if err := runExpose(auth.AuthToken, args[0], port); err != nil {
				errors.HandleFatalError(err)
			}
		},
	}
	cobraCmd.Flags().BoolVarP(&unexpose, "rm", "", false,
		"Remove any currently exposed ports")
	return cobraCmd
}

func runExpose(authToken, service string, port int) error {
	resp, err := manager.C.Expose(context.Background(), &cluster.ExposeRequest{
		Token:   authToken,
		Service: service,
		Port:    uint32(port),
	})
	if err != nil {
		return errors.WithContext("send expose port request", err)
	}

	fmt.Printf("The port was successfully exposed. You can access it at:\n%v\n", resp.Link)
	return nil
}

func runUnexpose(authToken string) error {
	_, err := manager.C.Unexpose(context.Background(), &cluster.UnexposeRequest{
		Token: authToken,
	})
	if err != nil {
		return errors.WithContext("send unexpose request", err)
	}

	fmt.Println("All exposed ports have been removed. Active connections may not be immediately closed.")
	return nil
}
