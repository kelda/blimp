package restart

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/kelda/blimp/cli/config"
	"github.com/kelda/blimp/cli/manager"
	"github.com/kelda/blimp/pkg/errors"
	"github.com/kelda/blimp/pkg/proto/cluster"
)

func New() *cobra.Command {
	return &cobra.Command{
		// TODO: SERVICE should be optional, with the default meaning all. Allow
		// use of a --timeout flag to specify the amount of time alloted for
		// graceful pod exit.
		Use:   "restart SERVICE",
		Short: "Restart a service",
		Run: func(_ *cobra.Command, args []string) {
			if len(args) != 1 {
				fmt.Fprintf(os.Stderr, "Exactly one service is required")
				os.Exit(1)
			}

			if err := run(args[0]); err != nil {
				errors.HandleFatalError(err)
			}
		},
	}
}

func run(svc string) error {
	blimpConfig, err := config.GetConfig()
	if err != nil {
		return errors.WithContext("parse auth config", err)
	}

	// Make sure the pod has booted at some point. If it has crashed or exited,
	// that's fine.
	err = manager.CheckServiceStarted(svc, blimpConfig.BlimpAuth())
	if err != nil {
		return err
	}

	_, err = manager.C.Restart(context.Background(), &cluster.RestartRequest{
		Auth:    blimpConfig.BlimpAuth(),
		Service: svc,
	})
	return err
}
