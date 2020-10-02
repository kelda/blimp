package down

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/kelda/blimp/cli/config"
	"github.com/kelda/blimp/cli/manager"
	"github.com/kelda/blimp/cli/util"
	"github.com/kelda/blimp/pkg/errors"
	"github.com/kelda/blimp/pkg/proto/cluster"
)

func New() *cobra.Command {
	var deleteVolumes bool
	cobraCmd := &cobra.Command{
		Use:   "down",
		Short: "Delete your cloud sandbox",
		Long: `Delete your cloud sandbox.

All containers are removed.
Volumes aren't removed unless the -v flag is used.
`,
		Run: func(_ *cobra.Command, args []string) {
			blimpConfig, err := config.GetConfig()
			if err != nil {
				errors.HandleFatalError(err)
			}

			if util.UpRunning() {
				fmt.Printf("It looks like `blimp up` is still running. You should stop it before running `blimp down`.\n" +
					"Are you sure you want to continue, even though things might break? (y/N) ")
				var response string
				num, err := fmt.Scanln(&response)
				if err != nil || num != 1 ||
					(strings.ToLower(response) != "y" && strings.ToLower(response) != "yes") {
					fmt.Printf("Aborting.\n")
					os.Exit(1)
				}
			}

			if err := Run(blimpConfig.BlimpAuth(), deleteVolumes); err != nil {
				errors.HandleFatalError(err)
			}
		},
	}
	cobraCmd.Flags().BoolVarP(&deleteVolumes, "volumes", "v", false,
		"Remove named volumes declared in the `volumes` section of the Compose file.")
	return cobraCmd
}

func Run(authToken string, deleteVolumes bool) error {
	_, err := manager.C.DeleteSandbox(context.Background(), &cluster.DeleteSandboxRequest{
		Token:         authToken,
		DeleteVolumes: deleteVolumes,
	})
	if err != nil {
		return errors.WithContext("start sandbox deletion", err)
	}

	fmt.Println("Sandbox deletion successfully started")
	fmt.Println("Note that `blimp up` won't work until the previous sandbox is completely deleted")
	pp := util.NewProgressPrinter(os.Stdout, "Waiting for sandbox deletion to complete")
	go pp.Run()
	defer pp.Stop()

	watchCtx, cancelWatch := context.WithCancel(context.Background())
	defer cancelWatch()
	statusStream, err := manager.C.WatchStatus(watchCtx, &cluster.GetStatusRequest{
		Token: authToken,
	})
	if err != nil {
		return errors.WithContext("start sandbox status watch", err)
	}

	for {
		update, err := statusStream.Recv()
		if err != nil {
			return errors.WithContext("read stream", err)
		}

		if update.Status.Phase == cluster.SandboxStatus_DOES_NOT_EXIST {
			return nil
		}
	}
}
