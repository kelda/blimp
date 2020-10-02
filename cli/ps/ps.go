package ps

import (
	"context"
	"fmt"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/buger/goterm"
	"github.com/spf13/cobra"

	"github.com/kelda/blimp/cli/config"
	"github.com/kelda/blimp/cli/manager"
	"github.com/kelda/blimp/pkg/errors"
	"github.com/kelda/blimp/pkg/proto/cluster"
)

func New() *cobra.Command {
	return &cobra.Command{
		Use:   "ps",
		Short: "Print the status of services in the cloud sandbox",
		Run: func(_ *cobra.Command, args []string) {
			blimpConfig, err := config.GetConfig()
			if err != nil {
				errors.HandleFatalError(err)
			}

			if err := run(blimpConfig.BlimpAuth()); err != nil {
				errors.HandleFatalError(err)
			}
		},
	}
}

func run(authToken string) error {
	status, err := manager.C.GetStatus(context.Background(), &cluster.GetStatusRequest{
		Token: authToken,
	})
	if err != nil {
		return err
	}

	printStatus(*status.Status)
	return nil
}

func printStatus(status cluster.SandboxStatus) {
	sandboxStr, sandboxColor := GetSandboxStatusString(status.Phase)
	fmt.Printf("Sandbox: %s\n", goterm.Color(sandboxStr, sandboxColor))

	if len(status.Services) == 0 {
		fmt.Println("No services found.")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 4, ' ', 0)
	defer w.Flush()
	fmt.Fprintln(w, "SERVICE\tSTATUS")

	var serviceNames []string
	for name := range status.Services {
		serviceNames = append(serviceNames, name)
	}
	sort.Strings(serviceNames)

	for _, name := range serviceNames {
		statusStr, statusColor, _ := GetStatusString(status.Services[name])
		fmt.Fprintf(w, "%s\t%s\n", name, goterm.Color(statusStr, statusColor))
	}
}
