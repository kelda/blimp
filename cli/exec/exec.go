package exec

import (
	"github.com/spf13/cobra"
)

func New() *cobra.Command {
	return &cobra.Command{
		Use: "exec",
		Run: func(_ *cobra.Command, args []string) {
			if err := run(); err != nil {
				panic("unimplemented")
			}
		},
	}
}
