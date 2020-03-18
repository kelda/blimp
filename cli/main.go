package main

import (
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/kelda-inc/blimp/cli/login"
	"github.com/kelda-inc/blimp/cli/logs"
	"github.com/kelda-inc/blimp/cli/ps"
	"github.com/kelda-inc/blimp/cli/up"
)

func main() {
	// By default, the random number generator is seeded to 1, so the resulting
	// numbers aren't actually different unless we explicitly seed it.
	rand.Seed(time.Now().UnixNano())

	rootCmd := &cobra.Command{
		Use: "blimp",

		// The call to rootCmd.Execute prints the error, so we silence errors
		// here to avoid double printing.
		SilenceErrors: true,
	}
	rootCmd.AddCommand(
		login.New(),
		logs.New(),
		ps.New(),
		up.New(),
	)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
