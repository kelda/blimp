package main

import (
	"math/rand"
	"time"

	"github.com/spf13/cobra"

	"github.com/kelda-inc/blimp/cli/login"
	"github.com/kelda-inc/blimp/cli/logs"
	"github.com/kelda-inc/blimp/cli/up"
	"github.com/kelda-inc/blimp/cli/util"
)

func main() {
	// By default, the random number generator is seeded to 1, so the resulting
	// numbers aren't actually different unless we explicitly seed it.
	rand.Seed(time.Now().UnixNano())

	rootCmd := &cobra.Command{Use: "blimp"}
	rootCmd.AddCommand(
		login.New(),
		logs.New(),
		up.New(),
	)

	if err := rootCmd.Execute(); err != nil {
		util.HandleFatalError("Failed to execute command", err)
	}
}
