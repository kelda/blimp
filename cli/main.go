package main

import (
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/kelda-inc/blimp/cli/down"
	"github.com/kelda-inc/blimp/cli/login"
	"github.com/kelda-inc/blimp/cli/logs"
	"github.com/kelda-inc/blimp/cli/ps"
	"github.com/kelda-inc/blimp/cli/ssh"
	"github.com/kelda-inc/blimp/cli/up"
	"github.com/kelda-inc/blimp/pkg/cfgdir"

	log "github.com/sirupsen/logrus"
)

func main() {
	// By default, the random number generator is seeded to 1, so the resulting
	// numbers aren't actually different unless we explicitly seed it.
	rand.Seed(time.Now().UnixNano())

	if err := cfgdir.Create(); err != nil {
		log.WithError(err).Fatal("failed to create config directory")
	}

	rootCmd := &cobra.Command{
		Use: "blimp",

		// The call to rootCmd.Execute prints the error, so we silence errors
		// here to avoid double printing.
		SilenceErrors: true,
	}
	rootCmd.AddCommand(
		down.New(),
		login.New(),
		logs.New(),
		ps.New(),
		ssh.New(),
		up.New(),
	)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
