package main

import (
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/kelda-inc/blimp/cli/authstore"
	"github.com/kelda-inc/blimp/cli/cp"
	"github.com/kelda-inc/blimp/cli/down"
	"github.com/kelda-inc/blimp/cli/login"
	"github.com/kelda-inc/blimp/cli/logs"
	"github.com/kelda-inc/blimp/cli/manager"
	"github.com/kelda-inc/blimp/cli/ps"
	"github.com/kelda-inc/blimp/cli/ssh"
	"github.com/kelda-inc/blimp/cli/up"
	"github.com/kelda-inc/blimp/pkg/analytics"
	"github.com/kelda-inc/blimp/pkg/auth"
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

		PersistentPreRun:  setupAnalytics,
		PersistentPostRun: closeManager,

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
		cp.New(),
	)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func setupAnalytics(cmd *cobra.Command, _ []string) {
	if err := manager.SetupClient(); err != nil {
		log.WithError(err).Fatal("Failed to connect to the Blimp cluster")
	}

	analytics.Init(analytics.ProxyPoster{manager.C}, analytics.StreamID{
		Source:    cmd.CalledAs(),
		Namespace: getNamespace(),
	})

	analytics.Log.WithFields(log.Fields{
		"cmd":      cmd.CalledAs(),
		"full-cmd": os.Args,
	}).Info("Ran command")
}

func getNamespace() string {
	store, err := authstore.New()
	if err != nil {
		return ""
	}

	if store.AuthToken == "" {
		return "unauthenticated"
	}

	user, err := auth.ParseIDToken(store.AuthToken)
	if err == nil {
		return user.Namespace
	}
	return ""
}

func closeManager(_ *cobra.Command, _ []string) {
	manager.C.Close()
}
