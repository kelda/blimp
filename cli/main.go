package main

import (
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/buger/goterm"
	"github.com/spf13/cobra"

	"github.com/kelda-inc/blimp/cli/authstore"
	"github.com/kelda-inc/blimp/cli/cp"
	"github.com/kelda-inc/blimp/cli/down"
	"github.com/kelda-inc/blimp/cli/exec"
	"github.com/kelda-inc/blimp/cli/login"
	"github.com/kelda-inc/blimp/cli/logs"
	"github.com/kelda-inc/blimp/cli/manager"
	"github.com/kelda-inc/blimp/cli/ps"
	"github.com/kelda-inc/blimp/cli/ssh"
	"github.com/kelda-inc/blimp/cli/up"
	"github.com/kelda-inc/blimp/pkg/analytics"
	"github.com/kelda-inc/blimp/pkg/auth"
	"github.com/kelda-inc/blimp/pkg/cfgdir"
	"github.com/kelda-inc/blimp/pkg/errors"

	log "github.com/sirupsen/logrus"
)

// verboseLogKey is the environment variable used to enable verbose logging.
// When it's set to `true`, Debug events are logged, rather than just Info and
// above.
const verboseLogKey = "BLIMP_LOG_VERBOSE"

func main() {
	configureLogrus()

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
		exec.New(),
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

func configureLogrus() {
	if os.Getenv(verboseLogKey) == "true" {
		log.SetLevel(log.DebugLevel)
	}

	mirrorFile, err := os.OpenFile(cfgdir.CLILogFile(), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		log.WithError(err).Warn("Failed to open CLI log file")
		mirrorFile = nil
	}

	log.SetFormatter(formatter{
		delegated:  &log.TextFormatter{},
		mirrorFile: mirrorFile,
	})
}

type formatter struct {
	delegated  log.Formatter
	mirrorFile *os.File
}

func (f formatter) Format(e *log.Entry) ([]byte, error) {
	// Try to write the log entry to disk as well.
	if f.mirrorFile != nil {
		// Disable the entry's buffer so that we don't double print to the
		// user's terminal.
		eBuffer := e.Buffer
		e.Buffer = nil
		if l, err := f.delegated.Format(e); err == nil {
			f.mirrorFile.Write(l)
		}
		e.Buffer = eBuffer
	}

	if e.Level != log.FatalLevel {
		return f.delegated.Format(e)
	}

	colorLine := func(k string, v interface{}, verb string) string {
		return fmt.Sprintf("%s: "+verb+"\n",
			goterm.Color(k, goterm.YELLOW),
			v)
	}
	body := colorLine("Message", e.Message, "%s")

	// Print the error first because it's more important than the other fields.
	if err, ok := e.Data["error"]; ok {
		body += colorLine("Error", err, "%s")
	}

	var dataBody string
	for k, v := range e.Data {
		if k == "error" {
			continue
		}
		dataBody += " - " + colorLine(k, v, "%+v")
	}

	if len(dataBody) > 0 {
		body += goterm.Color("Additional Info", goterm.YELLOW) + ":" + "\n"
		body += dataBody
	}

	fmt.Fprintf(os.Stderr,
		goterm.Color("FATAL ERROR: Get help at https://kelda.io/blimp/docs/help/", goterm.RED)+"\n"+
			body)
	os.Exit(1)
	return nil, errors.New("unreached")
}
