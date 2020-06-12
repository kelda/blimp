package main

import (
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/buger/goterm"
	"github.com/spf13/cobra"

	"github.com/kelda/blimp/cli/authstore"
	"github.com/kelda/blimp/cli/bugtool"
	"github.com/kelda/blimp/cli/cp"
	"github.com/kelda/blimp/cli/down"
	"github.com/kelda/blimp/cli/exec"
	"github.com/kelda/blimp/cli/login"
	"github.com/kelda/blimp/cli/loginpw"
	"github.com/kelda/blimp/cli/logs"
	"github.com/kelda/blimp/cli/manager"
	"github.com/kelda/blimp/cli/ps"
	"github.com/kelda/blimp/cli/ssh"
	"github.com/kelda/blimp/cli/up"
	"github.com/kelda/blimp/pkg/analytics"
	"github.com/kelda/blimp/pkg/auth"
	"github.com/kelda/blimp/pkg/cfgdir"
	"github.com/kelda/blimp/pkg/errors"

	log "github.com/sirupsen/logrus"
)

// verboseLogKey is the environment variable used to enable verbose logging.
// When it's set to `true`, TRACE logs are written to disk, and DEBUG logs are
// printed to the user's console.
const verboseLogKey = "BLIMP_LOG_VERBOSE"

func main() {
	if err := cfgdir.Create(); err != nil {
		log.WithError(err).Fatal("failed to create config directory")
	}

	configureLogrus()

	// By default, the random number generator is seeded to 1, so the resulting
	// numbers aren't actually different unless we explicitly seed it.
	rand.Seed(time.Now().UnixNano())

	rootCmd := &cobra.Command{
		Use: "blimp",

		PersistentPreRun:  setupAnalytics,
		PersistentPostRun: closeManager,

		// The call to rootCmd.Execute prints the error, so we silence errors
		// here to avoid double printing.
		SilenceErrors: true,
	}
	rootCmd.AddCommand(
		bugtool.New(),
		cp.New(),
		down.New(),
		exec.New(),
		login.New(),
		loginpw.New(),
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

func setupAnalytics(cmd *cobra.Command, _ []string) {
	if err := manager.SetupClient(); err != nil {
		log.WithError(err).Fatal("Failed to connect to the Blimp cluster")
	}

	cfg, err := cfgdir.ParseConfig()
	if err != nil {
		log.WithError(err).Fatal("Failed to read blimp config")
	}

	if cfg.OptOutAnalytics {
		return
	}

	analytics.Init(manager.C, analytics.StreamID{
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
	// By default, print INFO logs to the console, and persist DEBUG logs to
	// disk.
	// When running in verbose mode, print DEBUG logs to the console, and TRACE
	// logs to disk.
	printLevel := log.InfoLevel
	mirrorLevel := log.DebugLevel
	if os.Getenv(verboseLogKey) == "true" {
		printLevel = log.DebugLevel
		mirrorLevel = log.TraceLevel
	}

	mirrorFile, err := os.OpenFile(cfgdir.CLILogFile(), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		log.WithError(err).Warn("Failed to open CLI log file")
		mirrorFile = nil
	}

	// Send all logs to our custom formatter. Our formatter will inspect the
	// level, and if it's below `printLevel`, it'll only log it to disk, and
	// not print it to the user's terminal.
	log.SetLevel(log.TraceLevel)
	log.SetFormatter(formatter{
		delegated: &log.TextFormatter{
			// Print out timestamps rather than how long it's been since the
			// process started.
			// This is more useful for correlating logs.
			FullTimestamp: true,
		},
		mirrorFile:  mirrorFile,
		printLevel:  printLevel,
		mirrorLevel: mirrorLevel,
	})
}

type formatter struct {
	delegated   log.Formatter
	mirrorFile  *os.File
	printLevel  log.Level
	mirrorLevel log.Level
}

func (f formatter) Format(e *log.Entry) ([]byte, error) {
	// Try to write the log entry to disk as well.
	if f.mirrorFile != nil && e.Level <= f.mirrorLevel {
		// Disable the entry's buffer so that we don't double print to the
		// user's terminal.
		eBuffer := e.Buffer
		e.Buffer = nil
		if l, err := f.delegated.Format(e); err == nil {
			f.mirrorFile.Write(l)
		}
		e.Buffer = eBuffer
	}

	if e.Level > f.printLevel {
		// Don't actually print the log.
		return nil, nil
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

	// Explicitly log the fatal error because the Logrus hook won't get
	// triggered.
	analytics.Log.WithField("msg", body).Error("Fatal error")

	fmt.Fprintf(os.Stderr,
		goterm.Color("[Error] Get help at https://kelda.io/blimp/docs/help/", goterm.RED)+"\n"+
			body)
	os.Exit(1)
	return nil, errors.New("unreached")
}
