package logs

import (
	"bufio"
	"context"
	"fmt"
	"hash/fnv"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/buger/goterm"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"

	"github.com/kelda-inc/blimp/cli/authstore"
	"github.com/kelda-inc/blimp/cli/manager"
	"github.com/kelda-inc/blimp/pkg/errors"
	"github.com/kelda-inc/blimp/pkg/kube"
	"github.com/kelda-inc/blimp/pkg/proto/cluster"
)

type LogsCommand struct {
	Containers []string
	Opts       corev1.PodLogOptions
	Auth       authstore.Store
}

type rawLogLine struct {
	// Any error that occurred when trying to read logs.
	// If this is non-nil, `message` and `receivedAt` aren't meaningful.
	readError error

	// The container that generated the log.
	fromContainer string

	// The contents of the log line (including the timestamp added by Kubernetes).
	message string

	// The time that we read the log line.
	receivedAt time.Time
}

type parsedLogLine struct {
	// The Kelda container that generated the log.
	fromContainer string

	// The contents of the log line (without the timestamp added by Kubernetes).
	message string

	// The time that the log line was generated by the application according to
	// the machine that the container is running on.
	loggedAt time.Time
}

func New() *cobra.Command {
	cmd := &LogsCommand{}

	cobraCmd := &cobra.Command{
		Use:   "logs SERVICE ...",
		Short: "Print the logs for the given services",
		Long: "Print the logs for the given services.\n\n" +
			"If multiple services are provided, the log output is interleaved.",
		Run: func(_ *cobra.Command, args []string) {
			auth, err := authstore.New()
			if err != nil {
				log.WithError(err).Fatal("Failed to parse auth store")
			}

			if auth.AuthToken == "" {
				fmt.Fprintln(os.Stderr, "Not logged in. Please run `blimp login`.")
				return
			}

			if len(args) == 0 {
				fmt.Fprintf(os.Stderr, "At least one container is required")
				os.Exit(1)
			}

			cmd.Auth = auth
			cmd.Containers = args
			if err := cmd.Run(); err != nil {
				errors.HandleFatalError(err)
			}
		},
	}

	cobraCmd.Flags().BoolVarP(&cmd.Opts.Follow, "follow", "f", false,
		"Specify if the logs should be streamed.")
	cobraCmd.Flags().BoolVarP(&cmd.Opts.Previous, "previous", "p", false,
		"If true, print the logs for the previous instance of the container if it crashed.")

	return cobraCmd
}

func (cmd LogsCommand) Run() error {
	kubeClient, _, err := cmd.Auth.KubeClient()
	if err != nil {
		return errors.WithContext("connect to cluster", err)
	}

	for _, container := range cmd.Containers {
		// For logs to work, the container needs to have started, but it doesn't
		// necessarily need to be running.
		err = manager.CheckServiceStatus(container, cmd.Auth.AuthToken,
			func(svcStatus *cluster.ServiceStatus) bool {
				return svcStatus.GetHasStarted()
			})
		if err != nil {
			return err
		}
	}

	// Exit gracefully when the user Ctrl-C's.
	// The `printLogs` function will return when the context is cancelled,
	// which allows functions defered in this method to run.
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-signalChan
		cancel()
	}()

	var wg sync.WaitGroup
	combinedLogs := make(chan rawLogLine, len(cmd.Containers)*32)
	for _, container := range cmd.Containers {
		// Enable timestamps so that `forwardLogs` can parse the logs.
		cmd.Opts.Timestamps = true
		logsReq := kubeClient.CoreV1().
			Pods(cmd.Auth.KubeNamespace).
			GetLogs(kube.PodName(container), &cmd.Opts)

		logsStream, err := logsReq.Stream()
		if err != nil {
			return errors.WithContext("start logs stream", err)
		}
		defer logsStream.Close()

		wg.Add(1)
		go func(container string) {
			forwardLogs(combinedLogs, container, logsStream)
			wg.Done()
		}(container)
	}

	// No more log messages will be written to the channel once all the
	// `forwardLogs` threads finish.
	go func() {
		wg.Wait()
		close(combinedLogs)
	}()

	noColor := len(cmd.Containers) == 1
	return printLogs(ctx, combinedLogs, noColor)
}

// forwardLogs forwards each log line from `logsReq` to the `combinedLogs`
// channel.
func forwardLogs(combinedLogs chan<- rawLogLine, container string, logsStream io.ReadCloser) {
	reader := bufio.NewReader(logsStream)
	for {
		message, err := reader.ReadString('\n')
		combinedLogs <- rawLogLine{
			fromContainer: container,
			message:       strings.TrimSuffix(message, "\n"),
			receivedAt:    time.Now(),
			readError:     err,
		}
		if err == io.EOF {
			// Signal to the parent that there will be no more logs for this
			// container, so that the parent can shut down cleanly once all the
			// log streams have ended.
			// We let the consumer of `combinedLogs` decide how to handle all
			// other errors.
			return
		}
	}
}

// The logs within a window are guaranteed to be sorted.
// Note that it's still possible for a delayed log to arrive in the next
// window, in which case it will be printed out of order.
const windowSize = 100 * time.Millisecond

// printLogs reads logs from the `rawLogs` in `windowSize` intervals, and
// prints the logs in each window in sorted order.
func printLogs(ctx context.Context, rawLogs <-chan rawLogLine, noColor bool) error {
	var window []rawLogLine
	var flushTrigger <-chan time.Time

	// flush prints the logs in the current window to the terminal.
	flush := func() {
		// Parse the logs in the windows to extract their timestamps.
		var parsedLogs []parsedLogLine
		for _, rawLog := range window {
			message, timestamp, err := parseLogLine(rawLog.message)

			// If we fail to parse the log's timestamp, revert to sorting based
			// on its receival time.
			if err != nil {
				logrus.WithField("message", rawLog.message).
					WithField("container", rawLog.fromContainer).
					WithError(err).Warn("Failed to parse timestamp")
				message = rawLog.message
				timestamp = rawLog.receivedAt
			}

			parsedLogs = append(parsedLogs, parsedLogLine{
				fromContainer: rawLog.fromContainer,
				message:       message,
				loggedAt:      timestamp,
			})
		}

		// Sort logs in the window.
		byLogTime := func(i, j int) bool {
			return parsedLogs[i].loggedAt.Before(parsedLogs[j].loggedAt)
		}
		sort.Slice(parsedLogs, byLogTime)

		// Print the logs.
		for _, log := range parsedLogs {
			if noColor {
				fmt.Fprintln(os.Stdout, log.message)
			} else {
				coloredContainer := goterm.Color(log.fromContainer, pickColor(log.fromContainer))
				fmt.Fprintf(os.Stdout, "%s › %s\n", coloredContainer, log.message)
			}
		}

		// Clear the buffer now that we've printed its contents.
		window = nil
	}

	for {
		select {
		case logLine, ok := <-rawLogs:
			if !ok {
				// There won't be any more messages, so we can exit after
				// flushing any unprinted logs.
				flush()
				return nil
			}

			// If it's an EOF error, still print the final contents of the buffer.
			// We don't need any special handling for ending the stream because
			// the log reader goroutine will just stop sending us messages.
			if logLine.readError != nil && logLine.readError != io.EOF {
				return errors.WithContext(fmt.Sprintf("read logs for %s", logLine.fromContainer), logLine.readError)
			}

			// Wake up later to flush the buffered lines.
			window = append(window, logLine)
			if flushTrigger == nil {
				flushTrigger = time.After(windowSize)
			}
		case <-flushTrigger:
			flush()
			flushTrigger = nil
		case <-ctx.Done():
			return nil
		}
	}
}

func parseLogLine(rawMessage string) (string, time.Time, error) {
	logParts := strings.SplitN(rawMessage, " ", 2)
	if len(logParts) != 2 {
		return "", time.Time{}, errors.New("malformed line")
	}

	rawTimestamp := logParts[0]
	timestamp, err := time.Parse(time.RFC3339Nano, rawTimestamp)
	if err != nil {
		// According to the Kubernetes docs, the timestamp might be in the
		// RFC3339 or RFC3339Nano format.
		timestamp, err = time.Parse(time.RFC3339, rawTimestamp)
		if err != nil {
			return "", time.Time{},
				errors.New("parse timestamp")
		}
	}

	message := logParts[1]
	return message, timestamp, nil
}

var colorList = []int{
	goterm.BLUE,
	goterm.CYAN,
	goterm.GREEN,
	goterm.MAGENTA,
	goterm.RED,
	goterm.YELLOW,
}

func pickColor(container string) int {
	hash := fnv.New32()
	hash.Write([]byte(container))
	idx := hash.Sum32() % uint32(len(colorList))
	return colorList[idx]
}
