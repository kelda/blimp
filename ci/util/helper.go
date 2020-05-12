package util

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/kelda-inc/blimp/pkg/errors"
)

// Start starts the given Blimp command. It returns a thread-safe reader for
// the stdout output, and a channel for obtaining any errors after starting the
// command, and any errors from starting the command.
func Start(ctx context.Context, args ...string) (io.Reader, chan error, error) {
	cmd := exec.Command("blimp", args...)

	stdoutReader, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}

	stderr := bytes.NewBuffer(nil)
	cmd.Stderr = stderr

	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}

	errChan := make(chan error)
	go func() {
		waitErr := make(chan error)
		go func() {
			waitErr <- cmd.Wait()
			close(waitErr)
		}()

		defer close(errChan)
		select {
		case <-ctx.Done():
			if err := cmd.Process.Signal(syscall.SIGINT); err != nil {
				errChan <- errors.WithContext("kill", err)
				return
			}
			<-waitErr
		case err := <-waitErr:
			errChan <- fmt.Errorf("crashed (%s): stderr: %s", err, stderr)
		}
	}()
	return stdoutReader, errChan, nil
}

// Run runs the given Blimp command, and returns its stdout.
func Run(ctx context.Context, command ...string) ([]byte, error) {
	return exec.CommandContext(ctx, "blimp", command...).Output()
}

// Up runs `blimp up` with the given arguments, and waits until the
// development environment is ready for use.
func Up(ctx context.Context, args ...string) (chan error, error) {
	log.Info("Starting blimp up")
	cmd := append([]string{"up"}, args...)
	stdout, cmdErr, startErr := Start(ctx, cmd...)
	if startErr != nil {
		return nil, errors.WithContext("start", startErr)
	}

	waitCtx, cancelWait := context.WithTimeout(ctx, 10*time.Minute)
	defer cancelWait()

	devEnvErr := make(chan error, 1)
	go func() {
		defer close(devEnvErr)
		log.Info("Waiting for development environment to boot")

		// The following text is printed by `blimp up` after the
		// containers are all booted.
		bootedText := []byte("All containers successfully started")
		stdoutBytes, err := waitForOutput(waitCtx, stdout, bootedText)
		if err != nil {
			devEnvErr <- errors.WithContext("wait for boot", err)
			return
		}

		unsupportedFeaturesText := []byte("WARNING: Docker Compose file uses features unsupported by Kelda Blimp")
		if bytes.Contains(stdoutBytes, unsupportedFeaturesText) {
			devEnvErr <- errors.New("Compose file uses unsupported features: %s", string(stdoutBytes))
			return
		}
	}()

	select {
	// If `blimp up` crashes.
	case err := <-cmdErr:
		return nil, errors.WithContext("blimp up crashed", err)

	// If we're done waiting for the development environment to be ready.
	case err := <-devEnvErr:
		// In a race between `cmdErr`, and `devEnvErr`, prefer `cmdErr`
		// (e.g. if the wait fails because `blimp up` crashed).
		select {
		// Give any crash errors time to propagate through the goroutines.
		// When `blimp up` crashes, its `stdout` gets closed immediately,
		// which causes an error in `devEnvErr` before we see the exit error in
		// `cmdErr`.
		case <-time.After(5 * time.Second):
		case err := <-cmdErr:
			return nil, errors.WithContext("blimp up crashed", err)
		}

		if err != nil {
			return nil, errors.WithContext("wait for ready", err)
		}
		return cmdErr, nil
	}
}

// waitForOutput blocks until `expOutput` is written to `reader`, or `ctx` has
// expired.
func waitForOutput(ctx context.Context, reader io.Reader, expOutput []byte) ([]byte, error) {
	actualOutput := bytes.NewBuffer(nil)
	streamReader := NewStreamReader(reader)
	for {
		select {
		case <-ctx.Done():
			return nil, errors.New("cancelled")
		case r := <-streamReader.Read(ctx):
			if r.Error != nil {
				return nil, errors.WithContext("read", r.Error)
			}
			if _, err := actualOutput.Write(r.Bytes); err != nil {
				return nil, errors.WithContext("copy", err)
			}

			if bytes.Contains(actualOutput.Bytes(), expOutput) {
				return actualOutput.Bytes(), nil
			}
		}
	}
}

func TestWithRetry(ctx context.Context, trigger chan struct{}, test func() bool) bool {
	maxSleepTime := 30 * time.Second
	sleepTime := 100 * time.Millisecond
	for {
		select {
		case <-ctx.Done():
			return test()
		case <-time.After(sleepTime):
			sleepTime *= 2
			if sleepTime > maxSleepTime {
				sleepTime = maxSleepTime
			}
		case <-trigger:
		}

		if test() {
			return true
		}
	}
}
