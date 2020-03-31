package util

import (
	"fmt"
	"io"
	"time"

	"github.com/buger/goterm"
)

// ProgressPrinter prints to the output every 2 seconds so that the user knows
// the application isn't stalled.
type ProgressPrinter struct {
	out     io.Writer
	msg     string
	stop    chan struct{}
	stopped chan struct{}
}

// NewProgressPrinter creates a new ProgressPrinter.
func NewProgressPrinter(out io.Writer, msg string) ProgressPrinter {
	return ProgressPrinter{out, msg, make(chan struct{}), make(chan struct{})}
}

var spinnerChars = []string{"/", "-", "\\", "|"}

// Run starts printing to the output.
func (pp ProgressPrinter) Run() {
	defer close(pp.stopped)
	poll := time.NewTicker(1 * time.Second)
	defer poll.Stop()

	time := 0
	// Print an extra space for the spinner character to go.
	fmt.Fprintf(pp.out, pp.msg+"  ")
	for {
		select {
		case <-pp.stop:
			return
		case <-poll.C:
			time++
			goterm.MoveCursorBackward(1)
			goterm.Flush()
			fmt.Fprintf(pp.out, spinnerChars[time%len(spinnerChars)])
		}
	}
}

// Stop stops printing to the output. After it returns, ProgressPrinter won't
// print anything more.
func (pp ProgressPrinter) Stop() {
	close(pp.stop)
	<-pp.stopped
	goterm.MoveCursorBackward(1)
	goterm.Flush()
	fmt.Fprint(pp.out, " \n")
}
