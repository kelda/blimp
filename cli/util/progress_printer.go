package util

import (
	"fmt"
	"io"
	"time"
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

// Run starts printing to the output.
func (pp ProgressPrinter) Run() {
	defer close(pp.stopped)
	poll := time.NewTicker(1 * time.Second)
	defer poll.Stop()

	fmt.Fprintf(pp.out, pp.msg)
	for {
		select {
		case <-pp.stop:
			return
		case <-poll.C:
			fmt.Fprintf(pp.out, ".")
		}
	}
}

// Stop stops printing to the output. After it returns, ProgressPrinter won't
// print anything more.
func (pp ProgressPrinter) Stop() {
	pp.StopWithPrint("\n")
}

// StopWithPrint stops the progress printer and prints the supplied
// message to the output.
func (pp ProgressPrinter) StopWithPrint(toPrint string) {
	close(pp.stop)
	<-pp.stopped
	fmt.Fprint(pp.out, toPrint)
}
