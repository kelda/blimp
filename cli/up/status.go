package up

import (
	"context"
	"fmt"
	"os"
	"sort"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/buger/goterm"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/kelda/blimp/cli/manager"
	"github.com/kelda/blimp/cli/ps"
	"github.com/kelda/blimp/pkg/errors"
	"github.com/kelda/blimp/pkg/proto/auth"
	"github.com/kelda/blimp/pkg/proto/cluster"
)

type statusPrinter struct {
	services      []string
	disableOutput bool

	currStatus map[string]*cluster.ServiceStatus
	sync.Mutex

	prevLinesPrinted int
	spinnerIdx       int
}

var spinnerChars = []string{"/", "-", "\\", "|"}

func newStatusPrinter(services []string, disableOutput bool) *statusPrinter {
	sp := &statusPrinter{services: services, disableOutput: disableOutput}
	sort.Strings(sp.services)
	return sp
}

func (sp *statusPrinter) Run(ctx context.Context,
	clusterManager manager.Client, auth *auth.BlimpAuth) bool {
	// Stop watching the status after we're done printing the status.
	syncCtx, cancelFn := context.WithCancel(ctx)
	defer cancelFn()

	go sp.syncStatus(syncCtx, clusterManager, auth)

	for {
		if !sp.disableOutput {
			sp.printStatus()
		}

		// Exit if all the services have finished booting.
		allReady := true
		for _, svc := range sp.services {
			_, _, done := sp.getServiceStatus(svc)
			if !done {
				allReady = false
				break
			}
		}

		if allReady {
			fmt.Println(goterm.Color("All containers successfully started", goterm.GREEN))
			return true
		}

		select {
		case <-ctx.Done():
			return false
		case <-time.After(1 * time.Second):
			// Continue.
		}
	}
	panic("unreached")
}

func (sp *statusPrinter) syncStatus(ctx context.Context,
	clusterManager manager.Client, auth *auth.BlimpAuth) {
	syncStream := func(stream cluster.Manager_WatchStatusClient) error {
		for {
			msg, err := stream.Recv()
			switch {
			case status.Code(err) == codes.Canceled:
				select {
				case <-ctx.Done():
					return nil
				default:
					return errors.New("unexpected stream termination")
				}
			case err != nil:
				return errors.WithContext("read stream", err)
			}

			sp.Lock()
			sp.currStatus = msg.Status.Services
			sp.Unlock()
		}
	}

	for {
		statusStream, err := clusterManager.WatchStatus(ctx, &cluster.GetStatusRequest{
			Auth: auth,
		})
		if err != nil {
			log.WithError(err).Warn("Failed to start status watch")
			time.Sleep(5 * time.Second)
			continue
		}

		if err := syncStream(statusStream); err == nil {
			return
		}

		log.WithError(err).Warn("Failed to read status stream")
		time.Sleep(5 * time.Second)
	}
}

func (sp *statusPrinter) printStatus() {
	// Reset the cursor so that we'll write over the previous status update.
	// TODO: Doesn't properly work if the previous print spanned multiple lines.
	for i := 0; i < sp.prevLinesPrinted; i++ {
		goterm.MoveCursorUp(1)
		goterm.Flush()
		fmt.Printf(goterm.ResetLine(""))
	}

	sp.spinnerIdx = (sp.spinnerIdx + 1) % len(spinnerChars)
	spinner := spinnerChars[sp.spinnerIdx]

	out := tabwriter.NewWriter(os.Stdout, 0, 10, 5, ' ', 0)
	defer out.Flush()
	for _, svc := range sp.services {
		statusStr, color, done := sp.getServiceStatus(svc)
		if !done {
			statusStr += " " + spinner
		}

		fmt.Fprintf(out, "%s\t%s\n", svc, goterm.Color(statusStr, color))
	}

	sp.prevLinesPrinted = len(sp.services)
}

func (sp *statusPrinter) getServiceStatus(svc string) (msg string, color int, booted bool) {
	sp.Lock()
	defer sp.Unlock()

	svcStatus, ok := sp.currStatus[svc]
	if !ok {
		return "Pending", goterm.YELLOW, false
	}

	return ps.GetStatusString(svcStatus)
}
