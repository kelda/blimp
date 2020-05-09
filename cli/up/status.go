package up

import (
	"context"
	"errors"
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

	"github.com/kelda-inc/blimp/cli/manager"
	"github.com/kelda-inc/blimp/cli/ps"
	"github.com/kelda-inc/blimp/pkg/proto/cluster"
)

type statusPrinter struct {
	services []string

	currStatus map[string]*cluster.ServiceStatus
	sync.Mutex

	prevLinesPrinted int
	spinnerIdx       int
}

var spinnerChars = []string{"/", "-", "\\", "|"}

func newStatusPrinter(services []string) *statusPrinter {
	sp := &statusPrinter{services: services}
	sort.Strings(sp.services)
	return sp
}

func (sp *statusPrinter) Run(clusterManager manager.Client, authToken string) {
	// Stop watching the status after we're done printing the status.
	ctx, cancelFn := context.WithCancel(context.Background())
	defer cancelFn()

	go sp.syncStatus(ctx, clusterManager, authToken)

	for {
		if sp.printStatus() {
			break
		}
		time.Sleep(1 * time.Second)
	}
	fmt.Println(goterm.Color("All containers successfully started", goterm.GREEN))
}

func (sp *statusPrinter) syncStatus(ctx context.Context,
	clusterManager manager.Client, authToken string) {
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
				return fmt.Errorf("read stream: %w", err)
			}

			sp.Lock()
			sp.currStatus = msg.Status.Services
			sp.Unlock()
		}
	}

	for {
		statusStream, err := clusterManager.WatchStatus(ctx, &cluster.GetStatusRequest{
			Token: authToken,
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

func (sp *statusPrinter) printStatus() bool {
	// Reset the cursor so that we'll write over the previous status update.
	// TODO: Doesn't properly work if the previous print spanned multiple lines.
	for i := 0; i < sp.prevLinesPrinted; i++ {
		goterm.MoveCursorUp(1)
		goterm.Flush()
		fmt.Printf(goterm.ResetLine(""))
	}

	sp.spinnerIdx = (sp.spinnerIdx + 1) % len(spinnerChars)
	spinner := spinnerChars[sp.spinnerIdx]

	allReady := true
	out := tabwriter.NewWriter(os.Stdout, 0, 10, 5, ' ', 0)
	defer out.Flush()
	for _, svc := range sp.services {
		statusStr, color, done := sp.getServiceStatus(svc)
		if !done {
			statusStr += " " + spinner
			allReady = false
		}

		fmt.Fprintf(out, "%s\t%s\n", svc, goterm.Color(statusStr, color))
	}

	sp.prevLinesPrinted = len(sp.services)
	return allReady
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
