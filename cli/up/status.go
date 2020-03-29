package up

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/buger/goterm"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/kelda-inc/blimp/pkg/proto/cluster"
)

type statusPrinter struct {
	services []string
	tracker  map[string]*tracker

	currStatus map[string]*cluster.ServiceStatus
	sync.Mutex

	prevLinesPrinted int
}

type tracker struct {
	phase string
	timer int
}

func newStatusPrinter(services []string) *statusPrinter {
	sp := &statusPrinter{tracker: map[string]*tracker{}, services: services}
	sort.Strings(sp.services)

	for _, svc := range services {
		sp.tracker[svc] = &tracker{phase: "Pending"}
	}

	return sp
}

func (sp *statusPrinter) Run(clusterManager managerClient, authToken string) {
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

func (sp *statusPrinter) syncStatus(ctx context.Context, clusterManager managerClient, authToken string) {
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

const donePhase = "Running"

func (sp *statusPrinter) printStatus() bool {
	// Increment the timers on all the statuses.
	for _, tr := range sp.tracker {
		tr.timer++
	}

	// If the state transitioned for any of the services, update its phase, and
	// reset its clock.
	sp.Lock()
	for svc, status := range sp.currStatus {
		tr, ok := sp.tracker[svc]
		if !ok {
			// Ignore services not declared in the Docker Compose file.
			continue
		}

		if tr.phase != status.Phase {
			sp.tracker[svc] = &tracker{phase: status.Phase}
		}
	}
	sp.Unlock()

	// Reset the cursor so that we'll write over the previous status update.
	// TODO: Doesn't properly work if the previous print spanned multiple lines.
	for i := 0; i < sp.prevLinesPrinted; i++ {
		goterm.MoveCursorUp(1)
		goterm.Flush()
		fmt.Printf(goterm.ResetLine(""))
	}

	allReady := true
	out := tabwriter.NewWriter(os.Stdout, 0, 10, 5, ' ', 0)
	defer out.Flush()
	for _, svc := range sp.services {
		tr := sp.tracker[svc]
		var phaseStr string
		if tr.phase != donePhase {
			allReady = false
			ndots := tr.timer + 2
			phaseStr = goterm.Color(tr.phase+strings.Repeat(".", ndots), goterm.YELLOW)
		} else {
			phaseStr = goterm.Color(tr.phase, goterm.GREEN)
		}

		fmt.Fprintf(out, "%s\t%s\n", svc, phaseStr)
	}

	sp.prevLinesPrinted = len(sp.services)
	return allReady
}
