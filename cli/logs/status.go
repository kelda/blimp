package logs

import (
	"context"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/kelda/blimp/cli/manager"
	"github.com/kelda/blimp/pkg/errors"
	"github.com/kelda/blimp/pkg/proto/auth"
	"github.com/kelda/blimp/pkg/proto/cluster"
)

// statusNotifier provides a way to notify watchers when a services exits or
// starts running, by creating channels that can be closed when the status
// updates.
type statusNotifier struct {
	lock        sync.Mutex
	phase       cluster.ServicePhase
	exitedChan  chan struct{}
	runningChan chan struct{}
}

// Exited returns a channel which will be closed when the service exits. Only
// the channel returned by the most recent invocation will be closed, so
// multiple calls should not be made in parallel.
func (p *statusNotifier) Exited() <-chan struct{} {
	exitedChan := make(chan struct{})

	p.lock.Lock()
	defer p.lock.Unlock()
	if phaseExited(p.phase) {
		close(exitedChan)
	} else {
		p.exitedChan = exitedChan
	}

	return exitedChan
}

// Running returns a channel which will be closed when the service begins
// running. Only the channel returned by the most recent invocation will be
// closed, so multiple calls should not be made in parallel.
func (p *statusNotifier) Running() <-chan struct{} {
	runningChan := make(chan struct{})

	p.lock.Lock()
	defer p.lock.Unlock()
	if phaseRunning(p.phase) {
		close(runningChan)
	} else {
		p.runningChan = runningChan
	}

	return runningChan
}

// UpdatePhase will update the known phase of the service and notify any current
// watchers.
func (p *statusNotifier) UpdatePhase(phase cluster.ServicePhase) {
	p.lock.Lock()
	defer p.lock.Unlock()

	if p.phase == phase {
		return
	}

	p.phase = phase

	switch {
	case phaseExited(phase):
		if p.exitedChan != nil {
			close(p.exitedChan)
			p.exitedChan = nil
		}

	case phaseRunning(phase):
		if p.runningChan != nil {
			close(p.runningChan)
			p.runningChan = nil
		}
	}
}

func phaseExited(phase cluster.ServicePhase) bool {
	return phase == cluster.ServicePhase_EXITED ||
		phase == cluster.ServicePhase_UNKNOWN
}

func phaseRunning(phase cluster.ServicePhase) bool {
	return phase == cluster.ServicePhase_RUNNING
}

func (cmd *Command) startStatusUpdater(ctx context.Context) error {
	cmd.svcStatus = map[string]*statusNotifier{}

	// Fetch initial statuses.
	fetchCtx, _ := context.WithTimeout(ctx, 15*time.Second)
	initStatus, err := manager.C.GetStatus(fetchCtx, &cluster.GetStatusRequest{
		Auth: cmd.Config.BlimpAuth(),
	})
	if err != nil {
		return errors.WithContext("logs fetch initial statuses", err)
	}
	for _, svc := range cmd.Services {
		cmd.svcStatus[svc] = &statusNotifier{}
		status, ok := initStatus.Status.Services[svc]
		if ok {
			cmd.svcStatus[svc].UpdatePhase(status.Phase)
		} else {
			cmd.svcStatus[svc].UpdatePhase(cluster.ServicePhase_UNKNOWN)
		}
	}

	go func() {
		for {
			err := watchStatus(ctx, cmd.svcStatus, cmd.Config.BlimpAuth())

			switch {
			case err == nil:
				// This means that we are actually done. We shouldn't retry.
				log.Debug("Logs status watcher terminating")
				return
			case err == context.Canceled || status.Code(err) == codes.Canceled:
				select {
				case <-ctx.Done():
					return
				default:
					log.WithError(err).Debug("Unexpected stream termination")
				}
			default:
				log.WithError(err).Debug("Failed to read status stream")
			}

			// Wait 5s and try to reconnect.
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
		}
	}()
	return nil
}

func watchStatus(ctx context.Context, statuses map[string]*statusNotifier, auth *auth.BlimpAuth) error {
	stream, err := manager.C.WatchStatus(ctx, &cluster.GetStatusRequest{
		Auth: auth,
	})
	if err != nil {
		return errors.WithContext("watch status", err)
	}

	for {
		msg, err := stream.Recv()
		if err != nil {
			return errors.WithContext("status stream recv", err)
		}

		if msg.Status.Phase != cluster.SandboxStatus_RUNNING {
			// Assume all pods are exiting.
			for _, notifier := range statuses {
				notifier.UpdatePhase(cluster.ServicePhase_EXITED)
			}
			return nil
		}

		for svc := range statuses {
			status, ok := msg.Status.Services[svc]
			if ok {
				statuses[svc].UpdatePhase(status.Phase)
			} else {
				statuses[svc].UpdatePhase(cluster.ServicePhase_EXITED)
			}
		}
	}
}
