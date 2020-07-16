package syncthing

import (
	"context"
	"time"

	"github.com/kelda/blimp/pkg/errors"
)

type progressPhase int

const (
	ProgressPending progressPhase = iota
	ProgressDone
	ProgressError
)

type progressStatus struct {
	phase progressPhase
	err   error
}

type progressFunction func() progressStatus

func waitUntil(ctx context.Context, maxRetries int, fn progressFunction) error {
	var retries int
	var err error
	for {
		switch status := fn(); status.phase {
		case ProgressDone:
			return nil
		case ProgressPending:
			retries = 0
			err = nil
		case ProgressError:
			retries++
			err = status.err
		}

		var canceled bool
		select {
		case <-ctx.Done():
			if err := ctx.Err(); err != context.Canceled && err != context.DeadlineExceeded {
				return err
			}
			canceled = true
		default:
		}

		if canceled || (maxRetries != 0 && retries >= maxRetries) {
			if err == nil {
				return errors.New("never completed")
			}
			return err
		}

		time.Sleep(1 * time.Second)
	}
}
