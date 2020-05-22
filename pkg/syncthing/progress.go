package syncthing

import (
	"context"
	"time"

	"github.com/kelda-inc/blimp/pkg/errors"
)

type progressPhase int

const (
	PROGRESS_PENDING progressPhase = iota
	PROGRESS_DONE
	PROGRESS_ERROR
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
		case PROGRESS_DONE:
			return nil
		case PROGRESS_PENDING:
			retries = 0
			err = nil
		case PROGRESS_ERROR:
			retries++
			err = status.err
		}

		var canceled bool
		select {
		case <-ctx.Done():
			if err := ctx.Err(); err != context.Canceled {
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
