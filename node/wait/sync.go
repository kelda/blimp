package wait

import (
	"context"
	"fmt"
	"sync"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/kelda/blimp/pkg/errors"
	"github.com/kelda/blimp/pkg/proto/node"
)

// SyncTracker tracks connections to CLIs that can be queried to get the sync
// status.
type SyncTracker struct {
	// conns maps namespaces to the stream connected to its CLI.
	// Reads and writes are protected by `lock`.
	conns map[string]*cliConn
	lock  sync.Mutex
}

// cliConn is a connection to the CLI. It provides an interface for waiters to
// block until the CLI reports that its volumes are synced.
type cliConn struct {
	// `srv` is the stream connected to the CLI. `Send` calls are protected by
	// `sendLock` to prevent concurrent sends.
	srv      node.Controller_SyncNotificationsServer
	sendLock sync.Mutex

	// `shutdown` is used to signal to `cliConn.Run` that the stream should
	// exit.
	shutdown chan error

	// `waiters` is the set of waiters that should be notified when the sync
	// completes. It's protected by `waitersLock`.
	waiters     map[int]syncWaiter
	waitersLock sync.Mutex

	// `idCtr` is used for generating unique IDs for the `waiters` map.  It's
	// protected by `idLock`.
	idCtr  int
	idLock sync.Mutex
}

type syncWaiter struct {
	// `result` sends a message when the sync has completed, or there is
	// unrecoverable error that terminates the wait.
	result chan error
}

func NewSyncTracker() *SyncTracker {
	return &SyncTracker{conns: map[string]*cliConn{}}
}

func (st *SyncTracker) RunServer(namespace string, srv node.Controller_SyncNotificationsServer) error {
	log.WithField("namespace", namespace).Info("Connected to CLI")

	st.lock.Lock()
	if oldCm, ok := st.conns[namespace]; ok {
		oldCm.Shutdown(errors.New("new connection supersedes stale stream"))
	}

	cc := newClientConn(srv)
	st.conns[namespace] = cc
	st.lock.Unlock()

	err := cc.Run()

	// We're closing the connection, so don't let any more waiters use it.
	// Note that there's a short period of time where `cc.Run` has exited, but
	// the client connection is still available in `st.conns`. This is fine,
	// since `cc.NewWaiter` doesn't assume that `cc.Run` is running. If
	// `cc.NewWaiter` is called in this situation, it'll immediately return
	// with an error when the GetSyncStatusRequest message fails to send.
	st.lock.Lock()
	delete(st.conns, namespace)
	st.lock.Unlock()

	log.WithError(err).
		WithField("namespace", namespace).
		Info("Lost connection to CLI")

	return err
}

// WaitFor creates a waiter function that blocks until the initial sync is
// completed for the given namespace.
func (st *SyncTracker) WaitFor(namespace string) Waiter {
	return func(ctx context.Context, updates chan<- string) error {
		log.WithField("namespace", namespace).Info("Started waiting for bind volumes to sync")

		waiter, err := st.newWaiter(ctx, namespace)
		if err != nil {
			return err
		}

		select {
		case err := <-waiter:
			var status string
			if err == nil {
				status = fmt.Sprintf("%s's bind volumes are synced", namespace)
			} else {
				status = fmt.Sprintf("unexpected error waiting for %s's volumes to sync: %s",
					namespace, err)
			}

			select {
			case updates <- status:
			default:
				log.WithField("status", status).Info("Updates channel is full, dropping.")
			}
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (st *SyncTracker) newWaiter(ctx context.Context, namespace string) (chan error, error) {
	st.lock.Lock()
	cc, ok := st.conns[namespace]
	st.lock.Unlock()

	if !ok {
		return nil, errors.New("no connection to CLI")
	}

	return cc.NewWaiter(ctx)
}

func newClientConn(srv node.Controller_SyncNotificationsServer) *cliConn {
	return &cliConn{
		srv:      srv,
		shutdown: make(chan error, 1),
		waiters:  map[int]syncWaiter{},
	}
}

func (cc *cliConn) Run() error {
	defer func() {
		cc.waitersLock.Lock()
		defer cc.waitersLock.Unlock()

		// Close all dangling waiters since they'll never get further updates now
		// that this connection is closed.
		for _, w := range cc.waiters {
			select {
			case w.result <- errors.New("connection is shutting down"):
			default:
			}
		}
	}()

	recvChan := asyncRecv(cc.srv)
	for {
		select {
		case recvResult := <-recvChan:
			if recvResult.err != nil {
				// The client gracefully closed the stream, most likely
				// because the user Ctrl-C'd.
				if status.Code(recvResult.err) == codes.Canceled {
					return nil
				}
				return errors.WithContext("receive", recvResult.err)
			}

			resp := recvResult.msg
			if !resp.GetSynced() {
				break
			}

			// Notify all the waiters.
			cc.waitersLock.Lock()
			for id, waiter := range cc.waiters {
				close(waiter.result)
				delete(cc.waiters, id)
			}
			cc.waitersLock.Unlock()

		case err := <-cc.shutdown:
			return errors.WithContext("shutting down stream", err)
		}
	}
}

func (cc *cliConn) NewWaiter(ctx context.Context) (chan error, error) {
	w := syncWaiter{make(chan error, 1)}

	// Get an ID to identify the waiter in `cc.waiters`. This is used to remove
	// the waiter if it's cancelled.
	cc.idLock.Lock()
	cc.idCtr++
	id := cc.idCtr
	cc.idLock.Unlock()

	cc.waitersLock.Lock()
	cc.waiters[id] = w
	cc.waitersLock.Unlock()

	go func() {
		<-ctx.Done()
		cc.waitersLock.Lock()
		delete(cc.waiters, id)
		cc.waitersLock.Unlock()
	}()

	cc.sendLock.Lock()
	defer cc.sendLock.Unlock()
	if err := cc.srv.Send(&node.GetSyncStatusRequest{}); err != nil {
		err = errors.WithContext("send poll request to CLI", err)

		// The connection is unstable, probably because the CLI disconnected.
		// Shutdown the entire stream -- it will get recreated by the CLI if
		// the CLI is still alive.
		cc.Shutdown(err)
		return nil, err
	}
	return w.result, nil
}

func (cc *cliConn) Shutdown(err error) {
	select {
	case cc.shutdown <- err:
	default:
	}
}

type recvResult struct {
	msg *node.SyncStatusResponse
	err error
}

// asyncRecv forwards messages from `srv` until it encounters an error.
func asyncRecv(srv node.Controller_SyncNotificationsServer) chan recvResult {
	recvChan := make(chan recvResult, 8)
	go func() {
		for {
			msg, err := srv.Recv()
			recvChan <- recvResult{msg, err}
			if err != nil {
				return
			}
		}
	}()
	return recvChan
}
