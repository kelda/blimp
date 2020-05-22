package syncthing

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/kelda-inc/blimp/pkg/errors"
	"github.com/kelda-inc/blimp/pkg/proto/node"
)

func runSyncCompletionServer(ctx context.Context, ncc node.ControllerClient, token string, syncedChan <-chan struct{}) {
	var hasSynced bool
	runServer := func() error {
		log.Debug("Starting sync status server")
		conn, err := ncc.SyncNotifications(ctx)
		if err != nil {
			return errors.WithContext("start stream", err)
		}
		defer conn.CloseSend()

		err = conn.Send(&node.SyncStatusResponse{
			Msg: &node.SyncStatusResponse_Token{
				Token: token,
			},
		})
		if err != nil {
			return errors.WithContext("send handshake", err)
		}

		recvChan := asyncRecv(conn)

		log.Debug("Connected to node controller")
		for {
			select {
			case <-syncedChan:
				hasSynced = true
			case err := <-recvChan:
				if err != nil {
					return errors.WithContext("receive", err)
				}
			}

			log.WithField("synced", hasSynced).Debug("Sending sync status")
			err = conn.Send(&node.SyncStatusResponse{
				Msg: &node.SyncStatusResponse_Synced{
					Synced: hasSynced,
				},
			})
			if err != nil {
				return errors.WithContext("send update", err)
			}
		}
	}

	for {
		err := runServer()
		// If the process exited because the context was cancelled, just exit.
		select {
		case <-ctx.Done():
			return
		default:
		}

		log.WithError(err).Warn("Sync notifier server crashed")
		time.Sleep(10 * time.Second)
	}
}

func asyncRecv(srv node.Controller_SyncNotificationsClient) <-chan error {
	recvChan := make(chan error, 8)
	go func() {
		for {
			_, err := srv.Recv()
			recvChan <- err
			if err != nil {
				return
			}
		}
	}()
	return recvChan
}
