package syncthing

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"path"

	log "github.com/sirupsen/logrus"

	"github.com/kelda/blimp/pkg/cfgdir"
	"github.com/kelda/blimp/pkg/errors"
)

type APIClient struct {
	Address string
}

type Status struct {
	State string `json:"state"`
}

type Completion struct {
	NeedBytes   int `json:"needBytes"`
	NeedDeletes int `json:"needDeletes"`
	NeedItems   int `json:"needItems"`
}

type Connections struct {
	Connections map[string]Connection `json:"connections"`
}

type Connection struct {
	Connected bool `json:"connected"`
}

func (api APIClient) OverrideVersion(folder string) error {
	return api.post("/rest/db/override", map[string]string{"folder": folder})
}

func (api APIClient) Restart() error {
	return api.post("/rest/system/restart", nil)
}

func (api APIClient) Reset() error {
	return api.post("/rest/system/reset", nil)
}

func (api APIClient) GetStatus(folder string) (status Status, err error) {
	err = api.get("/rest/db/status", map[string]string{"folder": folder}, &status)
	return status, err
}

func (api APIClient) GetCompletion(folder, device string) (completion Completion, err error) {
	opts := map[string]string{
		"folder": folder,
		"device": device,
	}
	err = api.get("/rest/db/completion", opts, &completion)
	return completion, err
}

func (api APIClient) GetConnections() (conns Connections, err error) {
	err = api.get("/rest/system/connections", nil, &conns)
	return conns, err
}

func (api APIClient) Ping() error {
	return api.get("/rest/system/ping", nil, nil)
}

func (api APIClient) get(path string, params map[string]string, respObj interface{}) error {
	return api.do("GET", path, params, respObj)
}

func (api APIClient) post(path string, params map[string]string) error {
	return api.do("POST", path, params, nil)
}

func (api APIClient) do(method, p string, params map[string]string, respObj interface{}) error {
	req, err := http.NewRequest(method, fmt.Sprintf("http://%s", path.Join(api.Address, p)), nil)
	if err != nil {
		return errors.WithContext("create request", err)
	}

	q := req.URL.Query()
	for k, v := range params {
		q.Add(k, v)
	}
	req.URL.RawQuery = q.Encode()
	req.Header.Set("X-API-Key", apiKey)

	httpClient := &http.Client{}
	resp, err := httpClient.Do(req)
	if err != nil {
		return errors.WithContext(fmt.Sprintf("http %s", method), err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return errors.WithContext("read response", err)
	}

	if resp.StatusCode != http.StatusOK {
		return errors.New("bad status (%s): %s", resp.Status, string(body))
	}

	if respObj != nil {
		if err := json.Unmarshal(body, respObj); err != nil {
			return errors.WithContext(fmt.Sprintf("failed to decode (%s)", string(body)), err)
		}
	}
	return nil
}

func setLocalFolderType(ctx context.Context, c APIClient, t string, idPathMap map[string]string) error {
	config := makeConfig(false, idPathMap, t)
	err := ioutil.WriteFile(cfgdir.Expand("config.xml"), []byte(config), 0644)
	if err != nil {
		return errors.WithContext("write config", err)
	}

	// This should succeed on the first try since it's only connecting to the
	// Syncthing daemon on localhost, but we allow some retries just to be
	// safe.
	return waitUntil(ctx, 5, func() progressStatus {
		log.Debug("Restarting syncthing")

		err := c.Restart()
		if err == nil {
			return progressStatus{phase: PROGRESS_DONE}
		}
		return progressStatus{phase: PROGRESS_ERROR, err: err}
	})
}

func waitUntilConnected(ctx context.Context, localClient, remoteClient APIClient) error {
	isConnected := func() error {
		if err := localClient.Ping(); err != nil {
			return errors.WithContext("ping local syncthing", err)
		}

		if err := remoteClient.Ping(); err != nil {
			return errors.WithContext("ping remote syncthing", err)
		}

		connections, err := localClient.GetConnections()
		if err != nil {
			return errors.WithContext("get local connections", err)
		}

		remoteDevice, ok := connections.Connections[RemoteDeviceID]
		if !ok || !remoteDevice.Connected {
			return errors.New("remote device isn't connected")
		}

		return nil
	}

	return waitUntil(ctx, 0, func() progressStatus {
		log.Debug("Checking Syncthing connection status")

		connErr := isConnected()
		if connErr == nil {
			return progressStatus{phase: PROGRESS_DONE}
		}
		return progressStatus{phase: PROGRESS_ERROR, err: connErr}
	})
}

func resetDatabases(ctx context.Context, clients ...APIClient) error {
	return waitUntil(ctx, 10, func() progressStatus {
		log.Debug("Resetting Syncthing databases")

		for _, c := range clients {
			if err := c.Reset(); err != nil {
				log.WithError(err).Warn("Failed to reset database")
				return progressStatus{phase: PROGRESS_ERROR, err: err}
			}
		}

		return progressStatus{phase: PROGRESS_DONE}
	})
}

func waitUntilScanned(ctx context.Context, c APIClient, folders []string) error {
	hasScanned := func() (bool, error) {
		for _, folder := range folders {
			status, err := c.GetStatus(folder)
			if err != nil {
				return false, errors.WithContext("get status", err)
			}

			// When Syncthing first boots, it immediately queues a scan. So if
			// the status is something other than "scanning" or "scan-waiting",
			// then we know that the initial scan has completed.
			// This check doesn't account for subsequent scans, but Syncthing
			// is usually in the "idle" state unless there was a file change,
			// so this isn't a big performance issue. Even if we do some
			// unecessary checks, it'll probably just be a couple at most.
			if status.State == "scanning" || status.State == "scan-waiting" {
				return false, nil
			}
		}
		return true, nil
	}

	return waitUntil(ctx, 10, func() progressStatus {
		log.Debug("Waiting for Syncthing to finish initial scan")

		scanned, err := hasScanned()
		if err != nil {
			log.WithError(err).Warn("Failed to get syncthing scan status")
			return progressStatus{phase: PROGRESS_ERROR, err: err}
		}

		if scanned {
			return progressStatus{phase: PROGRESS_DONE}
		}
		return progressStatus{phase: PROGRESS_PENDING}
	})
}

func waitUntilSynced(ctx context.Context, local, remote APIClient, folders []string) error {
	isSynced := func() (bool, error) {
		for _, folder := range folders {
			// Make sure the remote is using our index.
			if err := local.OverrideVersion(folder); err != nil {
				return false, errors.WithContext("override version", err)
			}

			// Although the status RPC also returns NeedBytes, we use the
			// completion RPC instead because it compares the given device's
			// completion with the index on the local device. In other words,
			// we don't have to make sure that the versions from the
			// OverrideVersion call have propagated to the remote device before
			// checking for completion.
			completion, err := local.GetCompletion(folder, RemoteDeviceID)
			if err != nil {
				return false, errors.WithContext("get remote folder completion", err)
			}

			if completion.NeedBytes != 0 || completion.NeedDeletes != 0 || completion.NeedItems != 0 {
				return false, nil
			}
		}

		return true, nil
	}

	return waitUntil(ctx, 10, func() progressStatus {
		log.Debug("Waiting for remote Syncthing to sync local changes")

		synced, err := isSynced()
		if err != nil {
			log.WithError(err).Warn("Failed to check sync status")
			return progressStatus{phase: PROGRESS_ERROR, err: err}
		}

		if synced {
			return progressStatus{phase: PROGRESS_DONE}
		}
		return progressStatus{phase: PROGRESS_PENDING}
	})
}
