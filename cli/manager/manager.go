package manager

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"

	"google.golang.org/grpc"

	"github.com/kelda/blimp/cli/util"
	"github.com/kelda/blimp/pkg/errors"
	"github.com/kelda/blimp/pkg/proto/cluster"
	"github.com/kelda/blimp/pkg/version"
)

// DefaultManagerHost can be overridden by `make`.
var DefaultManagerHost = "blimp-manager.kelda.io:443"

var (
	// ClusterManagerCertBase64 is the base64 encoded certificate for the
	// cluster manager. This is set at build time.
	ClusterManagerCertBase64 string

	// The PEM-encoded certificate for the cluster manager.
	clusterManagerCert = mustDecodeBase64(ClusterManagerCertBase64)
)

var C Client

var Host = getHost()

type Client struct {
	cluster.ManagerClient
	*grpc.ClientConn
}

func SetupClient() (err error) {
	C, err = dial()
	return err
}

func getHost() string {
	envVal := os.Getenv("MANAGER_HOST")
	if envVal != "" {
		return envVal
	}
	return DefaultManagerHost
}

func dial() (Client, error) {
	conn, err := util.Dial(Host, clusterManagerCert)
	if err != nil {
		return Client{}, errors.WithContext("dial", err)
	}

	client := Client{
		ManagerClient: cluster.NewManagerClient(conn),
		ClientConn:    conn,
	}

	resp, err := client.CheckVersion(context.Background(), &cluster.CheckVersionRequest{
		Version: version.Version,
	})
	if err != nil {
		return client, errors.WithContext("check version", err)
	}

	if resp.DisplayMessage != "" {
		fmt.Println(resp.DisplayMessage)
	}

	switch resp.Action {
	case cluster.CLIAction_OK:
	case cluster.CLIAction_EXIT:
		os.Exit(1)
	default:
		os.Exit(1)
	}

	return client, nil
}

func CheckServiceStatus(svc string, authToken string,
	predicate func(*cluster.ServiceStatus) bool) error {
	statusResp, err := C.GetStatus(context.Background(), &cluster.GetStatusRequest{
		Token: authToken,
	})
	if err != nil {
		return err
	}

	status := statusResp.GetStatus()
	if status.GetPhase() != cluster.SandboxStatus_RUNNING {
		return errors.NewFriendlyError(
			"Your sandbox is not booted. Please run `blimp up` first.")
	}

	for svcName, svcStatus := range status.GetServices() {
		if svcName == svc && predicate(svcStatus) {
			// We are booted!
			return nil
		}
	}

	// Either the service hasn't been created, or it isn't in the RUNNING phase.
	return errors.NewFriendlyError(
		"This service isn't booted. You can check its status with `blimp ps`.")
}

func CheckServiceRunning(svc string, authToken string) error {
	return CheckServiceStatus(svc, authToken, func(svcStatus *cluster.ServiceStatus) bool {
		// If a service is unhealthy, we probably still want to be able to
		// interact with it, to figure out why it's unhealthy.
		return svcStatus.GetPhase() == cluster.ServicePhase_RUNNING ||
			svcStatus.GetPhase() == cluster.ServicePhase_UNHEALTHY
	})
}

// CheckServiceStarted checks that the service has started at some point. It may or may not be actively running.
func CheckServiceStarted(svc string, authToken string) error {
	return CheckServiceStatus(svc, authToken, func(svcStatus *cluster.ServiceStatus) bool {
		return svcStatus.GetHasStarted()
	})
}

func mustDecodeBase64(encoded string) string {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		panic(err)
	}
	return string(decoded)
}
