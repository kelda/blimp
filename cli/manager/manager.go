package manager

import (
	"context"
	"fmt"
	"os"

	"google.golang.org/grpc"

	"github.com/kelda/blimp/cli/util"
	"github.com/kelda/blimp/pkg/errors"
	"github.com/kelda/blimp/pkg/proto/auth"
	"github.com/kelda/blimp/pkg/proto/cluster"
	"github.com/kelda/blimp/pkg/version"
)

var C Client

type Client struct {
	cluster.ManagerClient
	*grpc.ClientConn
}

func SetupClient(host, cert string) (err error) {
	hostname := "localhost" // Use default for host.
	envVal := os.Getenv("MANAGER_HOST")
	if envVal != "" {
		host = envVal
	}
	if host == "" || cert == "" {
		return errors.NewFriendlyError("Server host and certificate must be specified. Check your ~/.blimp/blimp.yaml")
	}
	C, err = dial(host, cert, hostname)
	return err
}

func dial(host, cert, hostname string) (Client, error) {
	// Since we are manually specifying the exact certificate to use, it should
	// be okay to override the server name. This simplifies self-hosted
	// deployments.
	conn, err := util.Dial(host, cert, hostname)
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

func CheckServiceStatus(svc string, auth *auth.BlimpAuth,
	predicate func(*cluster.ServiceStatus) bool) error {
	statusResp, err := C.GetStatus(context.Background(), &cluster.GetStatusRequest{
		Auth: auth,
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

func CheckServiceRunning(svc string, auth *auth.BlimpAuth) error {
	return CheckServiceStatus(svc, auth, func(svcStatus *cluster.ServiceStatus) bool {
		// If a service is unhealthy, we probably still want to be able to
		// interact with it, to figure out why it's unhealthy.
		return svcStatus.GetPhase() == cluster.ServicePhase_RUNNING ||
			svcStatus.GetPhase() == cluster.ServicePhase_UNHEALTHY
	})
}

// CheckServiceStarted checks that the service has started at some point. It may or may not be actively running.
func CheckServiceStarted(svc string, auth *auth.BlimpAuth) error {
	return CheckServiceStatus(svc, auth, func(svcStatus *cluster.ServiceStatus) bool {
		return svcStatus.GetHasStarted()
	})
}
