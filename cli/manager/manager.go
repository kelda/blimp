package manager

import (
	"context"
	"fmt"
	"os"

	"google.golang.org/grpc"

	"github.com/kelda-inc/blimp/cli/util"
	"github.com/kelda-inc/blimp/pkg/auth"
	"github.com/kelda-inc/blimp/pkg/errors"
	"github.com/kelda-inc/blimp/pkg/proto/cluster"
	"github.com/kelda-inc/blimp/pkg/version"
)

// Can be overriden by `make`.
var DefaultManagerHost = "blimp-manager.kelda.io:443"

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
	conn, err := util.Dial(Host, auth.ClusterManagerCert)
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
