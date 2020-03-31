package manager

import (
	"context"
	"fmt"
	"os"

	"github.com/kelda-inc/blimp/cli/util"
	"github.com/kelda-inc/blimp/pkg/auth"
	"github.com/kelda-inc/blimp/pkg/proto/cluster"
	"github.com/kelda-inc/blimp/pkg/version"
	"google.golang.org/grpc"
)

var Host = getHost()

type Client struct {
	cluster.ManagerClient
	*grpc.ClientConn
}

func getHost() string {
	envVal := os.Getenv("MANAGER_HOST")
	if envVal != "" {
		return envVal
	}
	return "blimp-manager.kelda.io:443"
}

func Dial() (Client, error) {
	conn, err := util.Dial(Host, auth.ClusterManagerCert)
	if err != nil {
		return Client{}, err
	}

	client := Client{
		ManagerClient: cluster.NewManagerClient(conn),
		ClientConn:    conn,
	}

	resp, err := client.CheckVersion(context.Background(), &cluster.CheckVersionRequest{
		Version: version.Version,
	})
	if err != nil {
		return client, err
	}

	if resp.DisplayMessage != "" {
		fmt.Println(resp.DisplayMessage)
	}

	switch resp.Action {
	case cluster.CLIAction_OK:
	case cluster.CLIAction_EXIT:
		os.Exit(0)
	default:
		os.Exit(0)
	}

	return client, nil
}
