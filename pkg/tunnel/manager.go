package tunnel

import (
	"fmt"
	"net"
	"strings"

	"github.com/kelda/blimp/pkg/errors"
	"github.com/kelda/blimp/pkg/proto/node"
)

type Manager struct {
	ncc   node.ControllerClient
	token string
}

func NewManager(ncc node.ControllerClient, token string) Manager {
	return Manager{ncc, token}
}

func (m Manager) Run(hostIP string, hostPort uint32, serviceName string, servicePort uint32) error {
	addr := fmt.Sprintf("%s:%d", hostIP, hostPort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		switch {
		case strings.Contains(err.Error(), "permission denied"):
			return errors.NewFriendlyError("Permission denied while listening for connections\n"+
				"Make sure that the local port for the service %q is above 1024.\n\n"+
				"The full error was:\n%s", serviceName, err)
		case strings.Contains(err.Error(), "address already in use"):
			return errors.NewFriendlyError("Another process is already listening on the same port\n"+
				"If you have been using docker-compose, make sure to run docker-compose down.\n"+
				"Make sure that the there aren't any other "+
				"services listening locally on port %d. This can be checked with the following command:\n"+
				"sudo lsof -i -P -n | grep :%d\n\n"+
				"The full error was:\n%s", hostPort, hostPort, err)
		}

		return errors.WithContext("listen locally", err)
	}

	return Client(m.ncc, ln, m.token, serviceName, servicePort)
}
