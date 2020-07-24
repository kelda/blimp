package ps

import (
	"fmt"

	"github.com/buger/goterm"

	"github.com/kelda/blimp/pkg/proto/cluster"
	"github.com/kelda/blimp/pkg/syncthing"
)

func GetSandboxStatusString(sandboxStatus cluster.SandboxStatus_SandboxPhase) (msg string, color int) {
	switch sandboxStatus {
	case cluster.SandboxStatus_RUNNING:
		msg = "Running"
		color = goterm.GREEN
	case cluster.SandboxStatus_TERMINATING:
		msg = "Terminating"
		color = goterm.YELLOW
	case cluster.SandboxStatus_DOES_NOT_EXIST:
		msg = "Not found"
		color = goterm.RED
	default:
		msg = "Unknown"
		color = goterm.YELLOW
	}

	return msg, color
}

func GetStatusString(svcStatus *cluster.ServiceStatus) (msg string, color int, booted bool) {
	color = goterm.YELLOW
	msg = "Unknown"
	switch svcStatus.Phase {
	case cluster.ServicePhase_INITIALIZING_VOLUMES:
		msg = "Initializing volumes"
	case cluster.ServicePhase_WAIT_DEPENDS_ON:
		msg = "Waiting for dependencies to be ready"
	case cluster.ServicePhase_WAIT_SYNC_BIND:
		msg = fmt.Sprintf("Syncing volumes. See progress at http://localhost:%d", syncthing.APIPort)
	case cluster.ServicePhase_PENDING:
		msg = "Pending"
	case cluster.ServicePhase_UNHEALTHY:
		msg = "Unhealthy"
		color = goterm.YELLOW
	case cluster.ServicePhase_RUNNING:
		msg = "Running"
		color = goterm.GREEN
	case cluster.ServicePhase_EXITED:
		msg = "Exited"
		color = goterm.RED
	case cluster.ServicePhase_UNSCHEDULABLE:
		msg = "Unschedulable. You may need to run `blimp down` and recreate your sandbox."
		color = goterm.RED
	}

	if svcStatus.Msg != "" {
		msg += ": " + svcStatus.Msg
	}
	return msg, color, svcStatus.HasStarted
}
