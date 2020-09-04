package version

import "os"

var (
	Version = ""

	CLIImage            = ""
	DNSImage            = ""
	InitImage           = ""
	ReservationImage    = ""
	SyncthingImage      = ""
	NodeControllerImage = ""

	BuildkitdImage = "moby/buildkit:master-rootless"
)

func init() {
	repo, ok := os.LookupEnv("BLIMP_DOCKER_REPO")
	if !ok || repo == "" {
		return
	}

	CLIImage = repo + "/blimp:" + Version
	DNSImage = repo + "/blimp-dns:" + Version
	InitImage = repo + "/blimp-init:" + Version
	ReservationImage = repo + "/sandbox-reservation:" + Version
	SyncthingImage = repo + "/sandbox-syncthing:" + Version
	NodeControllerImage = repo + "/blimp-node-controller:" + Version
}
