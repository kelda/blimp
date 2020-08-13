package version

import "os"

var (
	Version             = ""
	NodeControllerImage = ""
	InitImage           = ""
	ReservationImage    = ""
	SyncthingImage      = ""
	DNSImage            = ""
)

func init() {
	repo, ok := os.LookupEnv("BLIMP_DOCKER_REPO")
	if !ok || repo == "" {
		return
	}

	NodeControllerImage = repo + "/blimp-node-controller:" + Version
	InitImage = repo + "/blimp-init:" + Version
	ReservationImage = repo + "/sandbox-reservation:" + Version
	SyncthingImage = repo + "/sandbox-syncthing:" + Version
	DNSImage = repo + "/blimp-dns:" + Version
}
