package util

import (
	"os"

	log "github.com/sirupsen/logrus"
)

var ManagerHost = getManagerHost()

func getManagerHost() string {
	envVal := os.Getenv("MANAGER_HOST")
	if envVal != "" {
		return envVal
	}
	return "blimp-manager.kelda.io:9000"
}

// HandleFatalError handles errors that are severe enough to terminate the
// program.
func HandleFatalError(msg string, err error) {
	if err != nil {
		log.WithError(err).Error(msg)
	} else {
		log.Error(msg)
	}
	os.Exit(1)
}
