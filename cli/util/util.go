package util

import (
	"os"

	log "github.com/sirupsen/logrus"
)

const ManagerHost = "localhost:9000"

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
