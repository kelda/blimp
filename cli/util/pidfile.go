package util

import (
	"io/ioutil"
	"os"
	"strconv"
	"syscall"

	log "github.com/sirupsen/logrus"

	"github.com/kelda-inc/blimp/pkg/cfgdir"
	"github.com/kelda-inc/blimp/pkg/errors"
)

func UpRunning() bool {
	pidBytes, err := ioutil.ReadFile(getPidfilePath())
	if err != nil {
		if !os.IsNotExist(err) {
			log.WithError(err).Warn("Unable to read pidfile")
		}
		return false
	}

	pid, err := strconv.Atoi(string(pidBytes))
	if err != nil {
		log.WithError(err).Warn("Corrupt pidfile.")
		return false
	}

	// FindProcess will return successfully even when the process doesn't exist.
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}

	// Sending signal 0 doesn't actually do anything, but it will fail if the
	// process does not exist.
	err = process.Signal(syscall.Signal(0))
	return err == nil
}

func TakeUpLock() error {
	pidBytes := []byte(strconv.Itoa(os.Getpid()))
	err := ioutil.WriteFile(getPidfilePath(), pidBytes, 0644)
	if err != nil {
		return errors.WithContext("write to pidfile", err)
	}
	return nil
}

func ReleaseUpLock() {
	err := os.Remove(getPidfilePath())
	if err != nil {
		log.WithError(err).Warn("Failed to remove pidfile.")
	}
}

func getPidfilePath() string {
	return cfgdir.Expand("up.pid")
}
