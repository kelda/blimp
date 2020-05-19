package main

import (
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"

	log "github.com/sirupsen/logrus"

	"github.com/kelda-inc/blimp/pkg/errors"
	"github.com/kelda-inc/blimp/pkg/syncthing"
)

func main() {
	folders := syncthing.ArgsToMap(os.Args[1:])

	// Reset the bind volume so that we don't sync stale files back to the user.
	// The volume should already be empty because of the volume finalizer that
	// gets run when a namespace is deleted, but we check again here just in
	// case.
	if err := clearDir("/bind"); err != nil {
		log.WithError(err).Fatal("Failed to clear path")
	}

	err := syncthing.MakeMarkers(folders)
	if err != nil {
		panic(err)
	}

	configFile := syncthing.MakeServer(folders)
	configPath := "/var/syncthing/config/config.xml"
	err = ioutil.WriteFile(configPath, []byte(configFile), 0655)
	if err != nil {
		panic(err)
	}

	cmd := exec.Command("/bin/syncthing", "-verbose", "-home", "/var/syncthing/config")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		panic(err)
	}
}

func clearDir(dir string) error {
	paths, err := ioutil.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return errors.WithContext("read dir", err)
	}

	for _, path := range paths {
		if err := os.RemoveAll(filepath.Join(dir, path.Name())); err != nil {
			return errors.WithContext("remove", err)
		}
	}
	return nil
}
