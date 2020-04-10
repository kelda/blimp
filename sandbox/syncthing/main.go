package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"

	log "github.com/sirupsen/logrus"

	"github.com/kelda-inc/blimp/pkg/syncthing"
)

func main() {
	folders := syncthing.ArgsToMap(os.Args[1:])

	// Reset the bind volume so that we don't sync stale files back to the user.
	for _, path := range folders {
		if err := clearDir(path); err != nil {
			log.WithError(err).WithField("path", path).Fatal("Failed to clear path")
		}
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
		return fmt.Errorf("read dir: %w", err)
	}

	for _, path := range paths {
		if err := os.RemoveAll(filepath.Join(dir, path.Name())); err != nil {
			return fmt.Errorf("remove: %w", err)
		}
	}
	return nil
}
