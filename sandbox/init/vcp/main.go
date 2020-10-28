package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
)

func main() {
	fmt.Println("Hello World! This is Volume CP!")
	for _, arg := range os.Args[2:] {
		argSplit := strings.Split(arg, ":")
		from, to := argSplit[0], argSplit[1]
		log.WithField("from", from).WithField("to", to).Info("Starting initialization")

		// Resolve symlinks before copying so that we don't end just copying
		// the symlink, which will make Kubernetes unable to mount the path as
		// a directory.
		// Instead, if it's a symlink, we should copy the contents of the
		// destination.
		var err error
		from, err = filepath.EvalSymlinks(from)
		if err != nil {
			if os.IsNotExist(err) {
				log.Info("Container image doesn't contain folder. Nothing to do.")
			}
			log.WithError(err).Warn("Failed to resolve symlinks (if any). Skipping")
			continue
		}

		fromInfo, err := os.Stat(from)
		switch {
		case err != nil:
			log.WithError(err).Error("Failed to stat image contents. Skipping.")
			continue
		case !fromInfo.IsDir():
			// Docker errors out in this case, but we just skip it to simplify
			// the error handling.
			log.Warn("Path in image isn't a directory. Skipping.")
			continue
		}

		toContents, err := ioutil.ReadDir(to)
		switch {
		case os.IsNotExist(err):
			// It's ok if the volume does not exist yet -- the copy will create
			// it.
		case err != nil:
			log.WithError(err).Error("Failed to stat volume contents. Skipping.")
			continue
		case len(toContents) != 0:
			log.Info("Volume not empty. Skipping.")
			continue
		}

		// Make sure the parent directories exist.
		if err := os.MkdirAll(filepath.Dir(to), 0755); err != nil {
			log.WithError(err).Error("Failed to make parent directories for target. Skipping.")
			continue
		}

		cmd := exec.Command(os.Args[1],
			// Copy recursively, and preserve permissions and symlinks.
			"-a",
			// Overwrite the existing directory. This way we don't copy
			// _into_ the directory if it already exists.
			"-T",
			from, to)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		fmt.Println(cmd)

		if err := cmd.Run(); err != nil {
			// XXX: We don't fail even if the copy fails so that the container
			// will continue to boot. It's currently not possible for users to
			// debug these initialization containers, so it's better for us to
			// proceed with the boot so that users can inspect the running
			// container, and Blimp doesn't feel stuck.
			// Eventually, we should propagate error messages back to the user.
			log.WithError(err).Error("Failed to initialize volume")
		}
	}
}
