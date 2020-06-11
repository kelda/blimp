package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/kelda-inc/blimp/pkg/analytics"
)

func main() {
	analytics.Init(analytics.StreamID{
		Source:    "vcp",
		Namespace: os.Getenv("NAMESPACE"),
	})

	fmt.Println("Hello World! This is Volume CP!")
	for _, arg := range os.Args[2:] {
		argSplit := strings.Split(arg, ":")
		from, to := argSplit[0], argSplit[1]
		log.WithField("from", from).WithField("to", to).Info("Starting initialization")

		fromInfo, err := os.Stat(from)
		switch {
		case os.IsNotExist(err):
			log.Info("Container image doesn't contain folder. Nothing to do.")
			continue
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
		// It's ok if the volume does not exist yet -- the copy will create it.
		case os.IsNotExist(err):
			toContents = nil
		case err != nil:
			log.WithError(err).Error("Failed to stat volume contents. Skipping.")
			continue
		case len(toContents) != 0:
			log.Info("Volume not empty. Skipping.")
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
