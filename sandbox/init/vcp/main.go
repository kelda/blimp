package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	log "github.com/sirupsen/logrus"
)

func main() {
	fmt.Println("Hello World! This is Volume CP!")
	for _, arg := range os.Args[2:] {
		argSplit := strings.Split(arg, ":")
		from, to := argSplit[0], argSplit[1]

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
