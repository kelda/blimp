package main

import (
	"io/ioutil"
	"os"
	"os/exec"

	"github.com/kelda-inc/blimp/pkg/syncthing"
)

func main() {
	folders := syncthing.ArgsToMap(os.Args[1:])

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

	cmd := exec.Command("/bin/syncthing", "-home", "/var/syncthing/config")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		panic(err)
	}
}
