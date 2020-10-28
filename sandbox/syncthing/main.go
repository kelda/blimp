package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"sort"

	"github.com/kelda/blimp/pkg/hash"
	"github.com/kelda/blimp/pkg/syncthing"
)

func main() {
	folders := syncthing.ArgsToMap(os.Args[1:])

	err := syncthing.MakeMarkers(folders)
	if err != nil {
		panic(err)
	}

	if _, err := os.Stat("/pv/syncthing-config"); os.IsNotExist(err) {
		err := os.MkdirAll("/pv/syncthing-config", 0644)
		if err != nil {
			panic(err)
		}
	}


	homePath := fmt.Sprintf("/pv/syncthing-config/%s", configHash(folders))

	if _, err := os.Stat(homePath); os.IsNotExist(err) {
		// This homePath is new, so create it. Copy from /var/syncthing/config/
		// to get certs.
		cmd := exec.Command("cp", "-R", "/var/syncthing/config", homePath)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		fmt.Println(cmd)

		err := cmd.Run()
		if err != nil {
			panic(err)
		}

		configFile := syncthing.MakeServer(folders)
		configPath := filepath.Join(homePath, "config.xml")
		err = ioutil.WriteFile(configPath, []byte(configFile), 0655)
		if err != nil {
			panic(err)
		}
	}


	cmd := exec.Command("/bin/syncthing", "-verbose", "-home", homePath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		panic(err)
	}
}

func configHash(folders map[string]string) string {
	type kv struct{Key, Value string}
	slice := []kv{}
	for k, v := range folders {
		slice = append(slice, kv{k, v})
	}
	sort.Slice(slice, func(i, j int) bool {
		return slice[i].Key < slice[j].Key
	})

	jsonBytes, err := json.Marshal(slice)
	if err != nil {
		panic(err)
	}
	return hash.Bytes(jsonBytes)
}
