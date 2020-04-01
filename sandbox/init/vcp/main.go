package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func main() {
	fmt.Println("Hello World! This is Volume CP!")
	for _, arg := range os.Args[2:] {
		argSplit := strings.Split(arg, ":")

		from, to := argSplit[0], argSplit[1]

		cmd := exec.Command(os.Args[1], "-r", from, to)

		fmt.Println(cmd)

		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		err := cmd.Run()
		if err != nil {
			fmt.Printf("%s", err)
		}
	}
}
