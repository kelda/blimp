package main

import (
	"crypto/ed25519"
	"fmt"
	"io/ioutil"
	"os"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Printf("Usage: %s PRIVATE_KEY_FILE PUBLIC_KEY_FILE\n", os.Args[0])
		os.Exit(1)
	}

	pubkey, privkey, err := ed25519.GenerateKey(nil)
	if err != nil {
		fmt.Printf("error while generating key: %v\n", err)
		os.Exit(1)
	}

	err = ioutil.WriteFile(os.Args[1], privkey, 0400)
	if err != nil {
		fmt.Printf("error while writing private key: %v\n", err)
		os.Exit(1)
	}

	err = ioutil.WriteFile(os.Args[2], pubkey, 0666)
	if err != nil {
		fmt.Printf("error while writing public key: %v\n", err)
		os.Exit(1)
	}
}
