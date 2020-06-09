package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/cesanta/docker_auth/auth_server/api"
	log "github.com/sirupsen/logrus"

	"github.com/kelda/blimp/pkg/auth"
	"github.com/kelda/blimp/pkg/errors"
)

func init() {
	logPath := "/blimp-docker-auth.log"
	logFile, err := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err == nil {
		log.SetOutput(logFile)
	}
}

func main() {
	flag.Parse()
	args := flag.Args()
	if len(args) != 1 {
		log.Error("Expected either 'auth' or 'authz'")
		os.Exit(1)
	}

	stdin, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		log.WithError(err).Error("Failed to read from stdin")
		os.Exit(1)
	}

	switch args[0] {
	case "auth":
		err = authenticate(string(stdin))
	case "authz":
		err = authorize(string(stdin))
	default:
		log.WithField("mode", args[0]).Error("Unrecognized mode")
		os.Exit(1)
	}

	if err != nil {
		log.WithError(err).Error("Validation failed")
		os.Exit(1)
	}
	os.Exit(0)
}

// authenticate validates that the user is logging in with a valid identity
// token.
func authenticate(input string) error {
	credentials := strings.SplitN(input, " ", 2)
	if len(credentials) != 2 {
		return errors.New("malformed authentication input")
	}

	user, err := auth.ParseIDToken(credentials[1], auth.VerifierFromKeySet(
		diskCachedKeySet{
			localPath: "/blimp-jwks.json",
			remoteURL: auth.JWKSURL,
		}))
	if err != nil {
		return errors.WithContext("parse id token", err)
	}

	fmt.Printf(`{"labels": {"namespace": ["%s"]}}`, user.Namespace)
	return nil
}

// authorized validates that the user is attempting to interact with an image
// in their namespace.
func authorize(input string) error {
	var authReqInfo api.AuthRequestInfo
	err := json.Unmarshal([]byte(input), &authReqInfo)
	if err != nil {
		return errors.WithContext("parse input", err)
	}

	if len(authReqInfo.Labels["namespace"]) != 1 {
		return errors.New("missing namespace label")
	}

	namespace := authReqInfo.Labels["namespace"][0]
	if strings.HasPrefix(authReqInfo.Name, namespace+"/") {
		return nil
	}
	return errors.New("not within user's namespace")
}
