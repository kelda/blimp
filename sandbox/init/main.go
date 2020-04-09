package main

import (
	"context"
	"io/ioutil"
	"os"
	"time"

	"github.com/golang/protobuf/proto"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/encoding/gzip"

	"github.com/kelda-inc/blimp/pkg/proto/sandbox"
)

func main() {
	sandboxManagerHost := os.Getenv("SANDBOX_MANAGER_HOST")
	if sandboxManagerHost == "" {
		log.Fatal("SANDBOX_MANAGER_HOST environment variable is required")
	}

	waitSpecRaw, err := ioutil.ReadFile("/etc/blimp/wait-spec")
	if err != nil {
		log.WithError(err).Fatal("Failed to read wait spec")
	}

	var waitSpec sandbox.WaitSpec
	if err := proto.Unmarshal(waitSpecRaw, &waitSpec); err != nil {
		log.WithError(err).Fatal("Failed to unmarshal wait spec")
	}

	log.WithField("waitSpec", waitSpec).Info("Started")
	for {
		if err := runOnce(sandboxManagerHost, waitSpec); err != nil {
			log.WithError(err).Error("Failed to run")
		} else {
			log.Info("Ready to boot")
			os.Exit(0)
		}
	}
}

func runOnce(sandboxManagerHost string, waitSpec sandbox.WaitSpec) error {
	// Connect to the sandbox manager.
	conn, err := grpc.Dial(sandboxManagerHost+":9002",
		grpc.WithInsecure(),
		grpc.WithDefaultCallOptions(grpc.UseCompressor(gzip.Name)))
	if err != nil {
		return err
	}
	client := sandbox.NewBootWaiterClient(conn)

	// Poll the sandbox manager until we're allowed to boot.
	for {
		isReady, err := client.CheckReady(context.TODO(), &sandbox.CheckReadyRequest{
			WaitSpec: &waitSpec,
		})
		if err != nil {
			return err
		}

		if isReady.Ready {
			return nil
		}

		log.WithField("reason", isReady.Reason).Info("Not ready to boot yet... Will check again in one second")
		time.Sleep(1 * time.Second)
	}
}
