package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/golang/protobuf/proto"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/encoding/gzip"

	"github.com/kelda-inc/blimp/node/wait"
	protoWait "github.com/kelda-inc/blimp/pkg/proto/wait"
	"github.com/kelda/blimp/pkg/errors"
)

func main() {
	nodeControllerHost := os.Getenv("NODE_CONTROLLER_HOST")
	if nodeControllerHost == "" {
		log.Fatal("NODE_CONTROLLER_HOST environment variable is required")
	}

	namespace := os.Getenv("NAMESPACE")
	if namespace == "" {
		log.Fatal("NAMESPACE environment variable is required")
	}

	waitSpecRaw, err := ioutil.ReadFile("/etc/blimp/wait-spec")
	if err != nil {
		log.WithError(err).Fatal("Failed to read wait spec")
	}

	var waitSpec protoWait.WaitSpec
	if err := proto.Unmarshal(waitSpecRaw, &waitSpec); err != nil {
		log.WithError(err).Fatal("Failed to unmarshal wait spec")
	}

	log.WithField("waitSpec", waitSpec).Info("Started")
	for {
		if err := runOnce(nodeControllerHost, namespace, waitSpec); err != nil {
			log.WithError(err).Error("Failed to run. Retrying in 10 seconds.")
			time.Sleep(10 * time.Second)
		} else {
			log.Info("Ready to boot")
			os.Exit(0)
		}
	}
}

func runOnce(nodeControllerHost, namespace string, waitSpec protoWait.WaitSpec) error {
	log.Info("Initiating CheckReady request")

	// Connect to the node controller.
	conn, err := grpc.Dial(fmt.Sprintf("%s:%d", nodeControllerHost, wait.Port),
		grpc.WithInsecure(),
		grpc.WithBlock(),
		grpc.WithUnaryInterceptor(errors.UnaryClientInterceptor),
		grpc.WithDefaultCallOptions(grpc.UseCompressor(gzip.Name)))
	if err != nil {
		return err
	}
	defer conn.Close()
	client := protoWait.NewBootWaiterClient(conn)

	isReadyStream, err := client.CheckReady(context.TODO(), &protoWait.CheckReadyRequest{
		Namespace: namespace,
		WaitSpec:  &waitSpec,
	})
	if err != nil {
		return err
	}

	for {
		isReady, err := isReadyStream.Recv()
		if err != nil {
			return err
		}

		if isReady.Ready {
			return nil
		}
		log.WithField("reason", isReady.Reason).Info("Not ready to boot yet...")
	}
}
