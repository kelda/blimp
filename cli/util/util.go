package util

import (
	"context"
	"crypto/x509"
	"io/ioutil"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/keepalive"

	"github.com/docker/docker/client"
	"github.com/kelda/blimp/pkg/errors"
)

func Dial(addr, certPEM, serverNameOverride string) (*grpc.ClientConn, error) {
	cp := x509.NewCertPool()
	if !cp.AppendCertsFromPEM([]byte(certPEM)) {
		return nil, errors.New("failed to parse cert")
	}

	return grpc.Dial(addr,
		grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(cp, serverNameOverride)),
		// AWS ELBs close connections that are inactive for 60s, so we set a
		// keepalive interval lower than this.
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 30 * time.Second}),
		grpc.WithDefaultCallOptions(grpc.UseCompressor(gzip.Name)),
		grpc.WithUnaryInterceptor(errors.UnaryClientInterceptor))
}

// GetDockerClient returns a working Docker client, or nil if we can't connect
// to a Docker client. Notably, this function can return (nil, nil) if we can't
// find a Docker client that accepts connetions.
func GetDockerClient() (*client.Client, error) {
	dockerClient, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, errors.WithContext("create docker client", err)
	}

	ctx, _ := context.WithTimeout(context.Background(), 5 * time.Second)
	_, err = dockerClient.Ping(ctx)
	if err == nil {
		// We successfully connected to the Docker daemon, so we're pretty
		// confident it's running and works.
		return dockerClient, nil
	}
	if !client.IsErrConnectionFailed(err) {
		return nil, errors.WithContext("docker ping failed", err)
	}

	// If connection failed, Docker is probably not available at the default
	// address.

	// If a custom host is set, don't try any funny business.
	if dockerClient.DaemonHost() != client.DefaultDockerHost {
		return nil, nil
	}

	// If we're in WSL, see if we should use the TCP socket instead.
	procVersion, err := ioutil.ReadFile("/proc/version")
	if err != nil || !strings.Contains(string(procVersion), "Microsoft") {
		// Not WSL, so we just give up.
		return nil, nil
	}

	dockerClient, err = client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation(),
		client.WithHost("tcp://localhost:2375"))
	if err != nil {
		return nil, errors.WithContext("create WSL TCP docker client", err)
	}

	ctx, _ = context.WithTimeout(context.Background(), 5 * time.Second)
	_, err = dockerClient.Ping(ctx)
	if err == nil {
		return dockerClient, nil
	}
	if !client.IsErrConnectionFailed(err) {
		return nil, errors.WithContext("docker ping failed", err)
	}

	// Still unable to find a Docker daemon. Give up.
	return nil, nil
}
