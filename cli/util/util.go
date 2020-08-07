package util

import (
	"crypto/x509"
	"io/ioutil"
	"net/url"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/keepalive"

	"github.com/docker/docker/client"
	"github.com/kelda/blimp/pkg/errors"
)

func Dial(addr, certPEM string) (*grpc.ClientConn, error) {
	cp := x509.NewCertPool()
	if !cp.AppendCertsFromPEM([]byte(certPEM)) {
		return nil, errors.New("failed to parse cert")
	}

	return grpc.Dial(addr,
		grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(cp, "")),
		// AWS ELBs close connections that are inactive for 60s, so we set a
		// keepalive interval lower than this.
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 30 * time.Second}),
		grpc.WithDefaultCallOptions(grpc.UseCompressor(gzip.Name)),
		grpc.WithUnaryInterceptor(errors.UnaryClientInterceptor))
}

func GetDockerClient() (*client.Client, error) {
	dockerClient, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())

	// If a custom host is set, don't try any funny business.
	if err != nil || dockerClient.DaemonHost() != client.DefaultDockerHost {
		return dockerClient, err
	}

	socketUrl, err := url.Parse(dockerClient.DaemonHost())
	if err != nil {
		// We really do not expect this to ever happen.
		panic(err)
	}

	if socketUrl.Scheme != "unix" {
		return dockerClient, nil
	}

	// Check to see if this unix socket actually exists.
	f, err := os.Open(socketUrl.Path)
	if err == nil {
		f.Close()
		return dockerClient, nil
	}

	// It doesn't exist. If we're in WSL, see if we should use the TCP socket
	// instead.
	procVersion, err := ioutil.ReadFile("/proc/version")
	if err != nil || !strings.Contains(string(procVersion), "Microsoft") {
		return dockerClient, nil
	}

	return client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation(),
		client.WithHost("tcp://localhost:2375"))
}
