package util

import (
	"crypto/x509"
	"errors"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/encoding/gzip"
)

var ManagerHost = getManagerHost()

func getManagerHost() string {
	envVal := os.Getenv("MANAGER_HOST")
	if envVal != "" {
		return envVal
	}
	return "blimp-manager.kelda.io:9000"
}

func Dial(addr, certPEM string) (*grpc.ClientConn, error) {
	cp := x509.NewCertPool()
	if !cp.AppendCertsFromPEM([]byte(certPEM)) {
		return nil, errors.New("failed to parse cert")
	}

	return grpc.Dial(addr,
		grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(cp, "")),
		grpc.WithDefaultCallOptions(grpc.UseCompressor(gzip.Name)))
}
