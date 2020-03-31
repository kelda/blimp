package util

import (
	"crypto/x509"
	"errors"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/encoding/gzip"
)

func Dial(addr, certPEM string) (*grpc.ClientConn, error) {
	cp := x509.NewCertPool()
	if !cp.AppendCertsFromPEM([]byte(certPEM)) {
		return nil, errors.New("failed to parse cert")
	}

	return grpc.Dial(addr,
		grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(cp, "")),
		grpc.WithDefaultCallOptions(grpc.UseCompressor(gzip.Name)))
}
