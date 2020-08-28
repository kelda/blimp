package util

import (
	"crypto/x509"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/keepalive"

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
