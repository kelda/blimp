package buildkit

import (
	"context"

	"github.com/moby/buildkit/session/auth"
	"google.golang.org/grpc"

	blimpAuth "github.com/kelda/blimp/pkg/auth"
)

type authProvider struct {
	regCreds blimpAuth.RegistryCredentials
}

func (ap *authProvider) Register(server *grpc.Server) {
	auth.RegisterAuthServer(server, ap)
}

func (ap *authProvider) Credentials(_ context.Context, req *auth.CredentialsRequest) (*auth.CredentialsResponse, error) {
	cred, ok := ap.regCreds.LookupByHost(req.Host)
	if !ok {
		return &auth.CredentialsResponse{}, nil
	}

	return &auth.CredentialsResponse{
		Username: cred.Username,
		Secret:   cred.Password,
	}, nil
}
