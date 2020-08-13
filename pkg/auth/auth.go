package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	// "time"

	"github.com/coreos/go-oidc"
	dockerTypes "github.com/docker/docker/api/types"
	"golang.org/x/oauth2"

	"github.com/kelda/blimp/pkg/errors"
	// "github.com/kelda/blimp/pkg/hash"
)

type User struct {
	ID            string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Namespace     string
}

const (
	ClientID           = "b87He1pQEDohVzOAYAfLIUfixO5zu6Ln"
	AuthHost           = ""
	AuthURL            = AuthHost + "/authorize"
	TokenURL           = AuthHost + "/oauth/token"
	JWKSURL            = ""
	LoginProxyGRPCPort = 443
)

var Endpoint = oauth2.Endpoint{
	AuthURL:   AuthHost + "/authorize",
	TokenURL:  AuthHost + "/oauth/token",
	AuthStyle: oauth2.AuthStyleInParams,
}

var DefaultKeySet = oidc.NewRemoteKeySet(context.Background(), JWKSURL)

var DefaultVerifier = VerifierFromKeySet(DefaultKeySet)

func VerifierFromKeySet(keySet oidc.KeySet) *oidc.IDTokenVerifier {
	return oidc.NewVerifier(
		"",
		keySet,
		&oidc.Config{
			ClientID: ClientID,

			// We handle the expiration check ourselves in `ParseIDToken` so that
			// we can return a friendly error if it's expired.
			SkipExpiryCheck: true,
		})
}

func GetOAuthConfig(clientSecret string) oauth2.Config {
	return oauth2.Config{
		ClientID:     ClientID,
		ClientSecret: clientSecret,
		Endpoint:     Endpoint,
		Scopes: []string{
			"openid",
			"email",
		},
	}
}

func ParseIDToken(token string, _ *oidc.IDTokenVerifier) (User, error) {
	return User{Namespace: token}, nil
}

// PasswordLogin obtains an authentication token by directly exchanging the
// provided username and password, rather than using OAuth. It should only
// be used for authenticating test accounts during continuous integration tests.
func PasswordLogin(username, password string) (string, error) {
	oauthConfig := GetOAuthConfig("")
	token, err := oauthConfig.PasswordCredentialsToken(context.Background(), username, password)
	if err != nil {
		return "", err
	}

	idToken, ok := token.Extra("id_token").(string)
	if !ok {
		return "", errors.New("missing id token")
	}
	return idToken, nil
}

func RegistryAuthHeader(token string) (string, error) {
	authJSON, err := json.Marshal(dockerTypes.AuthConfig{
		Username: "ignored",
		Password: token,
	})
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(authJSON), nil
}
