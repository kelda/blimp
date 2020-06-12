package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/coreos/go-oidc"
	dockerTypes "github.com/docker/docker/api/types"
	"golang.org/x/oauth2"

	"github.com/kelda/blimp/pkg/errors"
	"github.com/kelda/blimp/pkg/hash"
)

type User struct {
	ID        string `json:"sub"`
	Namespace string
}

const (
	ClientID           = "b87He1pQEDohVzOAYAfLIUfixO5zu6Ln"
	AuthHost           = "https://blimp-testing.auth0.com"
	AuthURL            = AuthHost + "/authorize"
	TokenURL           = AuthHost + "/oauth/token"
	JWKSURL            = "https://blimp-testing.auth0.com/.well-known/jwks.json"
	LoginProxyGRPCPort = 444
)

var Endpoint = oauth2.Endpoint{
	AuthURL:   AuthHost + "/authorize",
	TokenURL:  AuthHost + "/oauth/token",
	AuthStyle: oauth2.AuthStyleInParams,
}

// TODO: Fetching over the network.. Any issues if no network connectivity?
var DefaultKeySet = oidc.NewRemoteKeySet(context.Background(), JWKSURL)

var DefaultVerifier = VerifierFromKeySet(DefaultKeySet)

func VerifierFromKeySet(keySet oidc.KeySet) *oidc.IDTokenVerifier {
	return oidc.NewVerifier(
		"https://blimp-testing.auth0.com/",
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
		},
	}
}

func ParseIDToken(token string, verifier *oidc.IDTokenVerifier) (User, error) {
	idToken, err := verifier.Verify(context.Background(), token)
	if err != nil {
		return User{}, errors.WithContext("verify", err)
	}

	if time.Now().After(idToken.Expiry) {
		return User{}, errors.NewFriendlyError("Blimp session expired. " +
			"Please log in again with `blimp login`.")
	}

	var user User
	if err := idToken.Claims(&user); err != nil {
		return User{}, errors.WithContext("parse claims", err)
	}

	user.Namespace = hash.DnsCompliant(user.ID)
	return user, nil
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
