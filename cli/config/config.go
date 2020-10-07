package config

import (
	"context"
	"crypto/tls"
	"fmt"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/kelda/blimp/cli/authstore"
	"github.com/kelda/blimp/pkg/auth"
	"github.com/kelda/blimp/pkg/cfgdir"
	"github.com/kelda/blimp/pkg/errors"
	authProto "github.com/kelda/blimp/pkg/proto/auth"
	"github.com/kelda/blimp/pkg/proto/login"
)

type Config struct {
	Auth       authstore.Store
	ConfigFile cfgdir.Config
}

func GetConfig() (Config, error) {
	store, err := authstore.New()
	if err != nil {
		return Config{}, errors.WithContext("get auth store", err)
	}

	if store.AuthToken == "" {
		return Config{}, errors.NewFriendlyError("Not logged in. Please run `blimp login`.")
	}

	// Check if the token is valid.
	if _, err := auth.ParseIDToken(store.AuthToken, auth.DefaultVerifier); err != nil {
		if err != auth.ErrTokenExpired || store.RefreshToken == "" {
			return Config{}, errors.NewFriendlyError("Invalid token. Please run `blimp login`.\n\n"+
				"The full error was: %s", err)
		}

		newToken, err := exchangeRefreshToken(store.RefreshToken)
		if err != nil {
			return Config{}, errors.NewFriendlyError("Failed to auto-refresh access token. Please run `blimp login`.\n\n"+
				"The full error was: %s", err)
		}
		store.AuthToken = newToken

		if err := store.Save(); err != nil {
			return Config{}, errors.NewFriendlyError("Failed to save new access token. Please run `blimp login`.\n\n"+
				"The full error was: %s", err)
		}
		log.Debug("Auto-refreshed access token")
	}

	configFile, err := cfgdir.ParseConfig()
	if err != nil {
		return Config{}, errors.WithContext("parse config file", err)
	}

	return Config{
		Auth:       store,
		ConfigFile: configFile,
	}, nil
}

func (config Config) BlimpAuth() *authProto.BlimpAuth {
	return &authProto.BlimpAuth{
		Token:       config.Auth.AuthToken,
		ClusterAuth: config.ConfigFile.ClusterToken,
	}
}

func exchangeRefreshToken(refreshToken string) (string, error) {
	// Use the system's default certificate pool.
	tlsConfig := &tls.Config{}
	conn, err := grpc.Dial(fmt.Sprintf("%s:%d", auth.LoginProxyGRPCHost, auth.LoginProxyGRPCPort),
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
		grpc.WithUnaryInterceptor(errors.UnaryClientInterceptor),
	)
	if err != nil {
		return "", errors.WithContext("create client", err)
	}
	defer conn.Close()

	client := login.NewLoginClient(conn)
	newToken, err := client.ExchangeRefreshToken(context.Background(),
		&login.ExchangeRefreshTokenRequest{RefreshToken: refreshToken})
	if err != nil {
		return "", errors.WithContext("get token", err)
	}

	return newToken.IdToken, nil
}
