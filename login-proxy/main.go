package main

import (
	"context"
	"fmt"
	"net/http"
	"os"

	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"

	"github.com/kelda/blimp/pkg/auth"
	"github.com/kelda/blimp/pkg/errors"
)

const (
	// The ports that we listen on from behind the load balancer. A Nginx proxy
	// handle terminating TLS, and proxies traffic to these ports.
	httpPort = 8000
	grpcPort = 8001
)

var LoginProxyHost string

func main() {
	clientSecret := os.Getenv("CLIENT_SECRET")
	if clientSecret == "" {
		log.Fatal("CLIENT_SECRET is required")
	}

	oauthConf := auth.GetOAuthConfig(clientSecret)
	cliLoginServer := newCLILoginServer(oauthConf)
	manualLoginServer := newManualLoginServer(oauthConf)

	// The HTTP server handles fetching the identity token based on the
	// authorization code sent by Auth0, as well as the browser-only login
	// flow.
	serveMux := http.NewServeMux()
	cliLoginServer.Register(serveMux)
	manualLoginServer.Register(serveMux)

	httpServer := http.Server{
		Handler: serveMux,
		Addr:    fmt.Sprintf(":%d", httpPort),
	}
	go func() {
		log.Info("Starting HTTP server")
		if err := httpServer.ListenAndServe(); err != nil {
			log.WithError(err).Fatal("Failed to run http server")
		}
	}()

	if err := cliLoginServer.ServeGRPC(fmt.Sprintf(":%d", grpcPort)); err != nil {
		log.WithError(err).Fatal("Failed to run grpc server")
	}
}

// getTokenForCode exchanges the authorization code from Auth0 for an identity token.
func getTokenForCode(oauthConf *oauth2.Config, r *http.Request) (string, error) {
	err := r.ParseForm()
	if err != nil {
		return "", errors.WithContext("parse form", err)
	}

	code := r.FormValue("code")
	if code == "" {
		return "", errors.New("no auth code")
	}

	log.WithField("code", code).Info("Exchanging oauth code for token")
	tok, err := oauthConf.Exchange(context.Background(), code)
	if err != nil {
		return "", errors.WithContext("exchange auth code", err)
	}

	idToken, ok := tok.Extra("id_token").(string)
	if !ok {
		return "", errors.New("missing id token")
	}

	return idToken, nil
}
