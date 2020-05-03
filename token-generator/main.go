package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"

	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"

	"github.com/kelda-inc/blimp/pkg/auth"
)

func main() {
	clientSecret := os.Getenv("CLIENT_SECRET")
	if clientSecret == "" {
		log.Fatal("CLIENT_SECRET is required")
	}

	oauthConf := &oauth2.Config{
		ClientID:     auth.ClientID,
		ClientSecret: clientSecret,
		Endpoint:     auth.Endpoint,
		RedirectURL:  fmt.Sprintf("https://blimp-login.kelda.io%s", auth.RedirectPath),
		Scopes: []string{
			"openid",
		},
	}

	serveMux := http.NewServeMux()
	serveMux.HandleFunc(auth.RedirectPath, func(w http.ResponseWriter, r *http.Request) {
		log.Info("Received oauth code")
		idToken, err := getTokenForCode(oauthConf, r)
		if err != nil {
			fmt.Fprintf(w, "Login failed: %s\n", err)
			return
		}

		msgTemplate := `Successfully logged in. Run the following command to use your token:

cat <<EOF > ~/.blimp/auth.yaml
AuthToken: %s
EOF`
		fmt.Fprintf(w, msgTemplate, idToken)
	})
	serveMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, oauthConf.AuthCodeURL("state"), 302)
	})

	server := http.Server{
		Handler: serveMux,
		Addr:    ":8000",
	}
	if err := server.ListenAndServe(); err != nil {
		panic(err)
	}
}

func getTokenForCode(oauthConf *oauth2.Config, r *http.Request) (string, error) {
	err := r.ParseForm()
	if err != nil {
		return "", fmt.Errorf("parse form: %w", err)
	}

	code := r.FormValue("code")
	if code == "" {
		return "", errors.New("no auth code")
	}

	log.WithField("code", code).Info("Exchanging oauth code for token")
	tok, err := oauthConf.Exchange(context.Background(), code)
	if err != nil {
		return "", fmt.Errorf("exchange auth code: %w", err)
	}

	idToken, ok := tok.Extra("id_token").(string)
	if !ok {
		return "", errors.New("missing id token")
	}
	return idToken, nil
}
