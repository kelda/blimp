package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	log "github.com/sirupsen/logrus"
	"gopkg.in/square/go-jose.v2"

	"github.com/kelda/blimp/pkg/errors"
)

// diskCachedKeySet implements oidc.KeySet by referencing keys on the local disk
// if they are present, and fetching them from the remoteURL if the couldn't be
// found locally.
type diskCachedKeySet struct {
	localPath string
	remoteURL string
}

// VerifySignature implements oidc.KeySet.
func (ks diskCachedKeySet) VerifySignature(ctx context.Context, jwt string) ([]byte, error) {
	jws, err := jose.ParseSigned(jwt)
	if err != nil {
		return nil, errors.WithContext("malformed jwt", err)
	}

	var keys jose.JSONWebKeySet
	fileBytes, err := ioutil.ReadFile(ks.localPath)
	if err == nil {
		err = json.Unmarshal(fileBytes, &keys)
	}

	if err != nil {
		log.WithError(err).Info("Fetching JWKS from remote")
		keys, err = ks.fetchKeySet()
	}

	if err != nil {
		return nil, err
	}

	for _, key := range keys.Keys {
		_, _, payload, err := jws.VerifyMulti(key)
		if err == nil {
			return payload, nil
		}
	}
	return nil, errors.New("failed to verify id token signature")
}

func (ks diskCachedKeySet) fetchKeySet() (jose.JSONWebKeySet, error) {
	resp, err := http.Get(ks.remoteURL)
	if err != nil {
		return jose.JSONWebKeySet{}, errors.WithContext("fetch jwks from remote", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return jose.JSONWebKeySet{}, errors.WithContext("read jwks response body", err)
	}

	if resp.StatusCode != http.StatusOK {
		return jose.JSONWebKeySet{}, errors.New(
			"bad status code %s while fetching jwks, body: %s", resp.Status, body)
	}

	var keys jose.JSONWebKeySet
	err = json.Unmarshal(body, &keys)
	if err != nil {
		return jose.JSONWebKeySet{}, errors.WithContext(
			fmt.Sprintf("failed to decode jwks with body %s", body), err)
	}

	// Write to disk cache.
	err = ioutil.WriteFile(ks.localPath, body, 0600)
	if err != nil {
		log.WithError(err).Error("Couldn't write JWKS to disk cache.")
	}
	return keys, nil
}
