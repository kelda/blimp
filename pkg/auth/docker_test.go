package auth

import (
	"testing"

	"github.com/docker/docker/api/types"

	"github.com/stretchr/testify/assert"
)

func TestRegistryCredentialsLookupByHost(t *testing.T) {
	correct := types.AuthConfig{Username: "correct"}
	incorrect := types.AuthConfig{Username: "incorrect"}
	tests := []struct {
		name     string
		regCreds RegistryCredentials
		host     string
	}{
		{
			name: "ExactMatch",
			regCreds: RegistryCredentials{
				"gcr.io":    correct,
				"us.gcr.io": incorrect,
			},
			host: "gcr.io",
		},
		{
			name: "DockerIndexAlias",
			regCreds: RegistryCredentials{
				"https://index.docker.io/v1/": correct,
				"us.gcr.io":                   incorrect,
			},
			host: "registry-1.docker.io",
		},
	}

	for _, test := range tests {
		res, ok := test.regCreds.LookupByHost(test.host)
		assert.True(t, ok, test.name)
		assert.Equal(t, correct, res, test.name)
	}
}

func TestRegistryCredentialsLookupByImage(t *testing.T) {
	correct := types.AuthConfig{Username: "correct"}
	incorrect := types.AuthConfig{Username: "incorrect"}
	tests := []struct {
		name     string
		regCreds RegistryCredentials
		image    string
	}{
		{
			name: "ExactMatch",
			regCreds: RegistryCredentials{
				"gcr.io":    correct,
				"us.gcr.io": incorrect,
			},
			image: "gcr.io/kelda-blimp/test:foo",
		},
		{
			name: "DockerHub",
			regCreds: RegistryCredentials{
				"index.docker.io":   correct,
				"https://us.gcr.io": incorrect,
			},
			image: "keldaio/test:bar",
		},
	}

	for _, test := range tests {
		res, ok := test.regCreds.LookupByImage(test.image)
		assert.True(t, ok, test.name)
		assert.Equal(t, correct, res, test.name)
	}
}
