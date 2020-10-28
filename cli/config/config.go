package config

import (
	"github.com/kelda/blimp/cli/authstore"
	"github.com/kelda/blimp/pkg/cfgdir"
	"github.com/kelda/blimp/pkg/errors"
	authProto "github.com/kelda/blimp/pkg/proto/auth"
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

	if store.Username == "" {
		// TODO: Remove references to `blimp login`. Rename field.
		return Config{}, errors.NewFriendlyError(`No username set. Set the "username" field in your ~/.blimp/auth.yaml.`)
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
		Token:       config.Auth.Username,
		ClusterAuth: config.ConfigFile.ClusterToken,
	}
}
