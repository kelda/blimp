package config

import (
	"github.com/kelda/blimp/cli/authstore"
	"github.com/kelda/blimp/pkg/cfgdir"
	"github.com/kelda/blimp/pkg/errors"
)

type Config struct {
	Auth       authstore.Store
	ConfigFile cfgdir.Config
}

func GetConfig() (Config, error) {
	auth, err := authstore.New()
	if err != nil {
		return Config{}, errors.WithContext("get auth store", err)
	}

	if auth.AuthToken == "" {
		return Config{}, errors.NewFriendlyError("Not logged in. Please run `blimp login`.")
	}

	configFile, err := cfgdir.ParseConfig()
	if err != nil {
		return Config{}, errors.WithContext("parse config file", err)
	}

	return Config{
		Auth: auth,
		ConfigFile: configFile,
	}, nil
}

func (config Config) BlimpAuth() string {
	return config.Auth.AuthToken
}
