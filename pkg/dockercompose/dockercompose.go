package dockercompose

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ghodss/yaml"

	"github.com/compose-spec/compose-go/envfile"
	"github.com/compose-spec/compose-go/loader"
	"github.com/compose-spec/compose-go/types"
)

func Load(path string, b []byte) (types.Config, error) {
	configIntf, err := loader.ParseYAML(b)
	if err != nil {
		return types.Config{}, fmt.Errorf("parse: %w", err)
	}

	env := map[string]string{}
	dotenvPath := filepath.Join(filepath.Dir(path), ".env")
	if _, err := os.Stat(dotenvPath); err == nil {
		dotenv, err := parseEnvFile(dotenvPath)
		if err != nil {
			return types.Config{}, fmt.Errorf("parse .env file: %w", err)
		}

		env = dotenv
	}

	// Environment variables in the shell take precedence over the .env file:
	// https://docs.docker.com/compose/environment-variables/#the-env-file
	for _, e := range os.Environ() {
		pair := strings.SplitN(e, "=", 2)
		var val string
		if len(pair) == 2 {
			val = pair[1]
		}
		env[pair[0]] = val
	}

	opts := []func(*loader.Options){
		// Discard env_files references after evaluating them so that the
		// cluster manager doesn't error when it tries to load the
		// configuration file.
		loader.WithDiscardEnvFiles,

		// Skip validation so that the loader doesn't error on non-v3 files.
		withSkipValidation,
	}

	cfgPtr, err := loader.Load(types.ConfigDetails{
		WorkingDir: filepath.Dir(path),
		ConfigFiles: []types.ConfigFile{
			{
				Filename: filepath.Base(path),
				Config:   configIntf,
			},
		},
		Environment: env,
	}, opts...)
	if err != nil {
		if forbiddenPropertiesErr, ok := err.(*loader.ForbiddenPropertiesError); ok {
			var tips []string
			for property, tip := range forbiddenPropertiesErr.Properties {
				tips = append(tips, fmt.Sprintf("%s: %s", property, tip))
			}
			return types.Config{}, fmt.Errorf("Compose File uses forbidden properties. "+
				"Please upgrade to Compose Spec version 3 (http://link.kelda.io/upgrade-compose).\n\n%s",
				strings.Join(tips, "\n"))
		}
		return types.Config{}, fmt.Errorf("load: %w", err)
	}

	return *cfgPtr, nil
}

func parseEnvFile(path string) (map[string]string, error) {
	parsed, err := envfile.Parse(path)
	if err != nil {
		return nil, err
	}

	ret := map[string]string{}
	for k, vPtr := range parsed {
		v := ""
		if vPtr != nil {
			v = *vPtr
		}
		ret[k] = v
	}
	return ret, nil
}

func Unmarshal(b []byte) (parsed types.Config, err error) {
	configIntf, err := loader.ParseYAML(b)
	if err != nil {
		return types.Config{}, fmt.Errorf("parse: %w", err)
	}

	cfgPtr, err := loader.Load(types.ConfigDetails{
		ConfigFiles: []types.ConfigFile{
			{
				Config: configIntf,
			},
		},
	}, withSkipValidation, withSkipInterpolation)
	if err != nil {
		return types.Config{}, fmt.Errorf("load: %w", err)
	}

	return *cfgPtr, nil
}

func Marshal(cfg types.Config) ([]byte, error) {
	return yaml.Marshal(cfg)
}

func withSkipValidation(opts *loader.Options) {
	opts.SkipValidation = true
}

func withSkipInterpolation(opts *loader.Options) {
	opts.SkipInterpolation = true
}
