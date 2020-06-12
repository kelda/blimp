package cfgdir

import (
	"io/ioutil"
	"os"

	"github.com/ghodss/yaml"
	homedir "github.com/mitchellh/go-homedir"
	log "github.com/sirupsen/logrus"

	"github.com/kelda/blimp/pkg/errors"
)

type Config struct {
	OptOutAnalytics bool `json:"opt_out_analytics"`
}

var ConfigDir string

func init() {
	var err error
	ConfigDir, err = homedir.Expand("~/.blimp")
	if err != nil {
		log.WithError(err).Fatal("can't find home directory")
	}
}

func Create() error {
	err := os.Mkdir(ConfigDir, 0755)
	if os.IsExist(err) {
		return nil
	}
	return err
}

func Expand(filename string) string {
	return ConfigDir + "/" + filename
}

func CLILogFile() string {
	return Expand("blimp-cli.log")
}

func ParseConfig() (Config, error) {
	cfgPath := Expand("blimp.yaml")
	cfgContents, err := ioutil.ReadFile(cfgPath)
	if err != nil {
		if os.IsNotExist(err) {
			return Config{}, nil
		}
		return Config{}, errors.WithContext("read config", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(cfgContents, &cfg); err != nil {
		return Config{}, errors.WithContext("parse config", err)
	}
	return cfg, nil
}
