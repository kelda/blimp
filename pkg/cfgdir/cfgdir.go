package cfgdir

import (
	"os"

	homedir "github.com/mitchellh/go-homedir"
	log "github.com/sirupsen/logrus"
)

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
