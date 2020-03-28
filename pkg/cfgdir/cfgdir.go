package cfgdir

import (
	"os"

	homedir "github.com/mitchellh/go-homedir"
	log "github.com/sirupsen/logrus"
)

var dir string

func init() {
	var err error
	dir, err = homedir.Expand("~/.blimp")
	if err != nil {
		log.WithError(err).Fatal("can't find home directory")
	}
}

func Create() error {
	err := os.Mkdir(dir, 0777)
	if os.IsExist(err) {
		return nil
	}
	return err
}

func Expand(filename string) string {
	return dir + "/" + filename
}
