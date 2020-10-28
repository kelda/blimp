package util

import (
	"io/ioutil"
	"path/filepath"

	"github.com/kelda/blimp/pkg/errors"
)

func MakeTestDirectory(files map[string]string) (string, error) {
	dir, err := ioutil.TempDir("", "blimp-ci")
	if err != nil {
		return "", errors.WithContext("create test directory", err)
	}

	for path, contents := range files {
		err = ioutil.WriteFile(filepath.Join(dir, path), []byte(contents), 0644)
		if err != nil {
			return "", errors.WithContext("write file", err)
		}
	}

	return dir, nil
}
