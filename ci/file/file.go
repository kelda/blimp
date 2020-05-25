package file

import (
	"io/ioutil"
	"strings"

	"github.com/kelda-inc/blimp/pkg/errors"
)

type Modifier func(string) (string, error)

func Modify(path string, modFn Modifier) error {
	f, err := ioutil.ReadFile(path)
	if err != nil {
		return errors.WithContext("read", err)
	}

	modified, err := modFn(string(f))
	if err != nil {
		return errors.WithContext("modify", err)
	}

	err = ioutil.WriteFile(path, []byte(modified), 0644)
	if err != nil {
		return errors.WithContext("write", err)
	}
	return nil
}

func Replace(currStr, newStr string) Modifier {
	return func(f string) (string, error) {
		if !strings.Contains(f, currStr) {
			return "", errors.New("file doesn't contain expected string. The test is probably buggy")
		}
		return strings.Replace(f, currStr, newStr, -1), nil
	}
}

func DeleteLine(linesToDelete ...int) Modifier {
	return func(f string) (string, error) {
		var resultLines []string
		for i, line := range strings.Split(f, "\n") {
			var shouldSkip bool
			for _, toDelete := range linesToDelete {
				if i+1 == toDelete {
					shouldSkip = true
					break
				}
			}
			if shouldSkip {
				continue
			}

			resultLines = append(resultLines, line)
		}

		return strings.Join(resultLines, "\n"), nil
	}
}
