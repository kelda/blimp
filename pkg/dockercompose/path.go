package dockercompose

import (
	"os"
	"path/filepath"
)

func GetPaths(composePaths []string) (string, []string, error) {
	getYamlFile := func(prefix string) (string, error) {
		paths := []string{
			prefix + ".yaml",
			prefix + ".yml",
		}

		var err error
		for _, path := range paths {
			if _, err = os.Stat(path); err == nil {
				return filepath.Abs(path)
			}
		}

		// Return the error from the last path we tried to stat.
		return "", err
	}

	// If the user doesn't explicitly specify any files, try to get the
	// default files.
	if len(composePaths) == 0 {
		composePath, err := getYamlFile("docker-compose")
		if err != nil {
			return "", nil, err
		}

		var overridePaths []string
		if overridePath, err := getYamlFile("docker-compose.override"); err == nil {
			overridePaths = []string{overridePath}
		}
		return composePath, overridePaths, nil
	}

	var absPaths []string
	for _, composePath := range composePaths {
		p, err := filepath.Abs(composePath)
		if err != nil {
			return "", nil, err
		}
		absPaths = append(absPaths, p)
	}

	return absPaths[0], absPaths[1:], nil
}
