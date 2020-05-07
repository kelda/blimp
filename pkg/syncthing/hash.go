package syncthing

import (
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
)

func HashVolume(volumePath string, isIgnored func(string) bool) (string, error) {
	// Don't ignore any files by default.
	if isIgnored == nil {
		isIgnored = func(_ string) bool { return false }
	}

	var hashes []string
	err := filepath.Walk(volumePath, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if fi.IsDir() {
			return nil
		}

		if isIgnored(path) {
			return nil
		}

		var hash string
		switch {
		case fi.Mode()&os.ModeSymlink != 0:
			hash, err = os.Readlink(path)
			if err != nil {
				return fmt.Errorf("get symlink target for %s: %w", path, err)
			}
		default:
			hash, err = hashFile(path)
			if err != nil {
				return err
			}
		}

		hashes = append(hashes, hash)
		return nil
	})
	if err != nil {
		return "", err
	}

	sort.Strings(hashes)
	hasher := sha512.New()
	for _, hash := range hashes {
		fmt.Fprintf(hasher, hash)
	}
	return base64.StdEncoding.EncodeToString(hasher.Sum(nil)), nil
}

// hashFile returns the sha512 hash of the file at the given path.
func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open: %w", err)
	}
	defer f.Close()

	hasher := sha512.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return "", fmt.Errorf("read: %w", err)
	}

	return base64.StdEncoding.EncodeToString(hasher.Sum(nil)), nil
}
