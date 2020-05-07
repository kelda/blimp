package syncthing

import (
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/syncthing/syncthing/lib/fs"
	"github.com/syncthing/syncthing/lib/ignore"
)

const hashTrackerName = ".blimp-hash"

func syncFileHash(stop <-chan struct{}, folder string) {
	hashPath := HashTrackerPath(folder)
	defer os.Remove(hashPath)

	writeOnce := func() {
		h, err := HashFolder(folder)
		if err != nil {
			log.WithError(err).Warn("Failed to calculate bind volume hash")
			return
		}

		if err := ioutil.WriteFile(hashPath, []byte(h), 0644); err != nil {
			log.WithError(err).Warn("Failed to write bind volume hash")
		}
	}

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		writeOnce()

		select {
		case <-stop:
			return
		case <-ticker.C:
		}
	}
}

func HashTrackerPath(folder string) string {
	return filepath.Join(folder, hashTrackerName)
}

func HashFolder(root string) (string, error) {
	ignoreMatcher := ignore.New(fs.NewFilesystem(fs.FilesystemTypeBasic, ""))
	ignorePath := filepath.Join(root, ".stignore")
	if _, err := os.Stat(ignorePath); err == nil {
		if err := ignoreMatcher.Load(ignorePath); err != nil {
			return "", fmt.Errorf("load stignore: %w", err)
		}
	}

	// If the folder is a symlink, resolve the symlink so that we
	// `filepath.Walk` reads the files within it. This fixes a bug where we
	// would calculate the hash as just a single symlink, while the remote
	// container would (correctly) include the contents of the folder in its
	// hash.
	fi, err := os.Lstat(root)
	if err != nil {
		return "", fmt.Errorf("stat volume: %w", err)
	}

	if fi.Mode()&os.ModeSymlink != 0 {
		link, err := os.Readlink(root)
		if err != nil {
			return "", fmt.Errorf("get symlink target for volume: %w", err)
		}

		if filepath.IsAbs(link) {
			root = link
		} else {
			root = filepath.Join(filepath.Dir(root), link)
		}
	}

	var hashes []string
	err = filepath.Walk(root, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if fi.IsDir() {
			return nil
		}

		// Don't include the hash tracker file in the hash, or else when we
		// update the hash file, the next calculation will be different.
		if fi.Name() == hashTrackerName {
			return nil
		}

		relativePath, err := filepath.Rel(root, path)
		if err != nil || strings.HasPrefix(relativePath, "..") {
			return fmt.Errorf("get relative path: %w", err)
		}

		if ignoreMatcher.ShouldIgnore(relativePath) {
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
