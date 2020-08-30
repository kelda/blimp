package docker

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/docker/cli/cli/config/configfile"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/jsonmessage"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh/terminal"

	"github.com/kelda/blimp/pkg/errors"
	"github.com/kelda/blimp/pkg/hash"
	composeTypes "github.com/kelda/compose-go/types"
)

// ImageCacheRepo is the local image name used to tag built versions of images.
// Each cached image is identified by a tag appended to the imageCacheRepo.
const ImageCacheRepo = "blimp-cache"

func CachedImageName(absComposePath, svc string) string {
	tag := hash.DNSCompliant(fmt.Sprintf("%s-%s", absComposePath, svc))
	return fmt.Sprintf("%s:%s", ImageCacheRepo, tag)
}

func Build(dockerClient *client.Client, absComposePath, svc string, spec composeTypes.BuildConfig,
	regCreds map[string]types.AuthConfig, dockerConfig *configfile.ConfigFile, pullParent, noCache bool) (string, error) {
	opts := types.ImageBuildOptions{
		Dockerfile:  spec.Dockerfile,
		Tags:        []string{CachedImageName(absComposePath, svc)},
		AuthConfigs: regCreds,
		BuildArgs:   dockerConfig.ParseProxyConfig(dockerClient.DaemonHost(), spec.Args),
		Target:      spec.Target,
		Labels:      spec.Labels,
		CacheFrom:   spec.CacheFrom,
		PullParent:  pullParent,
		NoCache:     noCache,
	}

	buildContextTar, err := makeTar(spec.Context)
	if err != nil {
		return "", errors.WithContext("tar context", err)
	}

	buildResp, err := dockerClient.ImageBuild(context.TODO(), buildContextTar, opts)
	if err != nil {
		return "", errors.WithContext("start build", err)
	}
	defer buildResp.Body.Close()

	// Block until the build completes, and return any errors that happen
	// during the build.
	var imageID string
	callback := func(msg jsonmessage.JSONMessage) {
		var id struct{ ID string }
		if err := json.Unmarshal(*msg.Aux, &id); err != nil {
			log.WithError(err).Warn("Failed to parse build ID")
			return
		}

		if id.ID != "" {
			imageID = id.ID
		}
	}

	isTerminal := terminal.IsTerminal(int(os.Stderr.Fd()))
	err = jsonmessage.DisplayJSONMessagesStream(buildResp.Body, os.Stderr, os.Stderr.Fd(), isTerminal, callback)
	if err != nil {
		return "", errors.NewFriendlyError(
			"Image build for %q failed. This is likely an error with the Dockerfile, rather than Blimp.\n"+
				"Make sure that the image successfully builds with `docker build`.\n\n"+
				"The full error was:\n%s", svc, err)
	}

	return imageID, nil
}

func getHeader(fi os.FileInfo, path string) (*tar.Header, error) {
	var link string
	if fi.Mode()&os.ModeSymlink != 0 {
		var err error
		link, err = os.Readlink(path)
		if err != nil {
			return nil, err
		}
	}

	return tar.FileInfoHeader(fi, link)
}

func makeTar(dir string) (io.Reader, error) {
	var out bytes.Buffer
	tw := tar.NewWriter(&out)
	defer tw.Close()

	err := filepath.Walk(dir, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		header, err := getHeader(fi, path)
		if err != nil {
			return errors.WithContext("get header", err)
		}

		// Set the file's path within the archive to be relative to the build
		// context.
		relPath, err := filepath.Rel(dir, path)
		if err != nil {
			return errors.WithContext(fmt.Sprintf("get normalized path %q", path), err)
		}
		// On Windows, relPath will use backslashes. ToSlash normalizes to use
		// forward slashes.
		header.Name = filepath.ToSlash(relPath)

		if err := tw.WriteHeader(header); err != nil {
			return errors.WithContext(fmt.Sprintf("write header %q", header.Name), err)
		}

		fileMode := fi.Mode()
		if !fileMode.IsRegular() {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return errors.WithContext(fmt.Sprintf("open file %q", header.Name), err)
		}
		defer f.Close()

		if _, err := io.Copy(tw, f); err != nil {
			return errors.WithContext(fmt.Sprintf("write file %q", header.Name), err)
		}
		return nil
	})
	return &out, err
}
