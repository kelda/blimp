package up

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/pkg/jsonmessage"
	composeTypes "github.com/kelda/compose-go/types"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh/terminal"

	"github.com/kelda-inc/blimp/pkg/errors"
	"github.com/kelda-inc/blimp/pkg/hash"
)

var errNoCachedImage = errors.New("no cached image")

func (cmd *up) buildImages(composeFile composeTypes.Config) (map[string]string, error) {
	if cmd.dockerClient == nil {
		return nil, errors.New("no docker client")
	}

	images := map[string]string{}
	for _, svc := range composeFile.Services {
		if svc.Build == nil {
			continue
		}

		imageID, err := cmd.buildImage(*svc.Build, svc.Name)
		if err != nil {
			return nil, errors.WithContext(fmt.Sprintf("build %s", svc.Name), err)
		}

		imageName, err := cmd.pushImage(svc.Name, imageID)
		if err != nil {
			return nil, errors.WithContext(fmt.Sprintf("push %s", svc.Name), err)
		}

		images[svc.Name] = imageName
	}
	return images, nil
}

func (cmd *up) buildImage(spec composeTypes.BuildConfig, svc string) (string, error) {
	// If we've built the image already on a previous run, just use the cached
	// version.
	if !cmd.alwaysBuild {
		id, err := cmd.getCachedImage(svc)
		if err != nil && err != errNoCachedImage {
			log.WithError(err).WithField("service", svc).Warn("Failed to get cached image")
		} else if err == nil {
			return id, nil
		}
	}

	// Do a full image build.
	opts := types.ImageBuildOptions{
		Dockerfile:  spec.Dockerfile,
		Tags:        []string{cmd.getCachedImageName(svc)},
		AuthConfigs: cmd.regCreds,
		BuildArgs:   cmd.dockerConfig.ParseProxyConfig(cmd.dockerClient.DaemonHost(), spec.Args),
		Target:      spec.Target,
		Labels:      spec.Labels,
		CacheFrom:   spec.CacheFrom,
	}
	if opts.Dockerfile == "" {
		opts.Dockerfile = "Dockerfile"
	}

	buildContextTar, err := makeTar(spec.Context)
	if err != nil {
		return "", errors.WithContext("tar context", err)
	}

	buildResp, err := cmd.dockerClient.ImageBuild(context.TODO(), buildContextTar, opts)
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
		return "", errors.WithContext("build image", err)
	}

	return imageID, nil
}

func (cmd *up) pushImage(svc, imageID string) (string, error) {
	name := fmt.Sprintf("%s/%s:%s", cmd.imageNamespace, svc, strings.TrimPrefix(imageID, "sha256:"))
	if err := cmd.dockerClient.ImageTag(context.TODO(), imageID, name); err != nil {
		return "", errors.WithContext("tag image", err)
	}

	fmt.Printf("Pushing image for %s:\n", svc)

	registryAuth, err := makeRegistryAuthHeader(cmd.auth.AuthToken)
	if err != nil {
		return "", errors.WithContext("make registry auth header", err)
	}

	pushResp, err := cmd.dockerClient.ImagePush(context.TODO(), name, types.ImagePushOptions{
		RegistryAuth: registryAuth,
	})
	if err != nil {
		return "", errors.WithContext("start image push", err)
	}
	defer pushResp.Close()

	isTerminal := terminal.IsTerminal(int(os.Stderr.Fd()))
	err = jsonmessage.DisplayJSONMessagesStream(pushResp, os.Stderr, os.Stderr.Fd(), isTerminal, nil)
	if err != nil {
		return "", errors.WithContext("push image", err)
	}
	return name, nil
}

func (cmd *up) getCachedImage(svc string) (string, error) {
	cachedImageName := cmd.getCachedImageName(svc)
	opts := types.ImageListOptions{
		Filters: filters.NewArgs(filters.KeyValuePair{
			Key:   "reference",
			Value: cachedImageName,
		}),
	}
	images, err := cmd.dockerClient.ImageList(context.Background(), opts)
	if err != nil {
		return "", err
	}

	if len(images) != 1 {
		return "", errNoCachedImage
	}
	return images[0].ID, nil
}

func (cmd *up) getCachedImageName(svc string) string {
	tag := hash.DnsCompliant(fmt.Sprintf("%s-%s", cmd.composePath, svc))
	return fmt.Sprintf("blimp-cache:%s", tag)
}
