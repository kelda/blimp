package docker

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	docker "github.com/docker/docker/client"
	"github.com/moby/buildkit/frontend/dockerfile/instructions"
	dockerfileParser "github.com/moby/buildkit/frontend/dockerfile/parser"

	"github.com/kelda/blimp/cli/manager"
	"github.com/kelda/blimp/pkg/auth"
	"github.com/kelda/blimp/pkg/build"
	"github.com/kelda/blimp/pkg/errors"
	"github.com/kelda/blimp/pkg/proto/cluster"
)

type prePushResult struct {
	service string
	err     error
}

func pushBaseImages(dockerClient *docker.Client, blimpToken string, regCreds auth.RegistryCredentials,
	images map[string]build.BuildPushConfig, resultsChan chan<- prePushResult) error {
	defer close(resultsChan)

	var tagRequests []*cluster.TagImageRequest

	for service, opts := range images {
		baseImageName, err := getBaseImage(dockerClient, filepath.Join(opts.Context, opts.Dockerfile))
		if err != nil {
			return errors.WithContext("get base image name", err)
		}

		if baseImageName == "scratch" {
			// "scratch" is not an actual image, it just indicates that this is
			// a base image and there is no parent image to push.
			return nil
		}

		tagRequests = append(tagRequests, &cluster.TagImageRequest{
			Service: service,
			Image:   baseImageName,
			Tag:     replaceTag(opts.ImageName, "base"),
		})
	}

	if len(tagRequests) == 0 {
		return nil
	}

	tagStream, err := manager.C.TagImages(context.Background(), &cluster.TagImagesRequest{
		Token:               blimpToken,
		TagRequests:         tagRequests,
		RegistryCredentials: regCreds.ToProtobuf(),
	})
	if err != nil {
		return errors.WithContext("start tag", err)
	}

	for {
		msg, err := tagStream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return errors.WithContext("get tag result", err)
		}

		resultsChan <- prePushResult{
			service: msg.Service,
			err:     errors.Unmarshal(nil, msg.Error),
		}
	}
}

func getBaseImage(dockerClient *docker.Client, dockerfilePath string) (string, error) {
	f, err := os.Open(dockerfilePath)
	if err != nil {
		return "", errors.WithContext("open dockerfile", err)
	}
	defer f.Close()

	dockerfileTree, err := dockerfileParser.Parse(f)
	if err != nil {
		return "", errors.WithContext("load dockerfile", err)
	}

	stages, _, err := instructions.Parse(dockerfileTree.AST)
	if err != nil {
		return "", errors.WithContext("parse dockerfile", err)
	}

	if len(stages) == 0 {
		return "", errors.New("no base image")
	}

	baseImageName := stages[len(stages)-1].BaseName

	// Explicitly specify the image's digest if it's already pulled locally. If
	// the upstream tag has a newer digest, we want to cache the local version.
	// TODO: If the image we are going to push is already built, check the
	// digest actually used there. It could differ from the most recently pulled
	// image for this tag.
	ctx, _ := context.WithTimeout(context.Background(), 30*time.Second)
	localImages, err := dockerClient.ImageList(ctx, types.ImageListOptions{
		Filters: filters.NewArgs(filters.KeyValuePair{
			Key:   "reference",
			Value: baseImageName,
		}),
	})
	if err == nil && len(localImages) == 1 {
		// When ImageList is filtered by reference, it does not give
		// RepoDigests, so we have to use inspect to get them.
		localImage, _, err := dockerClient.ImageInspectWithRaw(ctx, localImages[0].ID)
		if err == nil {
			baseImageNoTag := stripTagFromImageURL(baseImageName)

			for _, repoDigest := range localImage.RepoDigests {
				// We look for a RepoDigest that matches the base image
				// specified in the Dockerfile, as we'd expect this one to be
				// pullable. (Other RepoDigests could be present, but we ignore
				// them.)
				// TODO: I don't think this is supported for v1 schema images.
				repoDigestParts := strings.Split(repoDigest, "@")
				if len(repoDigestParts) == 2 && stripTagFromImageURL(repoDigest) == baseImageNoTag {
					return injectDigestIntoImageURL(baseImageName, repoDigestParts[1]), nil
				}
			}
		}
	}
	return baseImageName, nil
}

func stripTagFromImageURL(imageURL string) string {
	if atIndex := strings.Index(imageURL, "@"); atIndex != -1 {
		imageURL = imageURL[:atIndex]
	}
	if colonIndex := strings.Index(imageURL, ":"); colonIndex != -1 {
		imageURL = imageURL[:colonIndex]
	}
	return imageURL
}

// injectDigestIntoImageURL strips the original tag or digest (if any) in an
// image URL and appends a new digest to it.
func injectDigestIntoImageURL(imageURL, newDigest string) string {
	return fmt.Sprintf("%s@%s", stripTagFromImageURL(imageURL), newDigest)
}

func replaceTag(imageURL, tag string) string {
	return fmt.Sprintf("%s:%s", stripTagFromImageURL(imageURL), tag)
}
