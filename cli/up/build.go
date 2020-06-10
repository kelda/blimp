package up

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/pkg/jsonmessage"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	composeTypes "github.com/kelda/compose-go/types"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh/terminal"

	"github.com/kelda-inc/blimp/pkg/errors"
	"github.com/kelda-inc/blimp/pkg/hash"
)

var errNoCachedImage = errors.New("no cached image")

// imageCacheRepo is the local image name used to tag built versions of images.
// Each cached image is identified by a tag appended to the imageCacheRepo.
const imageCacheRepo = "blimp-cache"

type image struct {
	// The ImageID of the image.
	id string

	// The name of the image (e.g. blimp-registry.kelda.io/namespace/web:id)
	name string
}

// buildImages builds the images referenced by services in the given Compose
// file. It builds all of the images first, and then tries to push them. When
// pushing, it first checks whether the image already exists remotely, and if
// it does, short circuits the push.
func (cmd *up) buildImages(composeFile composeTypes.Config) (map[string]string, error) {
	if cmd.dockerClient == nil {
		return nil, errors.New("no docker client")
	}

	images := map[string]image{}
	svcToImageName := map[string]string{}
	var imageNames []string
	for _, svc := range composeFile.Services {
		if svc.Build == nil {
			continue
		}

		imageID, err := cmd.buildImage(*svc.Build, svc.Name)
		if err != nil {
			return nil, errors.WithContext(fmt.Sprintf("build %s", svc.Name), err)
		}

		imageName := fmt.Sprintf("%s/%s:%s", cmd.imageNamespace, svc.Name,
			strings.TrimPrefix(imageID, "sha256:"))
		svcToImageName[svc.Name] = imageName
		images[svc.Name] = image{imageID, imageName}
		imageNames = append(imageNames, imageName)
	}

	// When pushing an image, we first check to see if the remote manifest
	// already exists. This is more efficient than doing a full image push
	// because we don't compare each individual layer.
	pushedImages := getPushedImages(imageNames, cmd.auth.AuthToken)
	for svc, img := range images {
		if _, exists := pushedImages[img]; exists {
			log.WithField("service", svc).Debug("Skipping push. Remote image already exists.")
			continue
		}

		fmt.Printf("Pushing image for %s:\n", svc)
		err := cmd.pushImage(img.id, img.name)
		if err != nil {
			return nil, errors.WithContext(fmt.Sprintf("push %s", img.name), err)
		}
	}

	return svcToImageName, nil
}

func (cmd *up) buildImage(spec composeTypes.BuildConfig, svc string) (string, error) {
	// If we've built the image already on a previous run, just use the cached
	// version.
	if !cmd.alwaysBuild {
		id, ok := getImage(cmd.cachedImages, cmd.getCachedImageName(svc))
		if ok {
			log.WithField("service", svc).
				WithField("id", id).
				Debug("Skipping build and using cached version")
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

	contextPath := filepath.Join(
		filepath.Dir(cmd.composePath),
		spec.Context)
	buildContextTar, err := makeTar(contextPath)
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
		return "", errors.NewFriendlyError(
			"Image build for %q failed. This is likely an error with the Dockerfile, rather than Blimp.\n"+
				"Make sure that the image successfully builds with `docker build`.\n\n"+
				"The full error was:\n%s", svc, err)
	}

	return imageID, nil
}

func (cmd *up) pushImage(imageID, remoteImageName string) error {
	if err := cmd.dockerClient.ImageTag(context.TODO(), imageID, remoteImageName); err != nil {
		return errors.WithContext("tag image", err)
	}

	registryAuth, err := makeRegistryAuthHeader(cmd.auth.AuthToken)
	if err != nil {
		return errors.WithContext("make registry auth header", err)
	}

	pushResp, err := cmd.dockerClient.ImagePush(context.TODO(), remoteImageName, types.ImagePushOptions{
		RegistryAuth: registryAuth,
	})
	if err != nil {
		return errors.WithContext("start image push", err)
	}
	defer pushResp.Close()

	isTerminal := terminal.IsTerminal(int(os.Stderr.Fd()))
	err = jsonmessage.DisplayJSONMessagesStream(pushResp, os.Stderr, os.Stderr.Fd(), isTerminal, nil)
	if err != nil {
		return errors.WithContext("push image", err)
	}
	return nil
}

func (cmd *up) getCachedImages() ([]types.ImageSummary, error) {
	opts := types.ImageListOptions{
		Filters: filters.NewArgs(filters.KeyValuePair{
			Key:   "reference",
			Value: fmt.Sprintf("%s:*", imageCacheRepo),
		}),
	}
	return cmd.dockerClient.ImageList(context.Background(), opts)
}

func (cmd *up) getCachedImageName(svc string) string {
	tag := hash.DnsCompliant(fmt.Sprintf("%s-%s", cmd.composePath, svc))
	return fmt.Sprintf("%s:%s", imageCacheRepo, tag)
}

func getImage(images []types.ImageSummary, exp string) (id string, ok bool) {
	for _, img := range images {
		for _, name := range img.RepoTags {
			if name == exp {
				return img.ID, true
			}
		}
	}
	return "", false
}

func getPushedImages(images []string, authToken string) map[image]struct{} {
	var wg sync.WaitGroup
	var pushedImagesLock sync.Mutex
	pushedImages := map[image]struct{}{}
	checkImageReqChan := make(chan string)

	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for imgName := range checkImageReqChan {
				imageRef, err := name.NewTag(imgName)
				if err != nil {
					log.WithError(err).WithField("name", imgName).Debug("Failed to parse image name")
					continue
				}

				img, err := remote.Image(imageRef,
					remote.WithAuth(&authn.Basic{Username: "ignored", Password: authToken}))
				if err != nil {
					isDoesNotExist := false
					if err, ok := err.(*transport.Error); ok {
						for _, code := range err.Errors {
							if code.Code == transport.ManifestUnknownErrorCode {
								isDoesNotExist = true
								break
							}
						}
					}

					if !isDoesNotExist {
						log.WithError(err).
							WithField("name", imgName).
							Debug("Failed to get remote image")
					}
					continue
				}

				imageID, err := img.ConfigName()
				if err != nil {
					log.WithError(err).WithField("name", imgName).Debug("Failed to get remote image ID")
					continue
				}

				pushedImagesLock.Lock()
				pushedImages[image{id: imageID.String(), name: imgName}] = struct{}{}
				pushedImagesLock.Unlock()
			}
		}()
	}

	for _, image := range images {
		checkImageReqChan <- image
	}
	close(checkImageReqChan)
	wg.Wait()

	return pushedImages
}
