package up

import (
	"sync"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	composeTypes "github.com/kelda/compose-go/types"
	log "github.com/sirupsen/logrus"

	"github.com/kelda/blimp/pkg/auth"
	"github.com/kelda/blimp/pkg/build"
	"github.com/kelda/blimp/pkg/build/buildkit"
	"github.com/kelda/blimp/pkg/build/docker"
	"github.com/kelda/blimp/pkg/errors"
)

func (cmd *up) buildImages(composeFile composeTypes.Project) (map[string]string, error) {
	var buildServices composeTypes.Services
	for _, svc := range composeFile.Services {
		if svc.Build != nil {
			buildServices = append(buildServices, svc)
		}
	}

	if len(buildServices) == 0 {
		return map[string]string{}, nil
	}

	builtImages := cmd.getRemoteCachedImages(buildServices)

	builder, err := cmd.getImageBuilder(composeFile.Name)
	if err != nil {
		return nil, errors.WithContext("get image builder", err)
	}

	buildOpts := map[string]build.BuildPushConfig{}
	for _, svc := range buildServices {
		if !cmd.alwaysBuild {
			if _, ok := builtImages[svc.Name]; ok {
				log.Debugf("Using remote cache image for %s\n", svc.Name)
				continue
			}
		}

		imageName := build.RemoteImageName(cmd.composePath, svc.Name, cmd.imageNamespace)
		buildOpts[svc.Name] = build.BuildPushConfig{
			BuildConfig: *svc.Build,
			ImageName:   imageName,
			ForceBuild:  cmd.alwaysBuild,
		}
	}

	if len(buildOpts) == 0 {
		// All images are already present in the remote.
		return builtImages, nil
	}

	newBuiltImages, err := builder.BuildAndPush(buildOpts)
	if err != nil {
		return nil, errors.WithContext("build images", err)
	}
	for s, i := range newBuiltImages {
		builtImages[s] = i
	}

	return builtImages, nil
}

func (cmd *up) getImageBuilder(projectName string) (build.Interface, error) {
	if !cmd.forceBuildkit {
		dockerClient, err := docker.New(cmd.regCreds, cmd.dockerConfig, cmd.config.BlimpAuth(), docker.CacheOptions{
			ProjectName: projectName,
			ComposePath: cmd.composePath,
		})
		if err == nil {
			return dockerClient, nil
		}
		log.WithError(err).Debug("Failed to get Docker client for local builder. " +
			"Falling back to building remotely with buildkit")
	}

	buildkitClient, err := buildkit.New(cmd.tunnelManager, cmd.regCreds)
	if err != nil {
		return nil, errors.WithContext("create buildkit image builder", err)
	}
	return buildkitClient, nil
}

func (cmd *up) getRemoteCachedImages(services composeTypes.Services) map[string]string {
	if cmd.alwaysBuild {
		return map[string]string{}
	}

	regcred, err := auth.BlimpRegcred(cmd.config.BlimpAuth())
	if err != nil {
		log.WithError(err).Warn("Failed to generate Blimp registry credential")
		return map[string]string{}
	}

	var wg sync.WaitGroup
	var pushedImagesLock sync.Mutex
	pushedImages := map[string]string{}
	checkImageReqChan := make(chan string)

	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for service := range checkImageReqChan {
				imgName := build.RemoteImageName(cmd.composePath, service, cmd.imageNamespace)
				imageRef, err := name.NewTag(imgName)
				if err != nil {
					log.WithError(err).WithField("name", imgName).Debug("Failed to parse image name")
					continue
				}

				remoteImage, err := remote.Image(imageRef,
					remote.WithAuth(regcred.ToContainerRegistry()))
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

				digest, err := remoteImage.Digest()
				if err == nil {
					imgName = build.ReplaceTagWithDigest(imgName, digest.String())
				}

				pushedImagesLock.Lock()
				pushedImages[service] = imgName
				pushedImagesLock.Unlock()
			}
		}()
	}

	for _, svc := range services {
		checkImageReqChan <- svc.Name
	}
	close(checkImageReqChan)
	wg.Wait()

	return pushedImages
}
