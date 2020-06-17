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
	"github.com/moby/buildkit/frontend/dockerfile/instructions"
	dockerfileParser "github.com/moby/buildkit/frontend/dockerfile/parser"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh/terminal"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/kelda/blimp/cli/manager"
	"github.com/kelda/blimp/pkg/auth"
	"github.com/kelda/blimp/pkg/errors"
	"github.com/kelda/blimp/pkg/hash"
	"github.com/kelda/blimp/pkg/proto/cluster"
)

var errNoCachedImage = errors.New("no cached image")

// imageCacheRepo is the local image name used to tag built versions of images.
// Each cached image is identified by a tag appended to the imageCacheRepo.
const imageCacheRepo = "blimp-cache"

type baseImage struct {
	// imageName is the reference to push as the base image for a given service,
	// if the base image was able to be prepushed. It is "" if the base image
	// pre-push failed server-side.
	imageName string
	service   string
}

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

	var buildServices composeTypes.Services
	for _, svc := range composeFile.Services {
		if svc.Build != nil {
			buildServices = append(buildServices, svc)
		}
	}

	toPush := cmd.getServicesToPush(buildServices)

	readyToPush, err := cmd.prePushBaseImages(toPush)
	if err != nil {
		log.WithError(err).Debug("Failed to pre-push the base images. " +
			"Falling back to pushing full images.")
	}

	images := map[string]image{}
	svcToImageName := map[string]string{}
	for _, svc := range buildServices {
		imageID, err := cmd.buildImage(*svc.Build, svc.Name)
		if err != nil {
			return nil, errors.WithContext(fmt.Sprintf("build %s", svc.Name), err)
		}

		imageName := getImageName(cmd.imageNamespace, svc.Name, imageID)
		svcToImageName[svc.Name] = imageName
		images[svc.Name] = image{imageID, imageName}
	}

	// We expect each service to be sent exactly once, and we expect the channel
	// to be closed when all images have been signalled as ready to push.
	for base := range readyToPush {
		// If the imageName is empty, it means the base image pre-push failed.
		// Just fall back to pushing the full image.
		if base.imageName != "" {
			// Even though the base image has already been pushed by the cluster
			// manager, we need to locally push it to the same tag.  This is a
			// no-op (in that no layers will actually be pushed) but it lets the
			// local docker daemon know that these layers are already present on
			// the registry, so that they won't be pushed when we push the main
			// image.
			err = cmd.pushBaseTag(base.imageName, base.service)
			if err != nil {
				// Don't die.
				log.WithError(err).WithField("service", base.service).Warn("Push base image tag failed")
			}
		}

		img := images[base.service]
		fmt.Printf("Pushing image for %s:\n", base.service)
		err := cmd.pushServiceImage(img.id, img.name)
		if err != nil {
			return nil, errors.WithContext(fmt.Sprintf("push %s", img.name), err)
		}
	}

	return svcToImageName, nil
}

func (cmd *up) getServicesToPush(services composeTypes.Services) (toPush composeTypes.Services) {
	// We only need to check to see if cached images are pushed. If an image
	// isn't cached, it isn't built yet, so we're going to push it after
	// building.
	cachedImageNames := []string{}
	svcToCachedImage := map[string]string{}
	for _, svc := range services {
		id, ok := getImage(cmd.cachedImages, cmd.getCachedImageName(svc.Name))
		if ok {
			imageName := getImageName(cmd.imageNamespace, svc.Name, id)
			cachedImageNames = append(cachedImageNames, imageName)
			svcToCachedImage[svc.Name] = imageName
		}
	}

	// Before pushing an image, we first check to see if the remote manifest
	// already exists. This is more efficient than doing a full image push
	// because we don't compare each individual layer.
	pushedImages := getPushedImages(cachedImageNames, cmd.auth.AuthToken)
	for _, svc := range services {
		if _, ok := pushedImages[svcToCachedImage[svc.Name]]; !ok {
			toPush = append(toPush, svc)
		}
	}

	return toPush
}

// prePushBaseImages initiates the pre-push requests for the given services. It
// returns a channel which sends the names of services as their prepush finishes
// or fails.
func (cmd *up) prePushBaseImages(services composeTypes.Services) (<-chan baseImage, error) {
	// We should send each service on this channel exactly once, then exit.
	readyToPush := make(chan baseImage, len(services))

	// Keep track of which services still need to be sent over the channel, to
	// make sure they are all eventually sent. We will delete from this map as
	// we send.
	// This is not thread-safe, so only one thread should use it at a time.
	needToSend := map[string]struct{}{}
	for _, svc := range services {
		needToSend[svc.Name] = struct{}{}
	}
	ready := func(service, baseImageName string) {
		if _, ok := needToSend[service]; !ok {
			panic("tried to send same service over the channel twice")
		}
		delete(needToSend, service)
		readyToPush <- baseImage{imageName: baseImageName, service: service}
	}

	tagRequests := []*cluster.TagImageRequest{}
	baseImages := map[string]string{}

	for _, svc := range services {
		dockerfilePath := svc.Build.Dockerfile
		if dockerfilePath == "" {
			dockerfilePath = "Dockerfile"
		}

		baseImageName, err := cmd.getBaseImage(dockerfilePath)
		if err != nil {
			log.WithError(err).WithField("service", svc.Name).Warn("Failed to get base image from Dockerfile")
			ready(svc.Name, "")
			continue
		}

		if baseImageName == "scratch" {
			// "scratch" is not an actual image, it just indicates that this is
			// a base image and there is no parent image to push.
			ready(svc.Name, "")
			continue
		}

		baseImages[svc.Name] = baseImageName
		tagRequests = append(tagRequests, &cluster.TagImageRequest{
			Service: svc.Name,
			Image:   baseImageName,
			Tag:     remoteBaseTag(cmd.imageNamespace, svc.Name),
		})
	}

	if len(needToSend) == 0 {
		// There shouldn't be any tag requests, so don't bother making the RPC.
		close(readyToPush)
		return readyToPush, nil
	}

	tagStream, err := manager.C.TagImages(context.Background(), &cluster.TagImagesRequest{
		Token:               cmd.auth.AuthToken,
		TagRequests:         tagRequests,
		RegistryCredentials: registryCredentialsToProtobuf(cmd.regCreds),
	})
	if err != nil {
		return nil, errors.WithContext("send tag image request", err)
	}

	go func() {
		defer func() {
			// By the time we exit, we should have handled all the services.
			if len(needToSend) != 0 {
				panic("map should be empty")
			}
			close(readyToPush)
		}()

		for len(needToSend) > 0 {
			msg, err := tagStream.Recv()
			if err != nil {
				if status.Code(err) != codes.Canceled {
					log.WithError(err).Warn("Failed to watch for tagged image responses")
				}
				// Give up on any remaining images.
				for service := range needToSend {
					ready(service, "")
				}
				return
			}

			if msg.Error != nil {
				err = errors.Unmarshal(nil, msg.Error)
				log.WithError(err).WithField("service", msg.Service).Warn("Tag image failed")
			}

			// Whether we were successful or not, this image is ready to be
			// pushed.
			ready(msg.Service, baseImages[msg.Service])
		}
	}()

	return readyToPush, nil
}

func (cmd *up) getBaseImage(dockerfilePath string) (string, error) {
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
		return "", nil
	}

	baseImageName := stages[len(stages)-1].BaseName

	// Explicitly specify the image's digest if it's already pulled locally. If
	// the upstream tag has a newer digest, we want to cache the local version.
	// TODO: If the image we are going to push is already built, check the
	// digest actually used there. It could differ from the most recently pulled
	// image for this tag.
	localImages, err := cmd.dockerClient.ImageList(context.Background(), types.ImageListOptions{
		Filters: filters.NewArgs(filters.KeyValuePair{
			Key:   "reference",
			Value: baseImageName,
		}),
	})
	if err == nil && len(localImages) == 1 {
		// When ImageList is filtered by reference, it does not give
		// RepoDigests, so we have to use inspect to get them.
		localImage, _, err := cmd.dockerClient.ImageInspectWithRaw(context.Background(), localImages[0].ID)
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

func (cmd *up) buildImage(spec composeTypes.BuildConfig, svc string) (string, error) {
	// If we've built the image already on a previous run, just use the cached
	// version.
	id, ok := getImage(cmd.cachedImages, cmd.getCachedImageName(svc))
	if ok {
		log.WithField("service", svc).
			WithField("id", id).
			Debug("Skipping build and using cached version")
		return id, nil
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

func (cmd *up) pushBaseTag(localImage, service string) error {
	remoteTag := remoteBaseTag(cmd.imageNamespace, service)
	if err := cmd.dockerClient.ImageTag(context.TODO(), localImage, remoteTag); err != nil {
		return errors.WithContext("tag base image", err)
	}

	return cmd.pushImage(remoteTag)
}

func (cmd *up) pushServiceImage(imageID, remoteImageName string) error {
	if err := cmd.dockerClient.ImageTag(context.TODO(), imageID, remoteImageName); err != nil {
		return errors.WithContext("tag image", err)
	}

	return cmd.pushImage(remoteImageName)
}

func (cmd *up) pushImage(image string) error {
	registryAuth, err := auth.RegistryAuthHeader(cmd.auth.AuthToken)
	if err != nil {
		return errors.WithContext("make registry auth header", err)
	}

	pushResp, err := cmd.dockerClient.ImagePush(context.TODO(), image, types.ImagePushOptions{
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
	if cmd.alwaysBuild {
		// If alwaysBuild is true, we are going to rebuild everything anyway. We
		// should ignore all cached images.
		return []types.ImageSummary{}, nil
	}

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

func getPushedImages(images []string, authToken string) map[string]struct{} {
	var wg sync.WaitGroup
	var pushedImagesLock sync.Mutex
	pushedImages := map[string]struct{}{}
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

				_, err = remote.Image(imageRef,
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

				pushedImagesLock.Lock()
				pushedImages[imgName] = struct{}{}
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

func remoteBaseTag(namespace, svc string) string {
	return fmt.Sprintf("%s/%s:base", namespace, svc)
}

func getImageName(namespace, name, id string) string {
	return fmt.Sprintf("%s/%s:%s", namespace, name,
		strings.TrimPrefix(id, "sha256:"))
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
