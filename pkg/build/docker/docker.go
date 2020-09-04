package docker

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/docker/cli/cli/config/configfile"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	docker "github.com/docker/docker/client"
	"github.com/docker/docker/pkg/jsonmessage"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh/terminal"

	"github.com/kelda/blimp/cli/util"
	"github.com/kelda/blimp/pkg/auth"
	"github.com/kelda/blimp/pkg/build"
	"github.com/kelda/blimp/pkg/errors"
)

type client struct {
	client       *docker.Client
	regCreds     auth.RegistryCredentials
	dockerConfig *configfile.ConfigFile
	blimpToken   string

	// Cache state
	composePath        string
	oldBlimpImageCache map[string]types.ImageSummary
	composeImageCache  map[string]types.ImageSummary
}

type CacheOptions struct {
	Disable     bool
	ProjectName string
	ComposePath string
}

func New(regCreds auth.RegistryCredentials, dockerConfig *configfile.ConfigFile, blimpToken string, cacheOpts CacheOptions) (build.Interface, error) {
	dockerClient, err := getDockerClient()
	if err != nil {
		return nil, err
	}

	c := client{
		client:       dockerClient,
		regCreds:     regCreds,
		dockerConfig: dockerConfig,
		blimpToken:   blimpToken,
	}

	if !cacheOpts.Disable {
		c.composePath = cacheOpts.ComposePath
		oldBlimpImageCache, composeImageCache, err := getImageCaches(dockerClient, cacheOpts.ProjectName)
		if err == nil {
			c.oldBlimpImageCache = oldBlimpImageCache
			c.composeImageCache = composeImageCache
		} else {
			log.WithError(err).Debug("Failed to get compose image cache")
		}
	}

	return c, nil
}

func (c client) BuildAndPush(images map[string]build.BuildPushConfig) (pushedImages map[string]string, err error) {
	pushedImages = map[string]string{}

	prePushChan := make(chan prePushResult)
	prePushErr := make(chan error)
	go func() {
		prePushErr <- pushBaseImages(c.client, c.blimpToken, c.regCreds, images, prePushChan)
	}()

	// needToPush keeps track of which images still need to be pushed to the
	// registry. We will delete service names from this map as they are pushed.
	needToPush := map[string]struct{}{}
	for service := range images {
		needToPush[service] = struct{}{}
	}

	// Build all the services.
	for serviceName, opts := range images {
		needToBuild := true

		// If the image is in the docker cache, then just tag it to be imageName
		// rather than doing a full build.
		if !opts.ForceBuild {
			cached, ok := c.getCachedImage(serviceName)
			if ok {
				log.WithField("service", serviceName).Info("Using cached image")
				if err := c.client.ImageTag(context.Background(), cached.ID, opts.ImageName); err != nil {
					return nil, errors.WithContext("tag", err)
				}
				needToBuild = false
			}
		}

		if needToBuild {
			if err := c.build(serviceName, opts.ImageName, opts); err != nil {
				return nil, errors.WithContext("build", err)
			}
		}
	}

	// Wait for prepushes to complete. If prepush isn't complete yet, indiciate
	// that we're waiting for it to finish.
	for {
		var result prePushResult
		var ok bool
		select {
		case result, ok = <-prePushChan:
		default:
			pp := util.NewProgressPrinter(os.Stdout, "Waiting for base image to be uploaded")
			go pp.Run()
			result, ok = <-prePushChan
			pp.Stop()
		}

		if !ok {
			break
		}

		if result.err != nil {
			log.WithField("service", result.service).WithError(result.err).Debug("Prepush failed. Proceeding with a full image push")
		}

		imageName := images[result.service].ImageName

		// Push the rest of the layers.
		digest, err := c.push(imageName)
		if err != nil {
			return nil, errors.WithContext("push image after pre-push", err)
		}
		pushedImages[result.service] = build.ReplaceTagWithDigest(imageName, digest)
		delete(needToPush, result.service)
	}

	err = <-prePushErr
	if err != nil {
		// This should probably not be fatal, but we wouldn't expect it to happen.
		log.WithError(err).Warn("Pre-push server call failed unexpectedly. Continuing anyways")
	}

	// Push any images that were not prepushed.
	for service := range needToPush {
		imageName := images[service].ImageName
		digest, err := c.push(imageName)
		if err != nil {
			return nil, errors.WithContext("push image without pre-push", err)
		}
		pushedImages[service] = build.ReplaceTagWithDigest(imageName, digest)
	}

	return pushedImages, nil
}

func (c *client) build(serviceName, imageName string, opts build.BuildPushConfig) error {
	fmt.Printf("Building image for %s...\n", serviceName)
	buildContextTar, err := makeTar(opts.Context)
	if err != nil {
		return errors.WithContext("tar context", err)
	}

	buildResp, err := c.client.ImageBuild(context.TODO(), buildContextTar, types.ImageBuildOptions{
		Tags:        []string{imageName},
		Dockerfile:  opts.Dockerfile,
		AuthConfigs: c.regCreds,
		BuildArgs:   c.dockerConfig.ParseProxyConfig(c.client.DaemonHost(), opts.Args),
		Target:      opts.Target,
		Labels:      opts.Labels,
		CacheFrom:   opts.CacheFrom,
		PullParent:  opts.PullParent,
		NoCache:     opts.NoCache,
	})
	if err != nil {
		return errors.WithContext("start build", err)
	}
	defer buildResp.Body.Close()

	// Block until the build completes, and return any errors that happen
	// during the build.
	isTerminal := terminal.IsTerminal(int(os.Stdout.Fd()))
	err = jsonmessage.DisplayJSONMessagesStream(buildResp.Body, os.Stdout, os.Stdout.Fd(), isTerminal, nil)
	if err != nil {
		return errors.NewFriendlyError(
			"Image build for %q failed. This is likely an error with the Dockerfile, rather than Blimp.\n"+
				"Make sure that the image successfully builds with `docker build`.\n\n"+
				"The full error was:\n%s", serviceName, err)
	}
	return nil
}

func (c *client) push(image string) (string, error) {
	cred, ok := c.regCreds.LookupByImage(image)
	if !ok {
		return "", errors.New("no credentials for pushing image")
	}

	registryAuth, err := auth.RegistryAuthHeader(cred)
	if err != nil {
		return "", err
	}

	fmt.Printf("Pushing %s...\n", image)
	pushResp, err := c.client.ImagePush(context.Background(), image, types.ImagePushOptions{
		RegistryAuth: registryAuth,
	})
	if err != nil {
		return "", errors.WithContext("start image push", err)
	}
	defer pushResp.Close()

	var imageDigest string
	callback := func(msg jsonmessage.JSONMessage) {
		var digest struct{ Digest string }
		if err := json.Unmarshal(*msg.Aux, &digest); err != nil {
			log.WithError(err).Warn("Failed to parse digest")
			return
		}

		if digest.Digest != "" {
			imageDigest = digest.Digest
		}
	}
	isTerminal := terminal.IsTerminal(int(os.Stdout.Fd()))
	err = jsonmessage.DisplayJSONMessagesStream(pushResp, os.Stdout, os.Stdout.Fd(), isTerminal, callback)
	return imageDigest, err
}

// getDockerClient gets a Docker client, and validates that the server will
// respond to requests. If we're running in WSL, we try to connect to the
// default Docker location, and to localhost:2375 (which we recommend as a
// workaround in our docs).
func getDockerClient() (*docker.Client, error) {
	dockerClient, err := docker.NewClientWithOpts(docker.FromEnv, docker.WithAPIVersionNegotiation())
	if err != nil {
		return nil, errors.WithContext("create docker client", err)
	}

	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	_, err = dockerClient.Ping(ctx)
	if err == nil {
		// We successfully connected to the Docker daemon, so we're pretty
		// confident it's running and works.
		return dockerClient, nil
	}
	if !docker.IsErrConnectionFailed(err) {
		return nil, errors.WithContext("docker ping failed", err)
	}

	// If connection failed, Docker is probably not available at the default
	// address.

	// If a custom host is set, don't try any funny business.
	if dockerClient.DaemonHost() != docker.DefaultDockerHost {
		return nil, errors.WithContext("docker ping failed", err)
	}

	// If we're in WSL, see if we should use the TCP socket instead.
	procVersion, err := ioutil.ReadFile("/proc/version")
	if err != nil || !strings.Contains(string(procVersion), "Microsoft") {
		// Not WSL, so we just give up.
		return nil, errors.WithContext("docker ping failed", err)
	}

	dockerClient, err = docker.NewClientWithOpts(docker.FromEnv, docker.WithAPIVersionNegotiation(),
		docker.WithHost("tcp://localhost:2375"))
	if err != nil {
		return nil, errors.WithContext("create WSL TCP docker client", err)
	}

	ctx, _ = context.WithTimeout(context.Background(), 5*time.Second)
	_, err = dockerClient.Ping(ctx)
	return dockerClient, err
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

func getImageCaches(c *docker.Client, project string) (map[string]types.ImageSummary, map[string]types.ImageSummary, error) {
	// See https://github.com/docker/compose/blob/854c14a5bcf566792ee8a972325c37590521656b/compose/service.py#L379
	ctx, _ := context.WithTimeout(context.Background(), 30*time.Second)
	opts := types.ImageListOptions{
		Filters: filters.NewArgs(filters.KeyValuePair{
			Key: "reference",
			// This will match images built by previous versions of Blimp.
			Value: "blimp-cache:*",
		}, filters.KeyValuePair{
			Key: "reference",
			// This will match images built by Docker Compose.
			Value: fmt.Sprintf("%s_*:latest", project),
		}),
	}
	images, err := c.ImageList(ctx, opts)
	if err != nil {
		return nil, nil, err
	}

	oldBlimpCache := map[string]types.ImageSummary{}
	for _, image := range images {
		for _, tag := range image.RepoTags {
			if strings.HasPrefix(tag, "blimp-cache:") {
				oldBlimpCache[strings.TrimPrefix(tag, "blimp-cache:")] = image
			}
		}
	}

	composeCache := map[string]types.ImageSummary{}
	for _, image := range images {
		for _, tag := range image.RepoTags {
			prefix := project + "_"
			suffix := ":latest"
			if !strings.HasPrefix(tag, prefix) || !strings.HasSuffix(tag, suffix) {
				continue
			}
			composeCache[strings.TrimPrefix(strings.TrimSuffix(tag, suffix), prefix)] = image
		}
	}
	return oldBlimpCache, composeCache, nil
}

func (c *client) getCachedImage(service string) (types.ImageSummary, bool) {
	// Try the old Blimp cache first.
	tag := build.BlimpServiceTag(c.composePath, service)
	image, ok := c.oldBlimpImageCache[tag]
	if ok {
		return image, true
	}

	// Try Docker Compose's cache.
	image, ok = c.composeImageCache[service]
	return image, ok
}
