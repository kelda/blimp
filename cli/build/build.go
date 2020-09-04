package build

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/docker/cli/cli/config"
	"github.com/docker/cli/cli/config/configfile"
	"github.com/docker/docker/api/types"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/kelda/blimp/cli/authstore"
	"github.com/kelda/blimp/cli/manager"
	"github.com/kelda/blimp/cli/util"
	"github.com/kelda/blimp/pkg/auth"
	"github.com/kelda/blimp/pkg/build"
	"github.com/kelda/blimp/pkg/build/buildkit"
	"github.com/kelda/blimp/pkg/build/docker"
	"github.com/kelda/blimp/pkg/dockercompose"
	"github.com/kelda/blimp/pkg/errors"
	"github.com/kelda/blimp/pkg/proto/cluster"
	"github.com/kelda/blimp/pkg/proto/node"
	"github.com/kelda/blimp/pkg/tunnel"
)

func New() *cobra.Command {
	var composePaths []string
	var pull bool
	var noCache bool
	var forceBuildkit bool
	cobraCmd := &cobra.Command{
		Use:   "build [OPTIONS] [SERVICE...]",
		Short: "Build or rebuild services.",
		Long: "Services are built once and then cached.\n" +
			"If you change a service's `Dockerfile` or the contents of its build directory, " +
			"you can run `blimp build` to rebuild it.",
		Run: func(_ *cobra.Command, services []string) {
			authConfig, err := authstore.New()
			if err != nil {
				log.WithError(err).Fatal("Failed to parse auth store")
			}

			if authConfig.AuthToken == "" {
				fmt.Fprintln(os.Stderr, "Not logged in. Please run `blimp login`.")
				return
			}

			dockerConfig, err := config.Load(config.Dir())
			if err != nil {
				log.WithError(err).Fatal("Failed to load docker config")
			}

			getNamespaceCtx, _ := context.WithTimeout(context.Background(), 30*time.Second)
			getImageNamespaceResp, err := manager.C.GetImageNamespace(getNamespaceCtx, &cluster.GetImageNamespaceRequest{Token: authConfig.AuthToken})
			if err != nil {
				log.WithError(err).Fatal("Failed to get development environment's image namespace")
			}
			imageNamespace := getImageNamespaceResp.GetNamespace()

			regCreds, err := auth.GetLocalRegistryCredentials(dockerConfig)
			if err != nil {
				// This can happen if the user does not have docker installed locally.
				log.WithError(err).Debug("Failed to get local registry credentials. Private images will fail to pull.")
				regCreds = map[string]types.AuthConfig{}
			}
			// Add the registry credentials for pushing to the blimp registry.
			regCreds[strings.SplitN(imageNamespace, "/", 2)[0]] = types.AuthConfig{
				Username: "ignored",
				Password: authConfig.AuthToken,
			}

			// Convert the compose path to an absolute path so that the code
			// that makes identifiers for bind volumes are unique for relative
			// paths.
			composePath, overridePaths, err := dockercompose.GetPaths(composePaths)
			if err != nil {
				if os.IsNotExist(err) {
					log.Fatal("Docker Compose file not found.\n" +
						"Blimp must be run from the same directory as docker-compose.yml.\n" +
						"If you don't have a docker-compose.yml, you can use one of our examples:\n" +
						"https://kelda.io/blimp/docs/examples/")
				}
				log.WithError(err).Fatal("Failed to get absolute path to Compose file")
			}

			parsedCompose, err := dockercompose.Load(composePath, overridePaths, services)
			if err != nil {
				log.WithError(err).Fatal("Failed to load compose file")
			}

			builder, err := getImageBuilder(regCreds, dockerConfig, authConfig.AuthToken, forceBuildkit)
			if err != nil {
				log.WithError(err).Fatal("Get image builder")
			}

			buildOpts := map[string]build.BuildPushConfig{}
			for _, svc := range parsedCompose.Services {
				if svc.Build == nil {
					log.Infof("%s uses an image, skipping\n", svc.Name)
					continue
				}

				imageName := build.RemoteImageName(composePath, svc.Name, imageNamespace)
				buildOpts[svc.Name] = build.BuildPushConfig{
					BuildConfig: *svc.Build,
					ImageName:   imageName,
					PullParent:  pull,
					NoCache:     noCache,
					ForceBuild:  true,
				}
			}

			_, err = builder.BuildAndPush(buildOpts)
			if err != nil {
				log.WithError(err).Warn("Failed to build services")
			}
		},
	}
	cobraCmd.Flags().StringSliceVarP(&composePaths, "file", "f", nil,
		"Specify an alternate compose file\nDefaults to docker-compose.yml and docker-compose.yaml")
	cobraCmd.Flags().BoolVarP(&pull, "pull", "", false,
		"Always attempt to pull a newer version of the image.")
	cobraCmd.Flags().BoolVarP(&noCache, "no-cache", "", false,
		"Do not use cache when building the image")
	cobraCmd.Flags().BoolVarP(&forceBuildkit, "remote-build", "", false,
		"Force Docker images to be built in your sandbox instead of locally")
	return cobraCmd
}

func getImageBuilder(regCreds auth.RegistryCredentials, dockerConfig *configfile.ConfigFile, authToken string, forceBuildkit bool) (build.Interface, error) {
	if !forceBuildkit {
		dockerClient, err := docker.New(regCreds, dockerConfig, authToken, docker.CacheOptions{})
		if err == nil {
			return dockerClient, nil
		}
		log.WithError(err).Debug("Failed to get Docker client for local builder. " +
			"Falling back to building remotely with buildkit")
	}

	// Get a connection to the remote buildkit container.
	pp := util.NewProgressPrinter(os.Stdout, "Booting remote Docker image builder")
	go pp.Run()
	ctx, _ := context.WithTimeout(context.Background(), 3*time.Minute)
	buildkitConn, err := manager.C.GetBuildkit(ctx, &cluster.GetBuildkitRequest{Token: authToken})
	pp.Stop()
	if err != nil {
		return nil, errors.WithContext("boot buildkit", err)
	}

	nodeConn, err := util.Dial(buildkitConn.NodeAddress, buildkitConn.NodeCert, "")
	if err != nil {
		return nil, errors.WithContext("connect to node controller", err)
	}
	tunnelManager := tunnel.NewManager(node.NewControllerClient(nodeConn), authToken)

	buildkitClient, err := buildkit.New(tunnelManager, regCreds)
	if err != nil {
		return nil, errors.WithContext("create buildkit image builder", err)
	}
	return buildkitClient, nil
}
