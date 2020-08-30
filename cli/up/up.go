package up

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/docker/cli/cli/config"
	"github.com/docker/cli/cli/config/configfile"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	composeTypes "github.com/kelda/compose-go/types"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	corev1 "k8s.io/api/core/v1"

	"github.com/kelda/blimp/cli/authstore"
	"github.com/kelda/blimp/cli/down"
	"github.com/kelda/blimp/cli/logs"
	"github.com/kelda/blimp/cli/manager"
	"github.com/kelda/blimp/cli/util"
	"github.com/kelda/blimp/pkg/analytics"
	"github.com/kelda/blimp/pkg/cfgdir"
	"github.com/kelda/blimp/pkg/docker"
	"github.com/kelda/blimp/pkg/dockercompose"
	"github.com/kelda/blimp/pkg/errors"
	"github.com/kelda/blimp/pkg/proto/cluster"
	"github.com/kelda/blimp/pkg/proto/node"
	"github.com/kelda/blimp/pkg/syncthing"
	"github.com/kelda/blimp/pkg/tunnel"
)

func New() *cobra.Command {
	var composePaths []string
	var alwaysBuild bool
	var detach bool
	cobraCmd := &cobra.Command{
		Use:   "up [options] [SERVICE...]",
		Short: "Create and start containers",
		Long: "Create and start containers\n\n" +
			"Up boots the docker-compose.yml in the current directory. " +
			"If service are specified, `up` boots the services, as well as their dependencies.",
		Run: func(_ *cobra.Command, services []string) {
			auth, err := authstore.New()
			if err != nil {
				log.WithError(err).Fatal("Failed to parse local authentication store")
			}

			// TODO: Prompt to login again if token is expired.
			if auth.AuthToken == "" {
				fmt.Fprintln(os.Stderr, "Not logged in. Please run `blimp login`.")
				os.Exit(1)
			}

			globalConfig, err := cfgdir.ParseConfig()
			if err != nil {
				log.WithError(err).Fatal("Failed to read blimp config")
			}

			cmd := up{
				auth:         auth,
				globalConfig: globalConfig,
				alwaysBuild:  alwaysBuild,
				detach:       detach,
			}

			dockerClient, err := util.GetDockerClient()
			if err == nil {
				cmd.dockerClient = dockerClient
			} else {
				log.WithError(err).Warn("Failed to connect to local Docker daemon. " +
					"Building images won't work, but all other features will.")
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

			cmd.composePath = composePath
			cmd.overridePaths = overridePaths
			//import the docker config
			cfg, err := config.Load(config.Dir())
			if err != nil {
				log.WithError(err).Fatal("Failed to load docker config")
			}

			cmd.dockerConfig = cfg
			if err := cmd.run(services); err != nil {
				errors.HandleFatalError(err)
			}
		},
	}
	cobraCmd.Flags().StringSliceVarP(&composePaths, "file", "f", nil,
		"Specify an alternate compose file\nDefaults to docker-compose.yml and docker-compose.yaml")
	cobraCmd.Flags().BoolVarP(&alwaysBuild, "build", "", false,
		"Build images before starting containers")
	cobraCmd.Flags().BoolVarP(&detach, "detach", "d", false,
		"Leave containers running after blimp up exits")
	return cobraCmd
}

type up struct {
	auth           authstore.Store
	globalConfig   cfgdir.Config
	composePath    string
	overridePaths  []string
	alwaysBuild    bool
	detach         bool
	dockerClient   *client.Client
	dockerConfig   *configfile.ConfigFile
	regCreds       map[string]types.AuthConfig
	imageNamespace string

	// The images in the image cache from previous Blimp runs.
	cachedImages []types.ImageSummary

	nodeControllerConn   *grpc.ClientConn
	nodeControllerClient node.ControllerClient
	tunnelManager        tunnel.Manager
}

func (cmd *up) run(services []string) error {
	// TODO: Make locking atomic. Currently there could be TOCTTOU problems.
	if util.UpRunning() {
		fmt.Printf("It looks like `blimp up` is already running.\n" +
			"Are you sure you want to continue, even though things might break? (y/N) ")
		var response string
		num, err := fmt.Scanln(&response)
		if err != nil || num != 1 ||
			(strings.ToLower(response) != "y" && strings.ToLower(response) != "yes") {
			fmt.Printf("Aborting.\n")
			os.Exit(1)
		}
	}

	err := util.TakeUpLock()
	if err != nil {
		return err
	}
	defer util.ReleaseUpLock()

	parsedCompose, err := dockercompose.Load(cmd.composePath, cmd.overridePaths, services)
	if err != nil {
		return errors.WithContext("load compose file", err)
	}

	parsedComposeBytes, err := dockercompose.Marshal(parsedCompose)
	if err != nil {
		return err
	}

	stClient := cmd.makeSyncthingClient(parsedCompose)
	idPathMap := stClient.GetIDPathMap()

	regCreds, err := docker.GetLocalRegistryCredentials(cmd.dockerConfig)
	if err != nil {
		log.WithError(err).Debug("Failed to get local registry credentials. Private images will fail to pull.")
		regCreds = map[string]types.AuthConfig{}
	}
	cmd.regCreds = regCreds

	// Start creating the sandbox immediately so that the systems services
	// start booting as soon as possible.
	if err := cmd.createSandbox(string(parsedComposeBytes), idPathMap); err != nil {
		log.WithError(err).Fatal("Failed to create development sandbox")
	}
	defer cmd.nodeControllerConn.Close()

	cachedImages, err := cmd.getCachedImages()
	if err == nil {
		cmd.cachedImages = cachedImages
	} else {
		log.WithError(err).Debug("Failed to get cached images")
	}

	builtImages, err := cmd.buildImages(parsedCompose)
	if err != nil {
		return err
	}

	// Send the boot request to the cluster manager.
	pp := util.NewProgressPrinter(os.Stdout, "Deploying Docker Compose file to sandbox")
	go pp.Run()

	_, err = manager.C.DeployToSandbox(context.Background(), &cluster.DeployRequest{
		Token:       cmd.auth.AuthToken,
		ComposeFile: string(parsedComposeBytes),
		BuiltImages: builtImages,
	})
	pp.Stop()
	if err != nil {
		return err
	}

	syncthingError := make(chan error, 1)
	syncthingCtx, cancelSyncthing := context.WithCancel(context.Background())
	defer cancelSyncthing()
	if len(idPathMap) != 0 {
		go func() {
			defer close(syncthingError)

			output, err := stClient.Run(syncthingCtx, cmd.nodeControllerClient, cmd.auth.AuthToken, cmd.tunnelManager)
			select {
			// We intentionally killed the Syncthing process, so exiting was expected.
			case <-syncthingCtx.Done():
				return

			// Syncthing crashed prematurely.
			default:
				if err != nil {
					syncthingError <- errors.WithContext(fmt.Sprintf("syncthing crashed (%s)", string(output)), err)
				} else {
					syncthingError <- errors.New("syncthing crashed")
				}
			}
		}()
	}

	// Start the tunnels.
	var tunnelsErrGroup errgroup.Group
	startedTunnels := false
	for _, svc := range parsedCompose.Services {
		svc := svc
		for _, mapping := range svc.Ports {
			mapping := mapping
			if mapping.Protocol == "tcp" {
				startedTunnels = true
				tunnelsErrGroup.Go(func() error {
					return cmd.tunnelManager.Run(mapping.HostIP, mapping.Published, svc.Name, mapping.Target, nil)
				})
			}
		}
	}
	tunnelsError := make(chan error, 1)
	if startedTunnels {
		go func() {
			tunnelsError <- tunnelsErrGroup.Wait()
		}()
	}

	// Start the GUI.
	guiCtx, cancelGui := context.WithCancel(context.Background())
	guiError := make(chan error, 1)
	go func() {
		guiError <- cmd.runGUI(guiCtx, parsedCompose)
	}()

	// Wait for the user to exit, or for something to error.
	exit := make(chan os.Signal, 1)
	signal.Notify(exit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-syncthingError:
		return errors.WithContext("syncthing error", err)

	case err := <-guiError:
		if err != nil {
			return errors.WithContext("run gui error", err)
		}
		log.Info("All containers have completed. Exiting.")
		return nil

	case err := <-tunnelsError:
		return errors.WithContext("tunnel crashed", err)

	case <-exit:
		cancelGui()

		if cmd.detach {
			fmt.Println("Cleaning up local processes. The remote containers will continue running.")
			fmt.Println("Use `blimp down` to clean up your remote sandbox.")
		}

		// If we spawned a child process for Syncthing, terminate it gracefully.
		if len(idPathMap) != 0 {
			cancelSyncthing()
			<-syncthingError
		}

		if !cmd.detach {
			fmt.Println("Cleaning up your containers and volumes.")
			fmt.Println("To keep your sandbox running, use `blimp up -d` instead.\n")

			downFinished := make(chan error)
			go func() {
				downFinished <- down.Run(cmd.auth.AuthToken, false)
			}()

			select {
			case err := <-downFinished:
				return err
			case <-exit:
				// This is the second signal, so we exit immediately without
				// waiting for `blimp down` to finish. We exit naturally without
				// `os.Exit` so that the lock is released.
			}
		}
		return nil
	}
	return nil
}

func (cmd *up) createSandbox(composeCfg string, idPathMap map[string]string) error {
	pp := util.NewProgressPrinter(os.Stdout, "Booting cloud sandbox")
	go pp.Run()
	defer pp.Stop()

	resp, err := manager.C.CreateSandbox(context.TODO(),
		&cluster.CreateSandboxRequest{
			Token:               cmd.auth.AuthToken,
			ComposeFile:         composeCfg,
			RegistryCredentials: registryCredentialsToProtobuf(cmd.regCreds),
			SyncedFolders:       idPathMap,
		})
	if err != nil {
		return err
	}

	if resp.Message != "" {
		fmt.Printf("\n" + resp.Message)
	}

	switch resp.Action {
	case cluster.CLIAction_OK:
	case cluster.CLIAction_EXIT:
		os.Exit(1)
	default:
		os.Exit(1)
	}

	cmd.nodeControllerConn, err = util.Dial(resp.NodeAddress, resp.NodeCert, "")
	if err != nil {
		return errors.WithContext("connect to node controller", err)
	}
	cmd.nodeControllerClient = node.NewControllerClient(cmd.nodeControllerConn)
	cmd.tunnelManager = tunnel.NewManager(cmd.nodeControllerClient, cmd.auth.AuthToken)

	cmd.imageNamespace = resp.ImageNamespace

	// Save the Kubernetes API credentials for use by other Blimp commands.
	kubeCreds := resp.GetKubeCredentials()
	cmd.auth.KubeToken = kubeCreds.Token
	cmd.auth.KubeHost = kubeCreds.Host
	cmd.auth.KubeCACrt = kubeCreds.CaCrt
	cmd.auth.KubeNamespace = kubeCreds.Namespace

	// Apply any overrides from the user's local config.
	if cmd.globalConfig.KubeHost != "" {
		cmd.auth.KubeHost = cmd.globalConfig.KubeHost
	}
	if err := cmd.auth.Save(); err != nil {
		return err
	}
	return nil
}

func (cmd *up) runGUI(ctx context.Context, parsedCompose composeTypes.Project) error {
	services := parsedCompose.ServiceNames()
	statusPrinter := newStatusPrinter(services)
	if !statusPrinter.Run(ctx, manager.C, cmd.auth.AuthToken) {
		return nil
	}
	analytics.Log.Info("Containers booted")

	return logs.Command{
		Services: services,
		Opts:     corev1.PodLogOptions{Follow: true},
		Auth:     cmd.auth,
	}.Run(ctx)
}

func (cmd *up) makeSyncthingClient(dcCfg composeTypes.Project) syncthing.Client {
	var allVolumes []syncthing.BindVolume
	for _, svc := range dcCfg.Services {
		// bindVolumes maps target paths (the paths to be mounted in the
		// container) to syncthing.BindVolume structs that represent the
		// necessary syncing information.
		bindVolumes := map[string]syncthing.BindVolume{}
		// First, collect all the synced bindVolumes.
		for _, v := range svc.Volumes {
			if v.Type != composeTypes.VolumeTypeBind {
				continue
			}
			bindVolumes[v.Target] = syncthing.BindVolume{
				LocalPath: v.Source,
			}
		}

		// Now, mask off any native volumes that fall under these mounts.
		for _, v := range svc.Volumes {
			// Theoretically this could match other types of volumes like tmpfs,
			// although we don't support these yet.
			if v.Type == composeTypes.VolumeTypeBind {
				continue
			}

			// Search through existing mounts for this service to see which need
			// Masks.
			for bindTarget, volume := range bindVolumes {
				relPath, err := filepath.Rel(bindTarget, v.Target)
				if err != nil || strings.HasPrefix(relPath, "..") {
					// This native volume does not fall under the bind volume.
					continue
				}

				volume.Masks = append(volume.Masks, relPath)
				bindVolumes[bindTarget] = volume
			}
		}

		for _, volume := range bindVolumes {
			allVolumes = append(allVolumes, volume)
		}
	}

	for _, namedVol := range dcCfg.Volumes {
		source, ok := dockercompose.ParseNamedBindVolume(namedVol)

		if ok {
			allVolumes = append(allVolumes, syncthing.BindVolume{LocalPath: source})
		}
	}

	return syncthing.NewClient(allVolumes)
}

func registryCredentialsToProtobuf(creds map[string]types.AuthConfig) map[string]*cluster.RegistryCredential {
	pb := map[string]*cluster.RegistryCredential{}
	for host, cred := range creds {
		pb[host] = &cluster.RegistryCredential{
			Username: cred.Username,
			Password: cred.Password,
		}
	}
	return pb
}
