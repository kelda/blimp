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
	composeTypes "github.com/kelda/compose-go/types"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	corev1 "k8s.io/api/core/v1"

	cliConfig "github.com/kelda/blimp/cli/config"
	"github.com/kelda/blimp/cli/down"
	"github.com/kelda/blimp/cli/logs"
	"github.com/kelda/blimp/cli/manager"
	"github.com/kelda/blimp/cli/util"
	"github.com/kelda/blimp/pkg/analytics"
	"github.com/kelda/blimp/pkg/auth"
	"github.com/kelda/blimp/pkg/dockercompose"
	"github.com/kelda/blimp/pkg/errors"
	"github.com/kelda/blimp/pkg/proto/cluster"
	"github.com/kelda/blimp/pkg/proto/node"
	"github.com/kelda/blimp/pkg/syncthing"
	"github.com/kelda/blimp/pkg/tunnel"
)

func New() *cobra.Command {
	var composePaths []string
	var cmd up
	cobraCmd := &cobra.Command{
		Use:   "up [options] [SERVICE...]",
		Short: "Create and start containers",
		Long: "Create and start containers\n\n" +
			"Up boots the docker-compose.yml in the current directory. " +
			"If service are specified, `up` boots the services, as well as their dependencies.",
		Run: func(_ *cobra.Command, services []string) {
			blimpConfig, err := cliConfig.GetConfig()
			if err != nil {
				errors.HandleFatalError(err)
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

			dockerConfig, err := config.Load(config.Dir())
			if err != nil {
				log.WithError(err).Fatal("Failed to load docker config")
			}

			cmd.composePath = composePath
			cmd.overridePaths = overridePaths
			cmd.dockerConfig = dockerConfig
			cmd.config = blimpConfig
			if err := cmd.run(services); err != nil {
				errors.HandleFatalError(err)
			}
		},
	}
	cobraCmd.Flags().StringSliceVarP(&composePaths, "file", "f", nil,
		"Specify an alternate compose file\nDefaults to docker-compose.yml and docker-compose.yaml")
	cobraCmd.Flags().BoolVarP(&cmd.alwaysBuild, "build", "", false,
		"Build images before starting containers")
	cobraCmd.Flags().BoolVarP(&cmd.detach, "detach", "d", false,
		"Leave containers running after blimp up exits")
	cobraCmd.Flags().BoolVarP(&cmd.forceBuildkit, "remote-build", "", false,
		"Force Docker images to be built in your sandbox instead of locally")

	cobraCmd.Flags().BoolVarP(&cmd.disableStatusOutput, "disable-status-output", "", false,
		"Don't print status updates. Used by preview implementation.")
	if err := cobraCmd.Flags().MarkHidden("disable-status-output"); err != nil {
		panic(err)
	}

	return cobraCmd
}

type up struct {
	config              cliConfig.Config
	composePath         string
	overridePaths       []string
	alwaysBuild         bool
	detach              bool
	forceBuildkit       bool
	disableStatusOutput bool
	dockerConfig        *configfile.ConfigFile
	regCreds            auth.RegistryCredentials
	imageNamespace      string

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

	regCreds, err := auth.GetLocalRegistryCredentials(cmd.dockerConfig)
	if err != nil {
		// This can happen if the user does not have docker installed locally.
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

	builtImages, err := cmd.buildImages(parsedCompose)
	if err != nil {
		return err
	}

	// Send the boot request to the cluster manager.
	pp := util.NewProgressPrinter(os.Stdout, "Deploying Docker Compose file to sandbox")
	go pp.Run()

	_, err = manager.C.DeployToSandbox(context.Background(), &cluster.DeployRequest{
		Auth:        cmd.config.BlimpAuth(),
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

			output, err := stClient.Run(syncthingCtx, cmd.nodeControllerClient, cmd.config.BlimpAuth(), cmd.tunnelManager)
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
				downFinished <- down.Run(cmd.config.BlimpAuth(), false)
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
			Auth:                cmd.config.BlimpAuth(),
			ComposeFile:         composeCfg,
			RegistryCredentials: cmd.regCreds.ToProtobuf(),
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
	cmd.tunnelManager = tunnel.NewManager(cmd.nodeControllerClient, cmd.config.BlimpAuth())

	cmd.imageNamespace = resp.ImageNamespace
	// Add the registry credentials for pushing to the blimp registry.
	blimpRegcred, err := auth.BlimpRegcred(cmd.config.BlimpAuth())
	if err != nil {
		return errors.WithContext("create Blimp regcred", err)
	}
	cmd.regCreds[strings.SplitN(cmd.imageNamespace, "/", 2)[0]] = blimpRegcred.ToDocker()

	// Save the Kubernetes API credentials for use by other Blimp commands.
	kubeCreds := resp.GetKubeCredentials()
	cmd.config.Auth.KubeToken = kubeCreds.Token
	cmd.config.Auth.KubeHost = kubeCreds.Host
	cmd.config.Auth.KubeCACrt = kubeCreds.CaCrt
	cmd.config.Auth.KubeNamespace = kubeCreds.Namespace

	// Apply any overrides from the user's local config.
	if cmd.config.ConfigFile.KubeHost != "" {
		cmd.config.Auth.KubeHost = cmd.config.ConfigFile.KubeHost
	}
	if err := cmd.config.Auth.Save(); err != nil {
		return err
	}
	return nil
}

func (cmd *up) runGUI(ctx context.Context, parsedCompose composeTypes.Project) error {
	services := parsedCompose.ServiceNames()
	statusPrinter := newStatusPrinter(services, cmd.disableStatusOutput)
	if !statusPrinter.Run(ctx, manager.C, cmd.config.BlimpAuth()) {
		return nil
	}
	analytics.Log.Info("Containers booted")

	return logs.Command{
		Services: services,
		Opts:     corev1.PodLogOptions{Follow: true},
		Config:     cmd.config,
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
