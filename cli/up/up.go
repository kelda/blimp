package up

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"

	composeTypes "github.com/compose-spec/compose-go/types"
	"github.com/docker/cli/cli/config"
	"github.com/docker/cli/cli/config/configfile"
	clitypes "github.com/docker/cli/cli/config/types"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"

	"github.com/kelda-inc/blimp/cli/authstore"
	"github.com/kelda-inc/blimp/cli/logs"
	"github.com/kelda-inc/blimp/cli/manager"
	"github.com/kelda-inc/blimp/cli/util"
	"github.com/kelda-inc/blimp/pkg/analytics"
	"github.com/kelda-inc/blimp/pkg/dockercompose"
	"github.com/kelda-inc/blimp/pkg/errors"
	"github.com/kelda-inc/blimp/pkg/proto/cluster"
	"github.com/kelda-inc/blimp/pkg/proto/sandbox"
	"github.com/kelda-inc/blimp/pkg/syncthing"
	"github.com/kelda-inc/blimp/pkg/tunnel"
)

func New() *cobra.Command {
	var composePaths []string
	var alwaysBuild bool
	cobraCmd := &cobra.Command{
		Use:   "up",
		Short: "Create and start containers",
		Long:  "Create and start containers\n\nDeploys the docker-compose.yml in the current directory.",
		Run: func(_ *cobra.Command, _ []string) {
			auth, err := authstore.New()
			if err != nil {
				log.WithError(err).Fatal("Failed to parse local authentication store")
			}

			// TODO: Prompt to login again if token is expired.
			if auth.AuthToken == "" {
				fmt.Fprintln(os.Stderr, "Not logged in. Please run `blimp login`.")
				os.Exit(1)
			}

			cmd := up{
				auth:        auth,
				alwaysBuild: alwaysBuild,
			}

			dockerClient, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
			if err == nil {
				cmd.dockerClient = dockerClient
			} else {
				log.WithError(err).Warn("Failed to connect to local Docker daemon. " +
					"Building images won't work, but all other features will.")
			}

			// Convert the compose path to an absolute path so that the code
			// that makes identifiers for bind volumes are unique for relative
			// paths.
			composePath, overridePaths, err := getComposePaths(composePaths)
			if err != nil {
				if os.IsNotExist(err) {
					fmt.Fprintf(os.Stderr, "Docker compose file not found: %s\n", cmd.composePath)
					os.Exit(1)
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
			if err := cmd.run(); err != nil {
				errors.HandleFatalError(err)
			}
		},
	}
	cobraCmd.Flags().StringSliceVarP(&composePaths, "file", "f", nil,
		"Specify an alternate compose file\nDefaults to docker-compose.yml and docker-compose.yaml")
	cobraCmd.Flags().BoolVarP(&alwaysBuild, "build", "", false,
		"Build images before starting containers")
	return cobraCmd
}

type up struct {
	auth           authstore.Store
	composePath    string
	overridePaths  []string
	alwaysBuild    bool
	dockerClient   *client.Client
	dockerConfig   *configfile.ConfigFile
	imageNamespace string
	sandboxAddr    string
	sandboxCert    string
}

func (cmd *up) createSandbox(composeCfg string, idPathMap map[string]string) error {
	pp := util.NewProgressPrinter(os.Stderr, "Booting cloud sandbox")
	go pp.Run()
	defer pp.Stop()

	registryCredentials, err := getLocalRegistryCredentials(cmd.dockerConfig)
	if err != nil {
		log.WithError(err).Warn("Failed to get local registry credentials. Private images will fail to pull.")
		registryCredentials = map[string]*cluster.RegistryCredential{}
	}

	resp, err := manager.C.CreateSandbox(context.TODO(),
		&cluster.CreateSandboxRequest{
			Token:               cmd.auth.AuthToken,
			ComposeFile:         string(composeCfg),
			RegistryCredentials: registryCredentials,
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
		os.Exit(0)
	default:
		os.Exit(0)
	}

	cmd.imageNamespace = resp.ImageNamespace
	cmd.sandboxAddr = resp.SandboxAddress
	cmd.sandboxCert = resp.SandboxCert

	// Save the Kubernetes API credentials for use by other Blimp commands.
	kubeCreds := resp.GetKubeCredentials()
	cmd.auth.KubeToken = kubeCreds.Token
	cmd.auth.KubeHost = kubeCreds.Host
	cmd.auth.KubeCACrt = kubeCreds.CaCrt
	cmd.auth.KubeNamespace = kubeCreds.Namespace
	if err := cmd.auth.Save(); err != nil {
		return err
	}
	return nil
}

func (cmd *up) run() error {
	parsedCompose, err := dockercompose.Load(cmd.composePath, cmd.overridePaths)
	if err != nil {
		return errors.WithContext("load compose file", err)
	}

	parsedComposeBytes, err := dockercompose.Marshal(parsedCompose)
	if err != nil {
		return err
	}

	stClient := cmd.makeSyncthingClient(parsedCompose)
	idPathMap := stClient.GetIDPathMap()

	// Start creating the sandbox immediately so that the systems services
	// start booting as soon as possible.
	if err := cmd.createSandbox(string(parsedComposeBytes), idPathMap); err != nil {
		log.WithError(err).Fatal("Failed to create development sandbox")
	}

	builtImages, err := cmd.buildImages(parsedCompose)
	if err != nil {
		return err
	}

	// Send the boot request to the cluster manager.
	pp := util.NewProgressPrinter(os.Stderr, "Deploying Docker Compose file to sandbox")
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

	sandboxConn, err := util.Dial(cmd.sandboxAddr, cmd.sandboxCert)
	if err != nil {
		return err
	}
	defer sandboxConn.Close()
	sandboxManager := sandbox.NewControllerClient(sandboxConn)

	// Start the tunnels.
	for _, svc := range parsedCompose.Services {
		for _, mapping := range svc.Ports {
			go startTunnel(sandboxManager, cmd.auth.AuthToken, svc.Name,
				mapping.Published, mapping.Target)
		}
	}

	stopHashSync := make(chan struct{})
	if len(idPathMap) != 0 {
		go startTunnel(sandboxManager, cmd.auth.AuthToken, "syncthing",
			syncthing.Port, syncthing.Port)
		go func() {
			output, err := stClient.Run(sandboxManager, stopHashSync)
			if err != nil {
				log.WithError(err).WithField("output", string(output)).Warn("syncthing error")
			}
		}()
	}

	services := parsedCompose.ServiceNames()
	statusPrinter := newStatusPrinter(services)
	statusPrinter.Run(manager.C, cmd.auth.AuthToken)
	analytics.Log.Info("Containers booted")

	// Now that the containers have finished booting, we know the initial
	// filesync is complete, and can stop updating the file hashes.
	close(stopHashSync)

	return logs.LogsCommand{
		Containers: services,
		Opts:       corev1.PodLogOptions{Follow: true},
		Auth:       cmd.auth,
	}.Run()
}

func startTunnel(scc sandbox.ControllerClient, token, name string,
	hostPort, containerPort uint32) {

	addr := fmt.Sprintf("127.0.0.1:%d", hostPort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		switch {
		case strings.Contains(err.Error(), "permission denied"):
			err = errors.NewFriendlyError("Permission denied while listening for connections\n"+
				"Make sure that the local port for the service %q is above 1024.\n\n"+
				"The full error was:\n%s", name, err)
		case strings.Contains(err.Error(), "address already in use"):
			err = errors.NewFriendlyError("Another process is already listening on the same port\n"+
				"Make sure that the there aren't any other "+
				"services listening locally on port %d. This can be checked with the following command:\n"+
				"lsof -i -P -n | grep %d\n\n"+
				"The full error was:\n%s", hostPort, hostPort, err)
		}

		// TODO.  It's appropriate that this error is fatal, but we need
		// a better way of handling it.  Log messages are ugly, and we
		// need to do some cleanup.
		log.WithError(err).
			WithField("address", addr).
			Fatal("Failed to started tunnels")
	}

	err = tunnel.Client(scc, ln, token, name, containerPort)
	if err != nil {
		// TODO.  Same question about Fatal.  Also if accept errors
		// maybe wes hould have retried inside accept tunnels instead of
		// fatal out here?
		log.WithFields(log.Fields{
			"error":   err,
			"address": addr,
			"network": "tcp",
		}).Fatal("failed to listen for connections")
		return
	}
}

func (cmd *up) makeSyncthingClient(dcCfg composeTypes.Config) syncthing.Client {
	var bindVolumes []string
	for _, svc := range dcCfg.Services {
		for _, v := range svc.Volumes {
			if v.Type != "bind" {
				continue
			}

			bindVolumes = append(bindVolumes, v.Source)
		}
	}
	return syncthing.NewClient(bindVolumes)
}

func getComposePaths(composePaths []string) (string, []string, error) {
	getYamlFile := func(prefix string) (string, error) {
		paths := []string{
			prefix + ".yaml",
			prefix + ".yml",
		}

		var err error
		for _, path := range paths {
			if _, err = os.Stat(path); err == nil {
				return filepath.Abs(path)
			}
		}

		// Return the error from the last path we tried to stat.
		return "", err
	}

	// If the user doesn't explicitly specify any files, try to get the
	// default files.
	if len(composePaths) == 0 {
		composePath, err := getYamlFile("docker-compose")
		if err != nil {
			return "", nil, err
		}

		var overridePaths []string
		if overridePath, err := getYamlFile("docker-compose.override"); err == nil {
			overridePaths = []string{overridePath}
		}
		return composePath, overridePaths, nil
	}

	var absPaths []string
	for _, composePath := range composePaths {
		p, err := filepath.Abs(composePath)
		if err != nil {
			return "", nil, err
		}
		absPaths = append(absPaths, p)
	}

	return absPaths[0], absPaths[1:], nil
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
		header.Name = relPath

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

func makeRegistryAuthHeader(idToken string) (string, error) {
	authJSON, err := json.Marshal(types.AuthConfig{
		Username: "ignored",
		Password: idToken,
	})
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(authJSON), nil
}

// getLocalRegistryCredentials reads the user's registry credentials from their
// local machine.
func getLocalRegistryCredentials(dockerConfig *configfile.ConfigFile) (map[string]*cluster.RegistryCredential, error) {
	// Get the insecure credentials that were saved directly to
	// the auths section of ~/.docker/config.json.
	creds := map[string]*cluster.RegistryCredential{}
	addCredentials := func(authConfigs map[string]clitypes.AuthConfig) {
		for host, cred := range authConfigs {
			creds[host] = &cluster.RegistryCredential{
				Username: cred.Username,
				Password: cred.Password,
			}
		}
	}
	addCredentials(dockerConfig.GetAuthConfigs())

	// Get the secure credentials that are set via credHelpers and credsStore.
	// These credentials take preference over any insecure credentials.
	credHelpers, err := dockerConfig.GetAllCredentials()
	if err != nil {
		return nil, err
	}
	addCredentials(credHelpers)

	return creds, nil
}
