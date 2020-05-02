package up

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"

	composeTypes "github.com/compose-spec/compose-go/types"
	"github.com/docker/cli/cli/config"
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
	"github.com/kelda-inc/blimp/pkg/dockercompose"
	"github.com/kelda-inc/blimp/pkg/proto/cluster"
	"github.com/kelda-inc/blimp/pkg/proto/sandbox"
	"github.com/kelda-inc/blimp/pkg/syncthing"
	"github.com/kelda-inc/blimp/pkg/tunnel"
	"github.com/kelda-inc/blimp/pkg/volume"
)

func New() *cobra.Command {
	var composePath string
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
				composePath: composePath,
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
			absComposePath, err := getComposeAbsPath(cmd.composePath)
			if err != nil {
				if os.IsNotExist(err) {
					fmt.Fprintf(os.Stderr, "Docker compose file not found: %s\n", cmd.composePath)
					os.Exit(1)
				}
				log.WithError(err).Fatal("Failed to get absolute path to Compose file")
			}

			cmd.composePath = absComposePath
			if err := cmd.run(); err != nil {
				log.Fatal(err)
			}
		},
	}
	cobraCmd.Flags().StringVarP(&composePath, "file", "f", "",
		"Specify an alternate compose file\nDefaults to docker-compose.yml and docker-compose.yaml")
	cobraCmd.Flags().BoolVarP(&alwaysBuild, "build", "", false,
		"Build images before starting containers")
	return cobraCmd
}

type up struct {
	auth           authstore.Store
	composePath    string
	alwaysBuild    bool
	dockerClient   *client.Client
	imageNamespace string
	sandboxAddr    string
	sandboxCert    string
}

func (cmd *up) createSandbox(composeCfg string) error {
	pp := util.NewProgressPrinter(os.Stderr, "Booting cloud sandbox")
	go pp.Run()
	defer pp.Stop()

	registryCredentials, err := getLocalRegistryCredentials()
	if err != nil {
		return fmt.Errorf("get local registry credentials: %w", err)
	}

	resp, err := manager.C.CreateSandbox(context.TODO(),
		&cluster.CreateSandboxRequest{
			Token:               cmd.auth.AuthToken,
			ComposeFile:         string(composeCfg),
			RegistryCredentials: registryCredentials,
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
	rawCompose, err := ioutil.ReadFile(cmd.composePath)
	if err != nil {
		return err
	}

	parsedCompose, err := dockercompose.Load(cmd.composePath, rawCompose)
	if err != nil {
		return err
	}

	parsedComposeBytes, err := dockercompose.Marshal(parsedCompose)
	if err != nil {
		return err
	}

	// Start creating the sandbox immediately so that the systems services
	// start booting as soon as possible.
	if err := cmd.createSandbox(string(parsedComposeBytes)); err != nil {
		log.WithError(err).Fatal("Failed to create development sandbox")
	}

	haveSyncthing, stopHashSync := cmd.bootSyncthing(parsedCompose)

	// TODO: Does Docker rebuild images when files change?
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

	// Start the tunnels.
	sandboxManager := sandbox.NewControllerClient(sandboxConn)
	for _, svc := range parsedCompose.Services {
		for _, mapping := range svc.Ports {
			go startTunnel(sandboxManager, cmd.auth.AuthToken, svc.Name,
				mapping.Published, mapping.Target)
		}
	}

	if haveSyncthing {
		go startTunnel(sandboxManager, cmd.auth.AuthToken, "syncthing",
			syncthing.Port, syncthing.Port)
	}

	services := parsedCompose.ServiceNames()
	statusPrinter := newStatusPrinter(services)
	statusPrinter.Run(manager.C, cmd.auth.AuthToken)

	// Now that the containers have finished booting, we know the initial
	// filesync is complete, and can stop updating the file hashes.
	if haveSyncthing {
		close(stopHashSync)
	}

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
		// TODO.  It's appropriate that this error is fatal, but we need
		// a better way of handling it.  Log messages are ugly, and we
		// need to do some cleanup.
		log.WithFields(log.Fields{
			"error":   err,
			"address": addr,
			"network": "tcp",
		}).Fatal("faield to listen for connections")
		return
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

func (cmd *up) bootSyncthing(dcCfg composeTypes.Config) (bool, chan<- struct{}) {
	namespace := cmd.auth.KubeNamespace
	idPathMap := map[string]string{}
	for _, svc := range dcCfg.Services {
		for _, v := range svc.Volumes {
			if v.Type != "bind" {
				continue
			}
			idPathMap[volume.ID(namespace, v)] = v.Source
		}
	}

	if len(idPathMap) == 0 {
		return false, nil
	}

	stopHashSync := make(chan struct{})
	go func() {
		output, err := syncthing.RunClient(stopHashSync, idPathMap)
		if err != nil {
			log.WithError(err).WithField("output", string(output)).Warn("syncthing error")
		}
	}()

	return true, stopHashSync
}

func getComposeAbsPath(composePath string) (string, error) {
	if composePath != "" {
		return filepath.Abs(composePath)
	}

	if _, err := os.Stat("docker-compose.yml"); os.IsNotExist(err) {
		return filepath.Abs("docker-compose.yaml")
	} else {
		return filepath.Abs("docker-compose.yml")
	}
}

func getHeader(fi os.FileInfo, relFilePath string) (*tar.Header, error) {
	var link string
	if fi.Mode()&os.ModeSymlink != 0 {
		var err error
		link, err = os.Readlink(relFilePath)
		if err != nil {
			return nil, err
		}
	}

	hdr, err := tar.FileInfoHeader(fi, link)
	if err != nil {
		return nil, err
	}

	hdr.Name = relFilePath
	return hdr, nil
}

func makeTar(dir string) (io.Reader, error) {
	var out bytes.Buffer
	tw := tar.NewWriter(&out)
	defer tw.Close()

	err := filepath.Walk(dir, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(dir, path)
		if err != nil {
			return fmt.Errorf("get normalized path %q: %w", path, err)
		}

		header, err := getHeader(fi, relPath)
		if err != nil {
			return fmt.Errorf("get header: %s", err)
		}

		if err := tw.WriteHeader(header); err != nil {
			return fmt.Errorf("write header %q: %w", header.Name, err)
		}

		fileMode := fi.Mode()
		if !fileMode.IsRegular() {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("open file %q: %w", header.Name, err)
		}
		defer f.Close()

		if _, err := io.Copy(tw, f); err != nil {
			return fmt.Errorf("write file %q: %w", header.Name, err)
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
func getLocalRegistryCredentials() (map[string]*cluster.RegistryCredential, error) {
	cfg, err := config.Load(config.Dir())
	if err != nil {
		return nil, err
	}

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
	addCredentials(cfg.GetAuthConfigs())

	// Get the secure credentials that are set via credHelpers and credsStore.
	// These credentials take preference over any insecure credentials.
	credHelpers, err := cfg.GetAllCredentials()
	if err != nil {
		return nil, err
	}
	addCredentials(credHelpers)

	return creds, nil
}
