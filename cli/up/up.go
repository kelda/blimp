package up

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/docker/cli/cli/config"
	clitypes "github.com/docker/cli/cli/config/types"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/jsonmessage"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh/terminal"
	"google.golang.org/grpc"
	corev1 "k8s.io/api/core/v1"

	"github.com/kelda-inc/blimp/cli/authstore"
	"github.com/kelda-inc/blimp/cli/logs"
	"github.com/kelda-inc/blimp/cli/util"
	"github.com/kelda-inc/blimp/pkg/auth"
	"github.com/kelda-inc/blimp/pkg/dockercompose"
	"github.com/kelda-inc/blimp/pkg/proto/cluster"
	"github.com/kelda-inc/blimp/pkg/proto/sandbox"
	"github.com/kelda-inc/blimp/pkg/syncthing"
	"github.com/kelda-inc/blimp/pkg/tunnel"
)

func New() *cobra.Command {
	return &cobra.Command{
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
				composePath: "./docker-compose.yml",
			}

			dockerClient, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
			if err == nil {
				cmd.dockerClient = dockerClient
			} else {
				log.WithError(err).Warn("Failed to connect to local Docker daemon. " +
					"Building images won't work, but all other features will.")
			}

			if err := cmd.run(); err != nil {
				log.Fatal(err)
			}
		},
	}
}

type up struct {
	auth           authstore.Store
	composePath    string
	dockerClient   *client.Client
	imageNamespace string
	sandboxAddr    string
	sandboxCert    string

	clusterManager managerClient
}

type managerClient struct {
	cluster.ManagerClient
	*grpc.ClientConn
}

func (cmd *up) createSandbox(rawCompose string) error {
	pp := util.NewProgressPrinter(os.Stderr, "Booting cloud sandbox..")
	go pp.Run()
	defer pp.StopWithPrint(" Done\n")

	clusterConn, err := util.Dial(util.ManagerHost, auth.ClusterManagerCert)
	if err != nil {
		return err
	}
	cmd.clusterManager = managerClient{cluster.NewManagerClient(clusterConn), clusterConn}

	registryCredentials, err := getLocalRegistryCredentials()
	if err != nil {
		return fmt.Errorf("get local registry credentials: %w", err)
	}

	createSandboxResp, err := cmd.clusterManager.CreateSandbox(context.TODO(),
		&cluster.CreateSandboxRequest{
			Token:               cmd.auth.AuthToken,
			ComposeFile:         rawCompose,
			RegistryCredentials: registryCredentials,
		})
	if err != nil {
		return err
	}
	cmd.imageNamespace = createSandboxResp.ImageNamespace
	cmd.sandboxAddr = createSandboxResp.SandboxAddress
	cmd.sandboxCert = createSandboxResp.SandboxCert

	// Save the Kubernetes API credentials for use by other Blimp commands.
	kubeCreds := createSandboxResp.GetKubeCredentials()
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
		if os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "Docker compose file not found: %s\n", cmd.composePath)
			return nil
		}
		return err
	}

	// Start creating the sandbox immediately so that the systems services
	// start booting as soon as possible.
	// Also, we ship the Docker Compose file to the cluster as quickly as
	// possible so that if the parsing fails, we will at least have the compose
	// file for debugging later.
	if err := cmd.createSandbox(string(rawCompose)); err != nil {
		log.WithError(err).Fatal("Failed to create development sandbox")
	}
	defer cmd.clusterManager.Close()

	parsedCompose, _, err := dockercompose.Parse(rawCompose)
	if err != nil {
		return err
	}

	haveSyncthing := cmd.bootSyncthing(parsedCompose)

	// TODO: Does Docker rebuild images when files change?
	builtImages, err := cmd.buildImages(parsedCompose)
	if err != nil {
		return err
	}

	// Send the boot request to the cluster manager.
	pp := util.NewProgressPrinter(os.Stderr, "Deploying Docker Compose file to sandbox..")
	go pp.Run()

	deployResp, err := cmd.clusterManager.DeployToSandbox(context.Background(), &cluster.DeployRequest{
		Token:       cmd.auth.AuthToken,
		ComposeFile: string(rawCompose),
		BuiltImages: builtImages,
	})
	pp.StopWithPrint(" Done\n")
	if err != nil {
		return err
	}

	if deployResp.StrictParseError != "" {
		log.Warn("Docker Compose file failed strict parsing:\n\n" +
			deployResp.StrictParseError + "\n\n" +
			"This is usually a sign that you're using an unsupported Docker Compose features.\n" +
			"To fix this error, please modify your Docker Compose file to " +
			"use the features described here: <TODO>\n\n" +
			"We're working on reaching full parity with Docker Compose, so let us know what features you'd like us to prioritize!")
		log.Info("Blimp will continue to attempt to boot")
	}

	sandboxConn, err := util.Dial(cmd.sandboxAddr, cmd.sandboxCert)
	if err != nil {
		return err
	}
	defer sandboxConn.Close()

	// Start the tunnels.
	sandboxManager := sandbox.NewControllerClient(sandboxConn)
	for name, svc := range parsedCompose.Services {
		for _, mapping := range svc.PortMappings {
			go startTunnel(sandboxManager, cmd.auth.AuthToken, name,
				mapping.HostPort, mapping.ContainerPort)
		}
	}

	if haveSyncthing {
		go startTunnel(sandboxManager, cmd.auth.AuthToken, "syncthing",
			syncthing.Port, syncthing.Port)
	}

	var services []string
	for name := range parsedCompose.Services {
		services = append(services, name)
	}

	statusPrinter := newStatusPrinter(services)
	statusPrinter.Run(cmd.clusterManager, cmd.auth.AuthToken)

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

func (cmd *up) buildImages(composeFile dockercompose.Config) (map[string]string, error) {
	if cmd.dockerClient == nil {
		return nil, errors.New("no docker client")
	}

	images := map[string]string{}
	for svcName, svc := range composeFile.Services {
		if svc.Build == nil {
			continue
		}

		imageName, err := cmd.buildImage(*svc.Build, svcName)
		if err != nil {
			return nil, fmt.Errorf("build %s: %w", svcName, err)
		}

		images[svcName] = imageName
	}
	return images, nil
}

func (cmd *up) buildImage(spec dockercompose.Build, svc string) (string, error) {
	opts := types.ImageBuildOptions{
		Dockerfile: spec.Dockerfile,
	}
	if opts.Dockerfile == "" {
		opts.Dockerfile = "Dockerfile"
	}

	buildContextTar, err := makeTar(spec.Context)
	if err != nil {
		return "", fmt.Errorf("tar context: %w", err)
	}

	buildResp, err := cmd.dockerClient.ImageBuild(context.TODO(), buildContextTar, opts)
	if err != nil {
		return "", fmt.Errorf("start build: %w", err)
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
		return "", fmt.Errorf("build image: %w", err)
	}

	name := fmt.Sprintf("%s/%s:%s", cmd.imageNamespace, svc, strings.TrimPrefix(imageID, "sha256:"))
	if err := cmd.dockerClient.ImageTag(context.TODO(), imageID, name); err != nil {
		return "", fmt.Errorf("tag image: %w", err)
	}

	pp := util.NewProgressPrinter(os.Stderr, fmt.Sprintf("Pushing image for %s..", svc))
	go pp.Run()
	defer pp.StopWithPrint(" Done\n")

	registryAuth, err := makeRegistryAuthHeader(cmd.auth.AuthToken)
	if err != nil {
		return "", fmt.Errorf("make registry auth header: %w", err)
	}

	pushResp, err := cmd.dockerClient.ImagePush(context.TODO(), name, types.ImagePushOptions{
		RegistryAuth: registryAuth,
	})
	if err != nil {
		return "", fmt.Errorf("start image push: %w", err)
	}
	defer pushResp.Close()

	err = jsonmessage.DisplayJSONMessagesStream(pushResp, ioutil.Discard, 0, false, nil)
	if err != nil {
		return "", fmt.Errorf("push image: %w", err)
	}
	return name, nil
}

func (cmd *up) bootSyncthing(dcCfg dockercompose.Config) bool {
	namespace := cmd.auth.KubeNamespace
	idPathMap := map[string]string{}
	for _, svc := range dcCfg.Services {
		for _, v := range svc.Volumes {
			if v.Type != "bind" {
				continue
			}
			idPathMap[v.Id(namespace)] = v.Source
		}
	}

	if len(idPathMap) == 0 {
		return false
	}

	go func() {
		output, err := syncthing.Run(idPathMap)
		if err != nil {
			log.WithError(err).WithField("output", string(output)).Warn("syncthing error")
		}
	}()

	return true
}

func makeTar(dir string) (io.Reader, error) {
	var out bytes.Buffer
	tw := tar.NewWriter(&out)
	defer tw.Close()

	err := filepath.Walk(dir, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		header, err := tar.FileInfoHeader(fi, fi.Name())
		if err != nil {
			return fmt.Errorf("write header: %s", err)
		}

		relPath, err := filepath.Rel(dir, path)
		if err != nil {
			return fmt.Errorf("get normalized path %q: %w", path, err)
		}

		header.Name = relPath
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
