package up

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha1"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/signal"
	"path/filepath"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/jsonmessage"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/encoding/gzip"

	"github.com/kelda-inc/blimp/cli/authstore"
	"github.com/kelda-inc/blimp/cli/up/tunnel"
	"github.com/kelda-inc/blimp/cli/util"
	"github.com/kelda-inc/blimp/pkg/auth"
	"github.com/kelda-inc/blimp/pkg/dockercompose"
	"github.com/kelda-inc/blimp/pkg/proto/cluster"
)

const managerHost = "localhost:9000"
const registry = "gcr.io/kevin-230505"

func New() *cobra.Command {
	return &cobra.Command{
		Use: "up",
		Run: func(_ *cobra.Command, _ []string) {
			auth, err := authstore.New()
			if err != nil {
				panic(err)
				//return fmt.Errorf("parse auth config: %w", err)
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
				log.WithError(err).Warn("Failed to connect to local Docker daemon. Builds won't work.")
			}

			if err := cmd.run(); err != nil {
				util.HandleFatalError("Unexpected error", err)
			}
		},
	}
}

type up struct {
	auth         authstore.Store
	composePath  string
	dockerClient *client.Client
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

	parsedCompose, err := dockercompose.Parse(rawCompose)
	if err != nil {
		return err
	}

	// Send the boot request to the cluster manager.
	// TODO: Use TLS
	conn, err := grpc.Dial(managerHost,
		grpc.WithInsecure(),
		grpc.WithDefaultCallOptions(grpc.UseCompressor(gzip.Name)))
	if err != nil {
		return err
	}
	defer conn.Close()

	user, err := auth.ParseIDToken(cmd.auth.AuthToken)
	if err != nil {
		return err
	}

	// TODO: Does Docker rebuild images when files change?
	builtImages, err := cmd.buildImages(dnsCompliantHash(user.ID), parsedCompose)
	if err != nil {
		return err
	}

	clusterManager := cluster.NewManagerClient(conn)
	bootResp, err := clusterManager.Boot(context.Background(), &cluster.BootRequest{
		Token:       cmd.auth.AuthToken,
		ComposeFile: string(rawCompose),
		BuiltImages: builtImages,
	})
	if err != nil {
		return err
	}

	// Save the Kubernetes API credentials for use by other Blimp commands.
	kubeCreds := bootResp.GetKubeCredentials()
	cmd.auth.KubeToken = kubeCreds.Token
	cmd.auth.KubeHost = kubeCreds.Host
	cmd.auth.KubeCACrt = kubeCreds.CaCrt
	cmd.auth.KubeNamespace = kubeCreds.Namespace
	if err := cmd.auth.Save(); err != nil {
		return err
	}

	kubeClient, restConfig, err := cmd.auth.KubeClient()
	if err != nil {
		return err
	}

	// Start the tunnels.
	var desiredTunnels []tunnel.Tunnel
	for name, svc := range parsedCompose.Services {
		for _, mapping := range svc.PortMappings {
			desiredTunnels = append(desiredTunnels, tunnel.Tunnel{
				Service:     name,
				PortMapping: mapping,
			})
		}
	}
	go tunnel.Run(kubeClient, restConfig, cmd.auth.KubeNamespace, desiredTunnels)

	// Block until the user exits.
	exitSig := make(chan os.Signal, 1)
	signal.Notify(exitSig, os.Interrupt)
	<-exitSig
	return nil
}

func (cmd *up) buildImages(namespace string, composeFile dockercompose.Config) (map[string]string, error) {
	if cmd.dockerClient == nil {
		return nil, errors.New("no docker client")
	}

	images := map[string]string{}
	for svcName, svc := range composeFile.Services {
		if svc.Build == nil {
			continue
		}

		// TODO: namespace images via registry/namespace/image:tag.
		imageName, err := cmd.buildImage(*svc.Build, fmt.Sprintf("%s/%s-%s", registry, namespace, svcName))
		if err != nil {
			return nil, fmt.Errorf("build %s: %w", svcName, err)
		}

		images[svcName] = imageName
	}
	return images, nil
}

// TODO: Generate `tag` in this function so that we can make sure it's unique.
func (cmd *up) buildImage(spec dockercompose.Build, tag string) (string, error) {
	opts := types.ImageBuildOptions{
		Dockerfile: spec.Dockerfile,
		Tags:       []string{tag},
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
	err = jsonmessage.DisplayJSONMessagesStream(buildResp.Body, os.Stderr, 0, false, nil)
	if err != nil {
		return "", fmt.Errorf("build image: %w", err)
	}

	// TODO: Auth
	pushResp, err := cmd.dockerClient.ImagePush(context.TODO(), tag, types.ImagePushOptions{
		RegistryAuth: auth.RegistryAuth,
	})
	if err != nil {
		return "", fmt.Errorf("push image: %w", err)
	}

	// TODO: Catch errors with push.. Maybe display message stream?
	io.Copy(os.Stderr, pushResp)
	pushResp.Close()
	return tag, nil
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

// TODO: Repeated
// dnsCompliantHash hashes the given string and encodes it into base16.
func dnsCompliantHash(str string) string {
	// TODO: sha1 is insecure.
	h := sha1.New()
	h.Write([]byte(str))
	return fmt.Sprintf("%x", h.Sum(nil))
}
