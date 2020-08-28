package buildkit

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/containerd/console"
	"github.com/moby/buildkit/client"
	"github.com/moby/buildkit/session"
	"github.com/moby/buildkit/util/progress/progressui"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh/terminal"

	"github.com/kelda/blimp/pkg/auth"
	"github.com/kelda/blimp/pkg/build"
	"github.com/kelda/blimp/pkg/errors"
	"github.com/kelda/blimp/pkg/tunnel"
)

type Client struct {
	client       *client.Client
	authProvider *authProvider
}

func New(tunnelManager tunnel.Manager, regCreds auth.RegistryCredentials) (build.Interface, error) {
	tunnelErr := make(chan error)
	tunnelReady := make(chan struct{})
	go func() {
		tunnelErr <- tunnelManager.Run("127.0.0.1", 1234, "buildkitd", 1234, tunnelReady)
	}()
	select {
	case err := <-tunnelErr:
		return nil, errors.WithContext("connect to buildkitd", err)
	case <-tunnelReady:
	}

	c, err := client.New(context.Background(), "tcp://127.0.0.1:1234")
	if err != nil {
		return nil, errors.WithContext("connect to buildkit", err)
	}

	return Client{
		client:       c,
		authProvider: &authProvider{regCreds: regCreds},
	}, nil
}

func (c Client) BuildAndPush(images map[string]build.BuildPushConfig) (map[string]string, error) {
	var cons console.Console
	if terminal.IsTerminal(int(os.Stdout.Fd())) {
		var err error
		cons, err = console.ConsoleFromFile(os.Stdout)
		if err != nil {
			return nil, errors.WithContext("create buildkit console", err)
		}
	}

	pushedImages := map[string]string{}
	for name, opts := range images {
		digest, err := c.buildOne(name, opts, cons)
		if err != nil {
			return nil, errors.WithContext(fmt.Sprintf("buildkit build %s", name), err)
		}

		pushedImages[name] = build.ReplaceTagWithDigest(opts.ImageName, digest)
	}

	return pushedImages, nil
}

func (c Client) buildOne(name string, opts build.BuildPushConfig, cons console.Console) (digest string, err error) {
	var ch chan *client.SolveStatus
	if cons != nil {
		ch = make(chan *client.SolveStatus)
		statusErr := make(chan error)
		go func() {
			statusErr <- progressui.DisplaySolveStatus(context.Background(),
				fmt.Sprintf("Building %s", name), cons, os.Stdout, ch)
		}()

		defer func() {
			// Wait for status update to finish printing before moving on.
			err := <-statusErr
			if err != nil {
				log.WithError(err).Warn("Buildkit status updates failed")
			}
		}()
	}

	// The buildkit documentation on build options is non-existent.
	// These keys are copied from the Docker source:
	// https://github.com/moby/moby/blob/7ae5222c72cc2aac42225df8f62c2f71a1813ab4/builder/builder-next/builder.go#L253
	frontendAttrs := map[string]string{
		"filename":   opts.Dockerfile,
		"cache-from": strings.Join(opts.CacheFrom, ","),
	}

	if opts.Target != "" {
		frontendAttrs["target"] = opts.Target
	}

	for k, v := range opts.Args {
		if v == nil {
			continue
		}
		frontendAttrs["build-arg:"+k] = *v
	}

	if opts.NoCache {
		frontendAttrs["no-cache"] = ""
	}

	if opts.PullParent {
		frontendAttrs["image-resolve-mode"] = "pull"
	} else {
		frontendAttrs["image-resolve-mode"] = "default"
	}

	solveOpt := client.SolveOpt{
		Frontend:      "dockerfile.v0",
		FrontendAttrs: frontendAttrs,
		LocalDirs: map[string]string{
			"context":    opts.Context,
			"dockerfile": opts.Context,
		},
		Exports: []client.ExportEntry{
			{
				Type: client.ExporterImage,
				Attrs: map[string]string{
					"name":           opts.ImageName,
					"push":           "true",
					"name-canonical": "true",
				},
			},
		},
		Session: []session.Attachable{
			c.authProvider,
		},
	}

	resp, err := c.client.Solve(context.Background(), nil, solveOpt, ch)
	if err != nil {
		return "", errors.WithContext("buildkit solve", err)
	}

	digest, ok := resp.ExporterResponse["containerimage.digest"]
	if !ok {
		return "", errors.New("didn't receive digest from buildkit")
	}

	return digest, nil
}
