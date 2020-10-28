package volume

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	blimpAssert "github.com/kelda/blimp/ci/assert"
	"github.com/kelda/blimp/ci/util"
)

var permissionsTestFiles = map[string]string{
	"docker-compose.yml": `version: '3'
services:
  ubuntu:
    build: .
    command:
      - sh
      - -c
      # The container should be able to modify the volume.
      - "touch /data/started && rm /data/remove-me && tail -f /dev/null"
    volumes:
    - "/data"
`,

	"Dockerfile": `FROM ubuntu:18.04
RUN groupadd -r testgroup && useradd -r -g testgroup testuser
RUN mkdir /data && chown -R testuser /data
USER testuser
RUN touch /data/remove-me /data/from-image
`,
}

func testVolumePermissions(ctx context.Context, t *testing.T) {
	dir, err := util.MakeTestDirectory(permissionsTestFiles)
	require.NoError(t, err)
	defer os.RemoveAll(dir)
	os.Chdir(dir)

	// Start blimp.
	upCtx, cancelUp := context.WithCancel(ctx)
	waitErr, err := util.Up(upCtx)
	require.NoError(t, err, "start blimp up")
	defer func() {
		cancelUp()
		require.NoError(t, <-waitErr, "run blimp up")
	}()

	// Check that the container was able to manipulate the volume.
	blimpAssert.FileExistence(t, "ubuntu", "/data/from-image", true)
	blimpAssert.FileExistence(t, "ubuntu", "/data/started", true)
	blimpAssert.FileExistence(t, "ubuntu", "/data/remove-me", false)
}
