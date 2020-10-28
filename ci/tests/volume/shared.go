package volume

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	blimpAssert "github.com/kelda/blimp/ci/assert"
	"github.com/kelda/blimp/ci/util"
)

var sharedVolumesTestFiles = map[string]string{
	"docker-compose.yml": `version: "3"
services:
  writer:
    build: .
    command: tail -f /dev/null
    volumes:
    # Mount /data, which causes the contents of the image at /data to get
    # copied into the volume.
    - "data:/data"

  reader:
    # Run an image that doesn't have data in /data.
    image: ubuntu
    # Check /data/from-image as soon as the container boots, so that it'll crash
    # if it the data directory wasn't populated.
    command: sh -c "ls /data/from-image && tail -f /dev/null"
    volumes:
    # Mount the volume that gets populated by 'writer'.
    - "data:/data"
volumes:
  data:
`,

	"Dockerfile": `FROM ubuntu:18.04
RUN groupadd -r testgroup && useradd -r -g testgroup testuser
RUN mkdir /data && chown -R testuser /data
USER testuser

# Make a 5GB file so that the volume initialization will take some time, in
# order to encourage race conditions.
RUN dd if=/dev/zero of=/data/from-image count=1024 bs=5M
`,
}

func testSharedVolumes(ctx context.Context, t *testing.T) {
	dir, err := util.MakeTestDirectory(sharedVolumesTestFiles)
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

	// Check that the files synced as expected.
	blimpAssert.FileExistence(t, "reader", "/data/from-image", true)
}
