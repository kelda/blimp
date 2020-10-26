package buildcache

import (
	"context"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kelda-inc/blimp/ci/util"
)

var cacheTestFiles = map[string]string{
	"docker-compose.yml": `version: "3"
services:
  service:
    build: .
    command: tail -f /dev/null
`,
	"Dockerfile": `FROM ubuntu
COPY file.txt /file.txt
`,
}

func testBuildCache(ctx context.Context, t *testing.T, upArgs ...string) {
	dir, err := util.MakeTestDirectory(cacheTestFiles)
	require.NoError(t, err)
	defer os.RemoveAll(dir)
	os.Chdir(dir)

	fileV1 := []byte("v1")
	fileV2 := []byte("v2")

	// Do the initial image build and boot.
	require.NoError(t, ioutil.WriteFile(filepath.Join(dir, "file.txt"), fileV1, 0644))
	upCtx, cancelUp := context.WithCancel(ctx)
	waitErr, err := util.Up(upCtx, append(upArgs, "-d", "--build")...)
	require.NoError(t, err, "start blimp up")

	assertFileContent(ctx, t, fileV1)

	cancelUp()
	require.NoError(t, <-waitErr, "run blimp up")

	// Change file.txt, but run `blimp up` without `--build`. The cached
	// version of the image should be used.
	require.NoError(t, ioutil.WriteFile(filepath.Join(dir, "file.txt"), fileV2, 0644))
	upCtx, cancelUp = context.WithCancel(ctx)
	waitErr, err = util.Up(upCtx, append(upArgs, "-d")...)
	require.NoError(t, err, "start blimp up")

	assertFileContent(ctx, t, fileV1)

	cancelUp()
	require.NoError(t, <-waitErr, "run blimp up")

	// Run `blimp up` again with `--build`. The file should get updated in the image.
	upCtx, cancelUp = context.WithCancel(ctx)
	waitErr, err = util.Up(upCtx, append(upArgs, "-d", "--build")...)
	require.NoError(t, err, "start blimp up")

	assertFileContent(ctx, t, fileV2)

	cancelUp()
	require.NoError(t, <-waitErr, "run blimp up")
}

func assertFileContent(ctx context.Context, t *testing.T, exp []byte) {
	actual, err := util.Run(ctx, "exec", "service", "cat", "/file.txt")
	if !assert.NoError(t, err) {
		return
	}
	assert.Equal(t, exp, actual)
}
