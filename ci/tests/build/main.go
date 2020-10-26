package build

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kelda/blimp/ci/util"
)

type Test struct{}

func (test Test) GetName() string {
	return "Build"
}

var buildTestFiles = map[string]string{
	"docker-compose.yml": `version: '3'
services:
  red:
    build:
      context: .
      dockerfile: ./Dockerfile.red
    command: tail -f /dev/null
  blue:
    build:
      context: .
      dockerfile: ./Dockerfile.blue
    command: tail -f /dev/null
  green:
    build:
      context: .
      dockerfile: ./Dockerfile.green
    command: tail -f /dev/null
`,

	"Dockerfile.red": `FROM ubuntu:18.04
COPY file /file
`,
	"Dockerfile.green": `FROM ubuntu:18.04
COPY file /file
`,
	"Dockerfile.blue": `FROM ubuntu:18.04
COPY file /file
`,
	"file": "1",
}

func (test Test) Run(ctx context.Context, t *testing.T) {
	dir, err := util.MakeTestDirectory(buildTestFiles)
	require.NoError(t, err)
	defer os.RemoveAll(dir)
	os.Chdir(dir)

	// Start blimp.
	log.Info("Booting the initial images")
	upCtx, cancelUp := context.WithCancel(ctx)
	waitErr, err := util.Up(upCtx)
	require.NoError(t, err, "start blimp up")

	checkFiles(ctx, t, map[string]string{
		"red":   "1",
		"green": "1",
		"blue":  "1",
	}, "Pre-rebuild")

	// Update the file, and rebuild green.
	log.Info("Booting the rebuilt version of green")
	require.NoError(t, ioutil.WriteFile("file", []byte("2"), 0644))
	out, err := util.Run(ctx, "build", "green")
	require.NoError(t, err, string(out))

	// Restart blimp.
	cancelUp()
	require.NoError(t, <-waitErr, "run blimp up")
	upCtx, cancelUp = context.WithCancel(ctx)
	waitErr, err = util.Up(upCtx)
	require.NoError(t, err, "start blimp up")

	checkFiles(ctx, t, map[string]string{
		"red":   "1",
		"green": "2",
		"blue":  "1",
	}, "Rebuild green")

	// Update the file again, and rebuild red and blue in parallel.
	log.Info("Booting the rebuilt versions of red and blue")
	require.NoError(t, ioutil.WriteFile("file", []byte("3"), 0644))
	out, err = util.Run(ctx, "build", "red", "blue")
	require.NoError(t, err, string(out))

	// Restart blimp.
	cancelUp()
	require.NoError(t, <-waitErr, "run blimp up")
	upCtx, cancelUp = context.WithCancel(ctx)
	waitErr, err = util.Up(upCtx)
	require.NoError(t, err, "start blimp up")

	checkFiles(ctx, t, map[string]string{
		"red":   "3",
		"green": "2",
		"blue":  "3",
	}, "Rebuild red and blue")

	// Wait for blimp to shutdown.
	cancelUp()
	require.NoError(t, <-waitErr, "run blimp up")
}

func checkFiles(ctx context.Context, t *testing.T, serviceToContents map[string]string, msg string) {
	for svc, exp := range serviceToContents {
		actual, err := util.Run(ctx, "exec", svc, "cat", "/file")
		require.NoError(t, err)
		assert.Equal(t, exp, string(actual), fmt.Sprintf("%s: %s", svc, msg))
	}
}
