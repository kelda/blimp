package logs

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kelda-inc/blimp/ci/util"
)

var noFollowTestFiles = map[string]string{
	"docker-compose.yml": `version: '3'
services:
  logger:
    image: ubuntu
    command:
      - bash
      - -c
      # The container should be able to modify the volume.
      - "for i in {1..1000}; do echo $$i; done; touch /ready; tail -f /dev/null"
`,
}

func testNoFollow(ctx context.Context, t *testing.T) {
	dir, err := util.MakeTestDirectory(noFollowTestFiles)
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

	// Wait for the container to finish writing.
	waitReadyCtx, _ := context.WithTimeout(ctx, 15*time.Second)
	ready := func() bool {
		_, err := util.Run(ctx, "exec", "logger", "ls", "/ready")
		return err == nil
	}
	if !util.TestWithRetry(waitReadyCtx, nil, ready) {
		t.Error("Container never finished writing logs")
	}

	// Make sure all the log messages were outputted by `blimp logs`.
	var exp string
	for i := 1; i <= 1000; i++ {
		exp += fmt.Sprintf("%d\n", i)
	}
	actual, err := util.Run(ctx, "logs", "logger")
	require.NoError(t, err)
	assert.Equal(t, exp, string(actual))
}
