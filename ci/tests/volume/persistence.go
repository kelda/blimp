package volume

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	blimpAssert "github.com/kelda/blimp/ci/assert"
	"github.com/kelda/blimp/ci/util"
)

var persistenceTestFiles = map[string]string{
	"docker-compose.yml": `version: "3"
services:
  service:
    image: ubuntu
    command: tail -f /dev/null
    volumes:
    - "data:/data"

volumes:
  data:
`,
}

func testPersistence(ctx context.Context, t *testing.T) {
	dir, err := util.MakeTestDirectory(persistenceTestFiles)
	require.NoError(t, err)
	defer os.RemoveAll(dir)
	os.Chdir(dir)

	// Start blimp and create a file in the volume.
	upCtx, cancelUp := context.WithCancel(ctx)
	waitErr, err := util.Up(upCtx, "-d")
	require.NoError(t, err, "start blimp up")

	// As a sanity check, make sure that the file doesn't already exist. If it
	// does, it could be a sign that the file is geting added in some
	// unexpected way.
	const testFile = "/data/file"
	blimpAssert.FileExistence(t, "service", testFile, false)

	_, err = util.Run(ctx, "exec", "service", "touch", testFile)
	require.NoError(t, err, "create file")

	cancelUp()
	require.NoError(t, <-waitErr, "run blimp up")

	// Reattach blimp, and make sure the file is still there.
	upCtx, cancelUp = context.WithCancel(ctx)
	waitErr, err = util.Up(upCtx, "-d")
	require.NoError(t, err, "start blimp up")

	blimpAssert.FileExistence(t, "service", testFile, true)

	cancelUp()

	// Run `blimp down`. The file should still be there after running `blimp
	// up` again.
	_, err = util.Run(ctx, "down")
	require.NoError(t, err, "run blimp down")

	upCtx, cancelUp = context.WithCancel(ctx)
	waitErr, err = util.Up(upCtx, "-d")
	require.NoError(t, err, "start blimp up")

	blimpAssert.FileExistence(t, "service", testFile, true)

	cancelUp()

	// Run `blimp down -v`. The file should no longer be there after running
	// `blimp up` again.
	_, err = util.Run(ctx, "down", "-v")
	require.NoError(t, err, "run blimp down -v")

	upCtx, cancelUp = context.WithCancel(ctx)
	defer cancelUp()
	waitErr, err = util.Up(upCtx, "-d")
	require.NoError(t, err, "start blimp up")

	blimpAssert.FileExistence(t, "service", testFile, false)
}
