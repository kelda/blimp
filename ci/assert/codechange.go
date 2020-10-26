package assert

import (
	"context"
	"io/ioutil"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kelda-inc/blimp/ci/file"
	"github.com/kelda-inc/blimp/ci/util"
)

// CodeChangeTest tests that Kelda properly syncs files by modifying a file,
// and checking the HTTP response.
type CodeChangeTest struct {
	Name string

	// The path to the file that we're going to change.
	CodePath string

	// The modification that should be made to CodePath.
	FileChange file.Modifier

	// The expected response before the code is changed.
	InitialResponseCheck Assertion

	// The expected response after the code is changed.
	ChangedResponseCheck Assertion
}

func (test CodeChangeTest) Run(ctx context.Context, t *testing.T) {
	// Restore the test file after the test.
	origContents, err := ioutil.ReadFile(test.CodePath)
	require.NoError(t, err, "read")
	defer func() {
		require.NoError(t, ioutil.WriteFile(test.CodePath, origContents, 0644), "restore")
	}()

	log.Info("Running initial check")
	assert.NoError(t, test.InitialResponseCheck())

	log.Info("Modifying file")
	require.NoError(t, file.Modify(test.CodePath, test.FileChange))

	// TODO: Check the Syncthing API or something.
	log.Info("Waiting for new code to sync")
	time.Sleep(20 * time.Second)

	log.Info("Checking new code was deployed")
	waitCtx, _ := context.WithTimeout(ctx, 1*time.Minute)
	deployed := func() bool {
		err := test.ChangedResponseCheck()
		if err != nil {
			log.WithError(err).Error("Modified code isn't deployed. Will retry.")
			return false
		}
		return true
	}
	if !util.TestWithRetry(waitCtx, nil, deployed) {
		t.Error("Code wasn't deployed")
	}
}

func (test CodeChangeTest) GetName() string {
	return test.Name
}
