package examples

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	blimpAssert "github.com/kelda-inc/blimp/ci/assert"
	"github.com/kelda-inc/blimp/ci/util"
)

type Test struct {
	Name       string
	WorkingDir string
	UpArgs     []string
	Tests      []blimpAssert.Test
}

func (test Test) GetName() string {
	return test.Name
}

func (test Test) Run(ctx context.Context, t *testing.T) {
	if test.WorkingDir != "" {
		require.NoError(t, os.Chdir(test.WorkingDir), "set working directory for test")
	}

	testCtx, cancelTest := context.WithCancel(ctx)
	upCtx, cancelUp := context.WithCancel(testCtx)
	waitErr, err := util.Up(upCtx, test.UpArgs...)
	require.NoError(t, err, "start blimp up")
	exited := make(chan bool)
	go func() {
		assert.NoError(t, <-waitErr, "run blimp up")
		cancelTest()
		exited <- true
	}()
	defer func() {
		cancelUp()
		// Wait for the process to exit before moving to the next test.
		<-exited
	}()

	// Wait for the service to start listening (it takes some time for the
	// service to actually initialize and bind to the port within the container).
	time.Sleep(20 * time.Second)

	for _, test := range test.Tests {
		t.Run(test.GetName(), func(t *testing.T) {
			test.Run(testCtx, t)
		})
	}
}
