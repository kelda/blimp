package assert

import (
	"bytes"
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kelda-inc/blimp/ci/util"
	"github.com/kelda-inc/blimp/pkg/errors"
)

type Test struct {
	Name string
	Test TestInterface
}

type TestInterface interface {
	Run(context.Context, *testing.T)
}

func RunTests(t *testing.T, composePaths []string, tests []Test) {
	var upArgs []string
	for _, path := range composePaths {
		upArgs = append(upArgs, "-f", path)
	}

	testCtx, cancelTest := context.WithCancel(context.Background())
	upCtx, cancelUp := context.WithCancel(testCtx)
	waitErr, err := util.Up(upCtx, upArgs...)
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

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			test.Test.Run(testCtx, t)
		})
	}
}

// CodeChangeTest tests that Kelda properly syncs files by modifying a file,
// and checking the HTTP response.
type CodeChangeTest struct {
	// The path to the file that we're going to change.
	CodePath string

	// The modification that should be made to CodePath.
	FileChange FileModifier

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
	require.NoError(t, ModifyFile(test.CodePath, test.FileChange))

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

type HTTPPostTest struct {
	Endpoint string
	Body     map[string]interface{}
}

func (test HTTPPostTest) Run(_ context.Context, t *testing.T) {
	jsonBody, err := json.Marshal(test.Body)
	if err != nil {
		require.NoError(t, err, "marshal json")
	}

	resp, err := http.Post(test.Endpoint, "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		require.NoError(t, err, "post")
	}

	// Close the body to avoid leaking resources.
	resp.Body.Close()
}

type HTTPGetTest struct {
	Endpoint string
}

func (test HTTPGetTest) Run(_ context.Context, t *testing.T) {
	resp, err := http.Get(test.Endpoint)
	if err != nil {
		require.NoError(t, err, "get")
	}

	// Close the body to avoid leaking resources.
	resp.Body.Close()
}

type FileModifier func(string) (string, error)

func ModifyFile(path string, modFn FileModifier) error {
	f, err := ioutil.ReadFile(path)
	if err != nil {
		return errors.WithContext("read", err)
	}

	modified, err := modFn(string(f))
	if err != nil {
		return errors.WithContext("modify", err)
	}

	err = ioutil.WriteFile(path, []byte(modified), 0644)
	if err != nil {
		return errors.WithContext("write", err)
	}
	return nil
}

func Replace(currStr, newStr string) FileModifier {
	return func(f string) (string, error) {
		if !strings.Contains(f, currStr) {
			return "", errors.New("file doesn't contain expected string. The test is probably buggy")
		}
		return strings.Replace(f, currStr, newStr, -1), nil
	}
}

func DeleteLine(linesToDelete ...int) FileModifier {
	return func(f string) (string, error) {
		var resultLines []string
		for i, line := range strings.Split(f, "\n") {
			var shouldSkip bool
			for _, toDelete := range linesToDelete {
				if i+1 == toDelete {
					shouldSkip = true
					break
				}
			}
			if shouldSkip {
				continue
			}

			resultLines = append(resultLines, line)
		}

		return strings.Join(resultLines, "\n"), nil
	}
}
