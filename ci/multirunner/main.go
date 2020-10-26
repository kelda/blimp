package main

import (
	"flag"
	"fmt"
	"go/build"
	"io/ioutil"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/kelda/blimp/pkg/errors"
)

// Must be run from the root of the Blimp repo.

var random = rand.New(
	rand.NewSource(time.Now().UnixNano()))

func main() {
	concurrency := flag.Int("concurrency", 1, "")
	runRegex := flag.String("run", "", "")
	flag.Parse()

	log.SetFormatter(&log.TextFormatter{FullTimestamp: true})
	if err := run(*concurrency, *runRegex); err != nil {
		fmt.Printf("Test failed: %s\n", err)
		os.Exit(1)
	}
}

type testResult struct {
	id       int
	output   []byte
	err      error
	duration time.Duration
}

func run(concurrency int, runRegex string) error {
	managerHost := os.Getenv("MANAGER_HOST")
	managerHost = strings.Replace(managerHost, "localhost", "host.docker.internal", 1)

	log.Info("Building test runner image")
	err := buildRunnerImage(managerHost)
	if err != nil {
		return errors.WithContext("build base image", err)
	}

	log.Info("Starting tests")
	testResults := make(chan testResult, concurrency)
	for id := 1; id <= concurrency; id++ {
		id := id
		go func() {
			// Clean up the old test runner if it exists.
			runCommand("docker", "rm", "-f", containerName(id))

			// Auth0's Authentication API has a global limit of 300 requests
			// per minute for free tenants.
			time.Sleep(time.Duration(random.Intn(30)) * time.Second)

			// Run the test.
			start := time.Now()
			output, err := runTest(id,
				fmt.Sprintf("_internal-scale-testing+%d@kelda.io", id),
				"VBiJH2tL7Mg?bvZvbTzNAiZ{",
				runRegex,
			)
			testDuration := time.Now().Sub(start)
			testResults <- testResult{
				id:       id,
				output:   output,
				err:      err,
				duration: testDuration,
			}

			// Remove the test runner immediately if the test passed.
			if err == nil {
				runCommand("docker", "exec", containerName(id), "blimp", "down")
				runCommand("docker", "rm", "-f", containerName(id))
			}
		}()
	}

	// Collect the test results.
	var failures int
	for i := 0; i < concurrency; i++ {
		fmt.Println()

		result := <-testResults
		if result.err == nil && result.duration > 40*time.Minute {
			result.err = errors.New("test passed, but took too long (%s)", result.duration)
		}

		msg := "RUNNER PASSED"
		fields := log.Fields{
			"id":       result.id,
			"duration": result.duration,
		}
		if result.err != nil {
			fields["error"] = result.err
			msg = "RUNNER FAILED"
			failures++
		}

		log.WithFields(fields).Info(msg)
		fmt.Println(string(result.output))
	}

	fmt.Println()
	if failures == 0 {
		fmt.Println("ALL RUNNERS PASSED")
		os.Exit(0)
	} else {
		fmt.Printf("%d / %d RUNNERS FAILED\n", failures, concurrency)
		os.Exit(1)
	}
	return nil
}

func buildRunnerImage(managerHost string) error {
	buildCtx, err := ioutil.TempDir("", "blimp-test-runner")
	if err != nil {
		return errors.WithContext("make build context dir", err)
	}
	defer os.RemoveAll(buildCtx)

	dockerfileLines := []string{
		"FROM golang:1.13",
		"RUN apt-get update && apt-get install ca-certificates",
		"GO-COPY github.com/kelda/node-todo",

		// Install dependencies.
		"WORKDIR /go/src/github.com/kelda/blimp",
		"GO-COPY github.com/kelda/blimp/Makefile",
		"RUN make go-get",

		"WORKDIR /go/src/github.com/kelda-inc/blimp",
		"GO-COPY github.com/kelda-inc/blimp/go.mod",
		"GO-COPY github.com/kelda-inc/blimp/go.sum",
		"RUN go mod download",

		// Build the CLI.
		"WORKDIR /go/src/github.com/kelda/blimp",
		"GO-COPY github.com/kelda/blimp",
		"RUN make build-cli-linux && mv ./blimp-linux /usr/local/bin/blimp",

		// Build the tests.
		"WORKDIR /go/src/github.com/kelda-inc/blimp",
		"GO-COPY github.com/kelda-inc/blimp",
		"RUN go test -v -c -o /usr/local/bin/run-tests --tags ci --timeout 0 ./ci",
		fmt.Sprintf("ENV MANAGER_HOST=%s", managerHost),
	}

	// Resolve the COPY statements to their full source and destination.
	for i, line := range dockerfileLines {
		if !strings.HasPrefix(line, "GO-COPY") {
			continue
		}

		parts := strings.Split(line, " ")
		if len(parts) != 2 {
			return errors.New("malformed GO-COPY: %s", line)
		}

		localPath := parts[1]
		pathInBuildCtx := filepath.Join("go/src", localPath)
		buildCtxPath := filepath.Join(buildCtx, pathInBuildCtx)
		if err := os.MkdirAll(filepath.Dir(buildCtxPath), 0755); err != nil {
			return errors.WithContext("make directory for repo", err)
		}

		err := runCommand("cp",
			// Copy all the contents of the directory.
			"-R",
			// Follow symlinks (this is necessary to copy github.com/kelda/blimp/certs).
			"-L",
			filepath.Join(build.Default.GOPATH, "src", localPath),
			filepath.Dir(buildCtxPath))
		if err != nil {
			return errors.WithContext("copy repo", err)
		}

		dockerfileLines[i] = fmt.Sprintf("COPY %s /%s", pathInBuildCtx, pathInBuildCtx)
	}

	dockerfile := strings.Join(dockerfileLines, "\n")
	err = ioutil.WriteFile(filepath.Join(buildCtx, "Dockerfile"), []byte(dockerfile), 0644)
	if err != nil {
		return errors.WithContext("write dockerfile", err)
	}

	// Ignore .git so that it doesn't invalidate the build cache.
	err = ioutil.WriteFile(filepath.Join(buildCtx, ".dockerignore"), []byte("**/.git"), 0644)
	if err != nil {
		return errors.WithContext("write .dockerignore", err)
	}

	buildCmd := exec.Command("docker", "build", "-t", "blimp-test-runner", buildCtx)
	buildCmd.Stdout = os.Stdout
	buildCmd.Stderr = os.Stderr
	if err := buildCmd.Run(); err != nil {
		return errors.WithContext("build image", err)
	}
	return nil
}

func runCommand(command string, args ...string) error {
	output, err := exec.Command(command, args...).CombinedOutput()
	if err != nil {
		return errors.New("command failed (%s): %s", err, string(output))
	}
	return nil
}

func runTest(id int, username, password, runRegex string) ([]byte, error) {
	out, err := exec.Command("docker", "run",
		"-v", "/var/run/docker.sock:/var/run/docker.sock",
		"--name", containerName(id),
		"--detach",
		"blimp-test-runner",
		"tail", "-f", "/dev/null").CombinedOutput()
	if err != nil {
		return out, errors.WithContext("start test container", err)
	}

	testCmd := "run-tests -test.v"
	if runRegex != "" {
		testCmd += " -test.run " + runRegex
	}
	return exec.Command("docker", "exec", containerName(id), "bash", "-c",
		fmt.Sprintf("set -o pipefail; "+
			"blimp loginpw --username %s --password %s && %s |& tee /proc/1/fd/1",
			username, password, testCmd)).CombinedOutput()
}

func containerName(id int) string {
	return fmt.Sprintf("blimp-test-runner-%d", id)
}
