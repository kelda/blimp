// +build ci

package main

import (
	"context"
	goBuild "go/build"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	blimpAssert "github.com/kelda/blimp/ci/assert"
	"github.com/kelda/blimp/ci/examples"
	"github.com/kelda/blimp/ci/file"
	"github.com/kelda/blimp/ci/tests/build"
	"github.com/kelda/blimp/ci/tests/buildcache"
	"github.com/kelda/blimp/ci/tests/logs"
	"github.com/kelda/blimp/ci/tests/volume"
	"github.com/kelda/blimp/ci/util"
)

func TestBlimp(t *testing.T) {
	reposRoot := filepath.Join(goBuild.Default.GOPATH, "src")

	tests := []blimpAssert.Test{
		examples.Test{
			Name:       "NodeTodo",
			WorkingDir: filepath.Join(reposRoot, "github.com/kelda/node-todo"),
			Tests: []blimpAssert.Test{
				blimpAssert.HTTPPostTest{
					Name:     "AddTodo",
					Endpoint: "http://localhost:8080/api/todos",
					Body:     map[string]interface{}{"text": "test"},
				},
				blimpAssert.CodeChangeTest{
					Name:     "CodeChange",
					CodePath: "app/routes.js",

					// Uncomment the sample code change.
					FileChange:           file.Replace("        // Uncomment the following line to add 'Kelda: ' before each todo item.\n        //", ""),
					InitialResponseCheck: blimpAssert.HTTPGetShouldNotContain("http://localhost:8080/api/todos", "Kelda: test"),
					ChangedResponseCheck: blimpAssert.HTTPGetShouldContain("http://localhost:8080/api/todos", "Kelda: test"),
				},
			},
		},

		// Same test as above, but with the local Docker build Compose file.
		examples.Test{
			Name:       "NodeTodoDockerfile",
			WorkingDir: filepath.Join(reposRoot, "github.com/kelda/node-todo"),
			UpArgs:     []string{"-f", "docker-compose-local-build.yml"},
			Tests: []blimpAssert.Test{
				blimpAssert.HTTPPostTest{
					Name:     "AddTodo",
					Endpoint: "http://localhost:8080/api/todos",
					Body:     map[string]interface{}{"text": "test"},
				},
				blimpAssert.CodeChangeTest{
					Name:     "CodeChange",
					CodePath: "app/routes.js",

					// Uncomment the sample code change.
					FileChange:           file.Replace("        // Uncomment the following line to add 'Kelda: ' before each todo item.\n        //", ""),
					InitialResponseCheck: blimpAssert.HTTPGetShouldNotContain("http://localhost:8080/api/todos", "Kelda: test"),
					ChangedResponseCheck: blimpAssert.HTTPGetShouldContain("http://localhost:8080/api/todos", "Kelda: test"),
				},
			},
		},

		// Same test as above, but using the remote builder.
		examples.Test{
			Name:       "NodeTodoDockerfileBuildkit",
			WorkingDir: filepath.Join(reposRoot, "github.com/kelda/node-todo"),
			UpArgs:     []string{"-f", "docker-compose-local-build.yml", "--remote-build"},
			Tests: []blimpAssert.Test{
				blimpAssert.HTTPPostTest{
					Name:     "AddTodo",
					Endpoint: "http://localhost:8080/api/todos",
					Body:     map[string]interface{}{"text": "test"},
				},
				blimpAssert.CodeChangeTest{
					Name:     "CodeChange",
					CodePath: "app/routes.js",

					// Uncomment the sample code change.
					FileChange:           file.Replace("        // Uncomment the following line to add 'Kelda: ' before each todo item.\n        //", ""),
					InitialResponseCheck: blimpAssert.HTTPGetShouldNotContain("http://localhost:8080/api/todos", "Kelda: test"),
					ChangedResponseCheck: blimpAssert.HTTPGetShouldContain("http://localhost:8080/api/todos", "Kelda: test"),
				},
			},
		},

		examples.Test{
			Name:       "Extends",
			WorkingDir: filepath.Join(reposRoot, "github.com/kelda/blimp/ci/tests/extends"),
			Tests: []blimpAssert.Test{
				blimpAssert.HTTPGetTest{
					Name:     "Get",
					Endpoint: "http://localhost:8000/extends.html",
					Expected: []byte("Extended\n"),
				},
				blimpAssert.HTTPGetTest{
					Name:     "Get",
					Endpoint: "http://localhost:8000/base.html",
					Expected: []byte("Base\n"),
				},
			},
		},

		examples.Test{
			Name:       "VolumeInitSymlink",
			WorkingDir: filepath.Join(reposRoot, "github.com/kelda/blimp/ci/tests/volume-init-symlink"),
			Tests: []blimpAssert.Test{
				blimpAssert.HTTPGetTest{
					Name:     "Get",
					Endpoint: "http://localhost:8000/bind.html",
					Expected: []byte("from-bind\n"),
				},
				blimpAssert.HTTPGetTest{
					Name:     "Get",
					Endpoint: "http://localhost:8000/masked/masked.html",
					Expected: []byte("from-dockerfile\n"),
				},
			},
		},

		examples.Test{
			Name: "BuildOptionsLocal",
			// Don't start blimp from the same directory as the compose file to
			// test path resolution.
			UpArgs:     []string{"-f", "tests/buildopts/docker-compose.yml", "--build"},
			WorkingDir: filepath.Join(reposRoot, "github.com/kelda/blimp/ci"),
			Tests: []blimpAssert.Test{
				blimpAssert.HTTPGetTest{
					Name:     "Get",
					Endpoint: "http://localhost:8000",
					Expected: []byte("base\nfrom-compose\n"),
				},
			},
		},

		examples.Test{
			Name: "BuildOptionsBuildkit",
			// Don't start blimp from the same directory as the compose file to
			// test path resolution.
			UpArgs:     []string{"-f", "tests/buildopts/docker-compose.yml", "--remote-build", "--build"},
			WorkingDir: filepath.Join(reposRoot, "github.com/kelda/blimp/ci"),
			Tests: []blimpAssert.Test{
				blimpAssert.HTTPGetTest{
					Name:     "Get",
					Endpoint: "http://localhost:8000",
					Expected: []byte("base\nfrom-compose\n"),
				},
			},
		},

		volume.Test{},
		logs.Test{},
		build.Test{},
		buildcache.Test{},
	}

	for _, test := range tests {
		t.Run(test.GetName(), func(t *testing.T) {
			// Restore the working directory after the test in case the test
			// changes it.
			oldWd, err := os.Getwd()
			require.NoError(t, err)
			defer os.Chdir(oldWd)

			// Clean up the namespace before each test.
			// We delete volumes so that the state is completely fresh for each
			// test.
			// XXX: Make `blimp down` not error if the namespace doesn't
			// exist, and check the returned error.
			util.Run(context.Background(), "down", "-v")

			test.Run(context.Background(), t)
		})
	}
}
