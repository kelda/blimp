// +build ci

package main

import (
	"context"
	"go/build"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	blimpAssert "github.com/kelda-inc/blimp/ci/assert"
	"github.com/kelda-inc/blimp/ci/examples"
	"github.com/kelda-inc/blimp/ci/file"
)

func TestBlimp(t *testing.T) {
	reposRoot := filepath.Join(build.Default.GOPATH, "src")

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
			Name:         "NodeTodoDockerfile",
			WorkingDir:   filepath.Join(reposRoot, "github.com/kelda/node-todo"),
			ComposePaths: []string{"docker-compose-local-build.yml"},
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
	}

	for _, test := range tests {
		t.Run(test.GetName(), func(t *testing.T) {
			// Restore the working directory after the test in case the test
			// changes it.
			oldWd, err := os.Getwd()
			require.NoError(t, err)
			defer os.Chdir(oldWd)

			test.Run(context.Background(), t)
		})
	}
}
