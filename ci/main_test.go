// +build ci

package main

import (
	"go/build"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	blimpAssert "github.com/kelda-inc/blimp/ci/assert"
)

func TestBlimp(t *testing.T) {
	reposRoot := filepath.Join(build.Default.GOPATH, "src")

	tests := []struct {
		name         string
		repo         string
		composePaths []string
		tests        []blimpAssert.Test
	}{
		{
			name: "NodeTodo",
			repo: "github.com/kelda/node-todo",
			tests: []blimpAssert.Test{
				{
					Name: "AddTodo",
					Test: blimpAssert.HTTPPostTest{
						Endpoint: "http://localhost:8080/api/todos",
						Body:     map[string]interface{}{"text": "test"},
					},
				},
				{
					Name: "CodeChange",
					Test: blimpAssert.CodeChangeTest{
						CodePath: "app/routes.js",

						// Uncomment the sample code change.
						FileChange:           blimpAssert.Replace("        // Uncomment the following line to add 'Kelda: ' before each todo item.\n        //", ""),
						InitialResponseCheck: blimpAssert.HTTPGetShouldNotContain("http://localhost:8080/api/todos", "Kelda: test"),
						ChangedResponseCheck: blimpAssert.HTTPGetShouldContain("http://localhost:8080/api/todos", "Kelda: test"),
					},
				},
			},
		},

		// Same test as above, but with the local Docker build Compose file.
		{
			name:         "NodeTodoDockerfile",
			repo:         "github.com/kelda/node-todo",
			composePaths: []string{"docker-compose-local-build.yml"},
			tests: []blimpAssert.Test{
				{
					Name: "AddTodo",
					Test: blimpAssert.HTTPPostTest{
						Endpoint: "http://localhost:8080/api/todos",
						Body:     map[string]interface{}{"text": "test"},
					},
				},
				{
					Name: "CodeChange",
					Test: blimpAssert.CodeChangeTest{
						CodePath: "app/routes.js",

						// Uncomment the sample code change.
						FileChange:           blimpAssert.Replace("        // Uncomment the following line to add 'Kelda: ' before each todo item.\n        //", ""),
						InitialResponseCheck: blimpAssert.HTTPGetShouldNotContain("http://localhost:8080/api/todos", "Kelda: test"),
						ChangedResponseCheck: blimpAssert.HTTPGetShouldContain("http://localhost:8080/api/todos", "Kelda: test"),
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			oldWd, err := os.Getwd()
			require.NoError(t, err)
			defer os.Chdir(oldWd)

			require.NoError(t, os.Chdir(filepath.Join(reposRoot, test.repo)), "Set working directory for test")
			blimpAssert.RunTests(t, test.composePaths, test.tests)
		})
	}
}
