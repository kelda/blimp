package syncthing

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCalculateMounts(t *testing.T) {
	tests := []struct {
		name    string
		dirs    []string
		volumes []string
		exp     []Mount
	}{
		{
			name: "Sync directory",
			volumes: []string{
				"/Users/kevin/kelda.io",
			},
			dirs: []string{
				"/Users/kevin/kelda.io",
			},
			exp: []Mount{
				{
					Path:    "/Users/kevin/kelda.io",
					SyncAll: true,
				},
			},
		},
		{
			name: "Sync two files in same dir",
			volumes: []string{
				"/Users/kevin/kelda.io/file-1",
				"/Users/kevin/kelda.io/file-2",
			},
			dirs: []string{
				"/Users/kevin/kelda.io",
			},
			exp: []Mount{
				{
					Path: "/Users/kevin/kelda.io",
					Include: []string{
						"file-1",
						"file-2",
					},
				},
			},
		},
		{
			name: "Sync two files in same dir and parent dir",
			volumes: []string{
				"/Users/kevin/kelda.io",
				"/Users/kevin/kelda.io/file-1",
				"/Users/kevin/kelda.io/file-2",
			},
			dirs: []string{
				"/Users/kevin/kelda.io",
			},
			exp: []Mount{
				{
					Path:    "/Users/kevin/kelda.io",
					SyncAll: true,
				},
			},
		},
		{
			name: "Nested syncs",
			volumes: []string{
				"/Users/kevin/kelda.io",
				"/Users/kevin/kelda.io/files",
				"/Users/kevin/kelda.io/files/file-1",
				"/Users/kevin/kelda.io/files/file-2",
			},
			dirs: []string{
				"/Users/kevin/kelda.io",
				"/Users/kevin/kelda.io/files",
			},
			exp: []Mount{
				{
					Path:    "/Users/kevin/kelda.io",
					SyncAll: true,
				},
			},
		},
		{
			name: "Nested syncs with top-level file",
			volumes: []string{
				"/Users/kevin/kelda.io/top-level",
				"/Users/kevin/kelda.io/files/subdir",
			},
			dirs: []string{
				"/Users/kevin/kelda.io",
				"/Users/kevin/kelda.io/files",
				"/Users/kevin/kelda.io/files/subdir",
			},
			exp: []Mount{
				{
					Path: "/Users/kevin/kelda.io",
					Include: []string{
						"top-level",
						"files/subdir",
					},
				},
			},
		},
		{
			name: "Top level file sync with nested dir sync",
			volumes: []string{
				"/Users/kevin/kelda.io/file-1",
				"/Users/kevin/kelda.io/dir",
			},
			dirs: []string{
				"/Users/kevin/kelda.io",
				"/Users/kevin/kelda.io/dir",
			},
			exp: []Mount{
				{
					Path: "/Users/kevin/kelda.io",
					Include: []string{
						"file-1",
						"dir",
					},
				},
			},
		},
		{
			name: "Syncing entire directory and nested file, with the file coming first",
			volumes: []string{
				"/Users/kevin/kelda.io/file-1",
				"/Users/kevin/kelda.io",
			},
			dirs: []string{
				"/Users/kevin/kelda.io",
			},
			exp: []Mount{
				{
					Path:    "/Users/kevin/kelda.io",
					SyncAll: true,
				},
			},
		},
		{
			name: "Multiple mounts",
			volumes: []string{
				"/Users/kevin/dir-1/file",
				"/Users/kevin/dir-2/file",
			},
			dirs: []string{
				"/Users/kevin/kelda.io",
				"/Users/kevin/dir-1",
				"/Users/kevin/dir-2",
			},
			exp: []Mount{
				{
					Path: "/Users/kevin/dir-1",
					Include: []string{
						"file",
					},
				},
				{
					Path: "/Users/kevin/dir-2",
					Include: []string{
						"file",
					},
				},
			},
		},
		{
			name: "Syncing entire directory and nested directory, as well as a sibling file",
			volumes: []string{
				"/Users/kevin/kelda.io/dir",
				"/Users/kevin/kelda.io",
				"/Users/kevin/sibling",
			},
			dirs: []string{
				"/Users/kevin/kelda.io",
				"/Users/kevin/kelda.io/dir",
			},
			exp: []Mount{
				{
					Path: "/Users/kevin",
					Include: []string{
						"sibling",
						"kelda.io",
					},
				},
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			isDir = func(path string) bool {
				for _, dir := range test.dirs {
					if filepath.Clean(path) == filepath.Clean(dir) {
						return true
					}
				}
				return false
			}

			actual := NewClient(test.volumes)
			assert.Equal(t, test.exp, actual.mounts)
		})
	}
}
