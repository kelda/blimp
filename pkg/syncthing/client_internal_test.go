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
		volumes []BindVolume
		exp     []Mount
	}{
		{
			name: "Sync directory",
			volumes: []BindVolume{
				{LocalPath: "/Users/kevin/kelda.io"},
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
			volumes: []BindVolume{
				{LocalPath: "/Users/kevin/kelda.io/file-1"},
				{LocalPath: "/Users/kevin/kelda.io/file-2"},
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
			volumes: []BindVolume{
				{LocalPath: "/Users/kevin/kelda.io"},
				{LocalPath: "/Users/kevin/kelda.io/file-1"},
				{LocalPath: "/Users/kevin/kelda.io/file-2"},
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
			volumes: []BindVolume{
				{LocalPath: "/Users/kevin/kelda.io"},
				{LocalPath: "/Users/kevin/kelda.io/files"},
				{LocalPath: "/Users/kevin/kelda.io/files/file-1"},
				{LocalPath: "/Users/kevin/kelda.io/files/file-2"},
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
			volumes: []BindVolume{
				{LocalPath: "/Users/kevin/kelda.io/top-level"},
				{LocalPath: "/Users/kevin/kelda.io/files/subdir"},
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
			volumes: []BindVolume{
				{LocalPath: "/Users/kevin/kelda.io/file-1"},
				{LocalPath: "/Users/kevin/kelda.io/dir"},
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
			volumes: []BindVolume{
				{LocalPath: "/Users/kevin/kelda.io/file-1"},
				{LocalPath: "/Users/kevin/kelda.io"},
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
			volumes: []BindVolume{
				{LocalPath: "/Users/kevin/dir-1/file"},
				{LocalPath: "/Users/kevin/dir-2/file"},
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
			volumes: []BindVolume{
				{LocalPath: "/Users/kevin/kelda.io/dir"},
				{LocalPath: "/Users/kevin/kelda.io"},
				{LocalPath: "/Users/kevin/sibling"},
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
		{
			name: "Sync directory with mask",
			volumes: []BindVolume{
				{
					LocalPath: "/Users/kevin/kelda.io",
					Masks:     []string{"masked"},
				},
			},
			dirs: []string{
				"/Users/kevin/kelda.io",
			},
			exp: []Mount{
				{
					Path:    "/Users/kevin/kelda.io",
					SyncAll: true,
					Ignore:  []string{"masked"},
				},
			},
		},
		{
			name: "Sync directory with multiple masks",
			volumes: []BindVolume{
				{
					LocalPath: "/Users/kevin/kelda.io",
					Masks: []string{
						"masked1",
						"masked2",
					},
				},
			},
			dirs: []string{
				"/Users/kevin/kelda.io",
			},
			exp: []Mount{
				{
					Path:    "/Users/kevin/kelda.io",
					SyncAll: true,
					Ignore: []string{
						"masked1",
						"masked2",
					},
				},
			},
		},
		{
			name: "Sync directory twice with same mask",
			volumes: []BindVolume{
				{
					LocalPath: "/Users/kevin/kelda.io",
					Masks:     []string{"masked"},
				},
				{
					LocalPath: "/Users/kevin/kelda.io",
					Masks:     []string{"masked"},
				},
			},
			dirs: []string{
				"/Users/kevin/kelda.io",
			},
			exp: []Mount{
				{
					Path:    "/Users/kevin/kelda.io",
					SyncAll: true,
					Ignore:  []string{"masked"},
				},
			},
		},
		{
			name: "Sync directory twice with only one mask",
			volumes: []BindVolume{
				{
					LocalPath: "/Users/kevin/kelda.io",
					Masks:     []string{"masked"},
				},
				{
					LocalPath: "/Users/kevin/kelda.io",
					Masks:     nil,
				},
			},
			dirs: []string{
				"/Users/kevin/kelda.io",
			},
			exp: []Mount{
				{
					Path:    "/Users/kevin/kelda.io",
					SyncAll: true,
					Ignore:  nil,
				},
			},
		},
		{
			name: "Sync nested directory with shared mask",
			volumes: []BindVolume{
				{
					LocalPath: "/Users/kevin/kelda.io",
					Masks:     []string{"subdir/masked"},
				},
				{
					LocalPath: "/Users/kevin/kelda.io/subdir",
					Masks:     []string{"masked"},
				},
			},
			dirs: []string{
				"/Users/kevin/kelda.io",
				"/Users/kevin/kelda.io/subdir",
			},
			exp: []Mount{
				{
					Path:    "/Users/kevin/kelda.io",
					SyncAll: true,
					Ignore:  []string{"subdir/masked"},
				},
			},
		},
		{
			name: "Sync nested directory with parent mask",
			volumes: []BindVolume{
				{
					LocalPath: "/Users/kevin/kelda.io",
					Masks:     []string{"subdir/masked"},
				},
				{
					LocalPath: "/Users/kevin/kelda.io/subdir",
					Masks:     nil,
				},
			},
			dirs: []string{
				"/Users/kevin/kelda.io",
				"/Users/kevin/kelda.io/subdir",
			},
			exp: []Mount{
				{
					Path:    "/Users/kevin/kelda.io",
					SyncAll: true,
					Ignore:  nil,
				},
			},
		},
		{
			name: "Sync nested directory with child mask",
			volumes: []BindVolume{
				{
					LocalPath: "/Users/kevin/kelda.io",
					Masks:     nil,
				},
				{
					LocalPath: "/Users/kevin/kelda.io/subdir",
					Masks:     []string{"masked"},
				},
			},
			dirs: []string{
				"/Users/kevin/kelda.io",
				"/Users/kevin/kelda.io/subdir",
			},
			exp: []Mount{
				{
					Path:    "/Users/kevin/kelda.io",
					SyncAll: true,
					Ignore:  nil,
				},
			},
		},
		{
			name: "Sync nested directory with parent mask above child",
			volumes: []BindVolume{
				{
					LocalPath: "/Users/kevin/kelda.io",
					Masks:     []string{"subdir"},
				},
				{
					LocalPath: "/Users/kevin/kelda.io/subdir/file",
				},
			},
			dirs: []string{
				"/Users/kevin/kelda.io",
				"/Users/kevin/kelda.io/subdir",
			},
			exp: []Mount{
				{
					Path:    "/Users/kevin/kelda.io",
					SyncAll: true,
					Ignore:  nil,
				},
			},
		},
		{
			name: "Nested masks",
			volumes: []BindVolume{
				{
					LocalPath: "/Users/kevin/kelda.io",
					Masks: []string{
						"masked",
						"masked/subdir",
					},
				},
			},
			dirs: []string{
				"/Users/kevin/kelda.io",
				"/Users/kevin/kelda.io/masked",
			},
			exp: []Mount{
				{
					Path:    "/Users/kevin/kelda.io",
					SyncAll: true,
					Ignore:  []string{"masked"},
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
