// This is not in dockercompose_test so that we can override the fs global
// variable.
package dockercompose

import (
	"testing"

	"github.com/kelda/compose-go/types"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"

	"github.com/kelda/blimp/pkg/errors"
)

func TestLoad(t *testing.T) {
	tests := []struct {
		name        string
		composeFile string
		expConfig   types.Config
		expError    error
	}{
		{
			name: "invalid YAML",
			composeFile: `version: "3"
ignoreme:
  foo
  bar:`,
			expError: errors.NewFriendlyError(
				"Failed to parse Compose file (docker-compose.yml)\n" +
					"Error: yaml: line 4: mapping values are not allowed in this context\n\n" +
					"3 |   foo\n" +
					"\x1b[33m4 |   bar:\x1b[0m"),
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			fs = afero.NewMemMapFs()
			assert.NoError(t, afero.WriteFile(fs, "docker-compose.yml", []byte(test.composeFile), 0644))
			config, err := Load("docker-compose.yml", nil, nil)
			assert.Equal(t, test.expError, err)
			assert.Equal(t, test.expConfig, config)
		})
	}
}
