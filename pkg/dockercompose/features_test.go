package dockercompose

import (
	"testing"

	"github.com/compose-spec/compose-go/types"
	"github.com/stretchr/testify/assert"
)

func TestValidateFeatures(t *testing.T) {
	tests := []struct {
		cfg types.Config
		exp []string
	}{
		// All features are supported.
		{
			cfg: types.Config{
				Services: types.Services([]types.ServiceConfig{
					{
						Name:    "test",
						Image:   "alpine",
						Command: types.ShellCommand([]string{"echo", "hello world"}),
					},
				}),
				Networks: map[string]types.NetworkConfig{
					"network": {Name: "network"},
				},
			},
			exp: nil,
		},

		// Using an unsupported feature.
		{
			cfg: types.Config{
				Services: types.Services([]types.ServiceConfig{
					{
						Name:     "test",
						Image:    "alpine",
						Command:  types.ShellCommand([]string{"echo", "hello world"}),
						ReadOnly: true,
					},
				}),
			},
			exp: []string{"Service.ReadOnly"},
		},

		// Using a supported value for ports.
		{
			cfg: types.Config{
				Services: types.Services([]types.ServiceConfig{
					{
						Name:  "test",
						Image: "alpine",
						Ports: []types.ServicePortConfig{
							{Protocol: "tcp"},
						},
					},
				}),
			},
			exp: nil,
		},

		// Using an unsupported value for ports.
		{
			cfg: types.Config{
				Services: types.Services([]types.ServiceConfig{
					{
						Name:  "test",
						Image: "alpine",
						Ports: []types.ServicePortConfig{
							{Protocol: "udp"},
						},
					},
				}),
			},
			exp: []string{"Service.Ports.Protocol"},
		},

		// Using a supported field in volumes.
		{
			cfg: types.Config{
				Volumes: map[string]types.VolumeConfig{
					"volume": {
						Name: "volume",
					},
				},
			},
			exp: nil,
		},

		// Using an unsupported field in volumes.
		{
			cfg: types.Config{
				Volumes: map[string]types.VolumeConfig{
					"volume": {
						Name:   "volume",
						Driver: "driver",
					},
				},
			},
			exp: []string{"Volume.Driver"},
		},
	}

	for _, test := range tests {
		assert.Equal(t, test.exp, GetUnsupportedFeatures(test.cfg))
	}
}
