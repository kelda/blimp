package main_test

import (
	"testing"

	"github.com/kelda/compose-go/types"
	"github.com/stretchr/testify/assert"

	main "github.com/kelda/blimp/cluster-controller"
)

func TestValidateFeatures(t *testing.T) {
	tests := []struct {
		cfg types.Project
		exp []string
	}{
		// All features are supported.
		{
			cfg: types.Project{
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
			cfg: types.Project{
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
			cfg: types.Project{
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
			cfg: types.Project{
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
			cfg: types.Project{
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
			cfg: types.Project{
				Volumes: map[string]types.VolumeConfig{
					"volume": {
						Name:   "volume",
						Driver: "driver",
					},
				},
			},
			exp: []string{"Volume.Driver"},
		},

		// Using a supported bind volume via local driver.
		{
			cfg: types.Project{
				Volumes: map[string]types.VolumeConfig{
					"volume": {
						Name:   "volume",
						Driver: "local",
						DriverOpts: map[string]string{
							"type":   "none",
							"device": "/home/user/volume",
							"o":      "bind",
						},
					},
				},
			},
			exp: nil,
		},

		// Using a mostly-supported bind volume via local driver.
		{
			cfg: types.Project{
				Volumes: map[string]types.VolumeConfig{
					"volume": {
						Name: "volume",
						DriverOpts: map[string]string{
							"device":  "/home/user/volume",
							"options": "bind,ro",
						},
					},
				},
			},
			exp: []string{"Volume.DriverOpts.options.ro"},
		},

		// Using unsupported local driver options.
		{
			cfg: types.Project{
				Volumes: map[string]types.VolumeConfig{
					"volume": {
						Name:   "volume",
						Driver: "local",
						DriverOpts: map[string]string{
							"type":   "nfs",
							"device": "server:/mount",
							"o":      "remount",
						},
					},
				},
			},
			exp: []string{"Volume.DriverOpts"},
		},
	}

	for _, test := range tests {
		assert.Equal(t, test.exp, main.GetUnsupportedFeatures(test.cfg))
	}
}
