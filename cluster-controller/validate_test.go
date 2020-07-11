package main_test

import (
	"testing"

	"github.com/kelda/compose-go/types"
	"github.com/stretchr/testify/assert"

	main "github.com/kelda-inc/blimp/cluster-controller"
)

func TestValidateComposeConfig(t *testing.T) {
	tests := []struct {
		cfg         types.Config
		expProblems []string
	}{
		// Basic compose file, no issues.
		{
			cfg: types.Config{
				Services: types.Services([]types.ServiceConfig{
					{
						Name:  "test",
						Image: "alpine",
					},
				}),
			},
			expProblems: []string{},
		},
		// Compose file with correct dependency.
		{
			cfg: types.Config{
				Services: types.Services([]types.ServiceConfig{
					{
						Name:  "test1",
						Image: "alpine",
					},
					{
						Name:  "test2",
						Image: "alpine",
						DependsOn: types.DependsOnConfig{
							"test1": types.ServiceDependency{
								Condition: types.ServiceConditionHealthy,
							},
						},
					},
				}),
			},
			expProblems: []string{},
		},
		// Invalid dependency.
		{
			cfg: types.Config{
				Services: types.Services([]types.ServiceConfig{
					{
						Name:  "test1",
						Image: "alpine",
						DependsOn: types.DependsOnConfig{
							"dne": types.ServiceDependency{
								Condition: types.ServiceConditionHealthy,
							},
						},
					},
					{
						Name:  "test2",
						Image: "alpine",
						DependsOn: types.DependsOnConfig{
							"test1": types.ServiceDependency{
								Condition: types.ServiceConditionHealthy,
							},
						},
					},
				}),
			},
			expProblems: []string{"The test1 service depends on \"dne\", which does not exist"},
		},
	}

	for _, test := range tests {
		assert.Equal(t, test.expProblems, main.ValidateComposeFile(test.cfg))
	}
}
