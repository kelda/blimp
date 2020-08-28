package build

import (
	composeTypes "github.com/kelda/compose-go/types"
)

type Interface interface {
	// BuildAndPush takes a map of service names to their build/push configs,
	// and returns a mapping from service names to the pushed image names.
	BuildAndPush(serviceConfigs map[string]BuildPushConfig) (map[string]string, error)
}

type BuildPushConfig struct {
	composeTypes.BuildConfig
	ImageName   string
	ForceBuild  bool
	PullParent  bool
	NoCache     bool
}
