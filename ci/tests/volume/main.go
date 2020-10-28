package volume

import (
	"context"
	"testing"
)

type Test struct{}

func (test Test) Run(ctx context.Context, t *testing.T) {
	t.Run("Shared", func(t *testing.T) { testSharedVolumes(ctx, t) })
	t.Run("Permissions", func(t *testing.T) { testVolumePermissions(ctx, t) })
	t.Run("Persistence", func(t *testing.T) { testPersistence(ctx, t) })
}

func (test Test) GetName() string {
	return "Volume"
}
