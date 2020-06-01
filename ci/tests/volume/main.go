package volume

import (
	"context"
	"testing"
)

type Test struct{}

func (test Test) Run(ctx context.Context, t *testing.T) {
	t.Run("Permissions", func(t *testing.T) { testVolumePermissions(ctx, t) })
}

func (test Test) GetName() string {
	return "Volume"
}
