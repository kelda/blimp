package buildcache

import (
	"context"
	"testing"
)

type Test struct{}

func (test Test) Run(ctx context.Context, t *testing.T) {
	t.Run("Local", func(t *testing.T) { testBuildCache(ctx, t) })
	t.Run("Buildkit", func(t *testing.T) { testBuildCache(ctx, t, "--remote-build") })
}

func (test Test) GetName() string {
	return "BuildCache"
}
