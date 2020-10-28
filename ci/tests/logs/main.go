package logs

import (
	"context"
	"testing"
)

type Test struct{}

func (test Test) Run(ctx context.Context, t *testing.T) {
	t.Run("NoFollow", func(t *testing.T) { testNoFollow(ctx, t) })
}

func (test Test) GetName() string {
	return "Logs"
}
