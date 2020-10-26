package assert

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/kelda/blimp/ci/util"
)

func FileExistence(t *testing.T, service, path string, shouldExist bool) {
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	_, err := util.Run(ctx, "exec", service, "test", "-f", path)
	if shouldExist {
		assert.NoError(t, err, fmt.Sprintf("%s should exist", path))
	} else {
		assert.NotNil(t, err, fmt.Sprintf("%s should not exist", path))
	}
}
