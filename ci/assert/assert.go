package assert

import (
	"context"
	"testing"
)

type Test interface {
	Run(context.Context, *testing.T)
	GetName() string
}

type Assertion func() error
