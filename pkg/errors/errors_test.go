package errors_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kelda/blimp/pkg/errors"
)

func TestRootCause(t *testing.T) {
	errOne := errors.New("1")
	errTwo := errors.WithContext("2", errOne)
	errThree := errors.WithContext("3", errTwo)

	assert.Equal(t, errOne, errors.RootCause(errOne))
	assert.Equal(t, errOne, errors.RootCause(errTwo))
	assert.Equal(t, errOne, errors.RootCause(errThree))
}

func TestCause(t *testing.T) {
	errOne := errors.New("1")
	errTwo := errors.WithContext("2", errOne)
	errThree := errors.WithContext("3", errTwo)

	tests := []struct {
		arg      error
		expCause error
		expOK    bool
	}{
		{
			arg:      errOne,
			expCause: nil,
			expOK:    false,
		},
		{
			arg:      errTwo,
			expCause: errOne,
			expOK:    true,
		},
		{
			arg:      errThree,
			expCause: errTwo,
			expOK:    true,
		},
	}

	for _, test := range tests {
		actualCause, actualOK := errors.Cause(test.arg)
		assert.Equal(t, test.expCause, actualCause)
		assert.Equal(t, test.expOK, actualOK)
	}
}

func TestGetPrintableMessage(t *testing.T) {
	friendlyError := errors.NewFriendlyError("friendly error")
	wrappedFriendlyError := errors.WithContext("ignore me", friendlyError)

	assert.Equal(t, "friendly error", errors.GetPrintableMessage(friendlyError))
	assert.Equal(t, "friendly error", errors.GetPrintableMessage(wrappedFriendlyError))

	regularError := errors.New("regular error")
	wrappedRegularError := errors.WithContext("context", regularError)
	assert.Equal(t, "regular error", errors.GetPrintableMessage(regularError))
	assert.Equal(t, "context: regular error", errors.GetPrintableMessage(wrappedRegularError))
}

func TestNewFriendlyErrorFmt(t *testing.T) {
	err := errors.NewFriendlyError("%d fish, %d fish, %s fish, %s fish",
		1, 2, "red", "blue")
	assert.EqualError(t, err, "1 fish, 2 fish, red fish, blue fish")
}
