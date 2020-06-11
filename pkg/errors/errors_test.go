package errors

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRootCause(t *testing.T) {
	errOne := New("1")
	errTwo := WithContext("2", errOne)
	errThree := WithContext("3", errTwo)

	assert.Equal(t, errOne, RootCause(errOne))
	assert.Equal(t, errOne, RootCause(errTwo))
	assert.Equal(t, errOne, RootCause(errThree))
}

func TestCause(t *testing.T) {
	errOne := New("1")
	errTwo := WithContext("2", errOne)
	errThree := WithContext("3", errTwo)

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
		actualCause, actualOK := Cause(test.arg)
		assert.Equal(t, test.expCause, actualCause)
		assert.Equal(t, test.expOK, actualOK)
	}
}

func TestGetPrintableMessage(t *testing.T) {
	friendlyError := NewFriendlyError("friendly error")
	wrappedFriendlyError := WithContext("ignore me", friendlyError)

	assert.Equal(t, "friendly error", GetPrintableMessage(friendlyError))
	assert.Equal(t, "friendly error", GetPrintableMessage(wrappedFriendlyError))

	regularError := New("regular error")
	wrappedRegularError := WithContext("context", regularError)
	assert.Equal(t, "regular error", GetPrintableMessage(regularError))
	assert.Equal(t, "context: regular error", GetPrintableMessage(wrappedRegularError))
}

func TestNewFriendlyErrorFmt(t *testing.T) {
	err := NewFriendlyError("%d fish, %d fish, %s fish, %s fish",
		1, 2, "red", "blue")
	assert.EqualError(t, err, "1 fish, 2 fish, red fish, blue fish")
}
