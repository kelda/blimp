package errors_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kelda/blimp/pkg/errors"
)

func TestMarshalUnmarshal(t *testing.T) {
	tests := []error{
		errors.New("error"),
		errors.WithContext("context", errors.New("error")),
		errors.NewFriendlyError("friendly error"),
		errors.WithContext("context", errors.NewFriendlyError("friendly error")),
		nil,
		errors.WithContext("context", nil),
	}
	for _, err := range tests {
		assert.Equal(t, err, errors.Unmarshal(nil, errors.Marshal(err)))
	}
}

func TestUnmarshalGRPCError(t *testing.T) {
	err := errors.New("grpc error")
	assert.Equal(t, err, errors.Unmarshal(err, nil))
}

type customFriendlyError struct {
	msg   string
	count int
}

func (err customFriendlyError) FriendlyMessage() string {
	return strings.Repeat(err.msg, err.count)
}

func (err customFriendlyError) Error() string {
	return "unused"
}

func TestMarshalCustomFriendlyError(t *testing.T) {
	err := customFriendlyError{"foo", 3}
	exp := errors.NewFriendlyError("foofoofoo")
	assert.Equal(t, exp, errors.Unmarshal(nil, errors.Marshal(err)))
}
