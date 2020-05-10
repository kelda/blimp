package errors

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMarshalUnmarshal(t *testing.T) {
	tests := []error{
		New("error"),
		WithContext("context", New("error")),
		NewFriendlyError("friendly error"),
		WithContext("context", NewFriendlyError("friendly error")),
		nil,
		WithContext("context", nil),
	}
	for _, err := range tests {
		assert.Equal(t, err, Unmarshal(nil, Marshal(err)))
	}
}

func TestUnmarshalGRPCError(t *testing.T) {
	err := New("grpc error")
	assert.Equal(t, err, Unmarshal(err, nil))
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
	exp := NewFriendlyError("foofoofoo")
	assert.Equal(t, exp, Unmarshal(nil, Marshal(err)))
}
