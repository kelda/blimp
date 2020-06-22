package errors_test

import (
	"context"
	goErrors "errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"

	"github.com/kelda/blimp/pkg/errors"
	proto "github.com/kelda/blimp/pkg/proto/errors"
)

type MsgWithCustomError struct {
	Error *proto.Error
}

type MsgWithoutCustomError struct{}

func TestUnaryClientInterceptor(t *testing.T) {
	tests := []struct {
		name      string
		mockReply interface{}
		mockError error
		expError  error
	}{
		{
			name:      "No custom error - non-nil gRPC error",
			mockReply: &MsgWithoutCustomError{},
			mockError: goErrors.New("grpc"),
			expError:  goErrors.New("grpc"),
		},
		{
			name:      "No custom error - no errors",
			mockReply: &MsgWithoutCustomError{},
			mockError: nil,
			expError:  nil,
		},
		{
			name:      "Custom error - non-nil gRPC error",
			mockReply: &MsgWithCustomError{},
			mockError: goErrors.New("grpc"),
			expError:  goErrors.New("grpc"),
		},
		{
			name: "Custom error - non-nil custom error",
			mockReply: &MsgWithCustomError{
				Error: errors.Marshal(errors.NewFriendlyError("friendly error")),
			},
			mockError: nil,
			expError:  errors.NewFriendlyError("friendly error"),
		},
		{
			name:      "Custom error - no errors",
			mockReply: &MsgWithCustomError{},
			mockError: nil,
			expError:  nil,
		},
		{
			name:      "Nil reply",
			mockReply: nil,
			mockError: nil,
			expError:  nil,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			invoker := func(_ context.Context, _ string, _, _ interface{},
				_ *grpc.ClientConn, _ ...grpc.CallOption) error {
				return test.mockError
			}

			err := errors.UnaryClientInterceptor(nil, "", nil, test.mockReply, nil, invoker)
			assert.Equal(t, test.expError, err)
		})
	}
}

func TestUnaryServerInterceptor(t *testing.T) {
	tests := []struct {
		name      string
		mockReply interface{}
		mockError error
		expReply  interface{}
		expError  error
	}{
		{
			name:      "No custom error - non-nil gRPC error",
			mockReply: &MsgWithoutCustomError{},
			mockError: goErrors.New("grpc"),
			expReply:  &MsgWithoutCustomError{},
			expError:  goErrors.New("grpc"),
		},
		{
			name:      "No custom error - no errors",
			mockReply: &MsgWithoutCustomError{},
			mockError: nil,
			expReply:  &MsgWithoutCustomError{},
			expError:  nil,
		},
		{
			name:      "Custom error - non-nil gRPC error",
			mockReply: &MsgWithCustomError{},
			mockError: goErrors.New("grpc"),
			expReply: &MsgWithCustomError{
				Error: errors.Marshal(goErrors.New("grpc")),
			},
			expError: nil,
		},
		{
			name:      "Custom error - non-nil custom error",
			mockReply: &MsgWithCustomError{},
			mockError: errors.NewFriendlyError("friendly error"),
			expReply: &MsgWithCustomError{
				Error: errors.Marshal(errors.NewFriendlyError("friendly error")),
			},
			expError: nil,
		},
		{
			name:      "Custom error - no errors",
			mockReply: &MsgWithCustomError{},
			mockError: nil,
			expReply:  &MsgWithCustomError{},
			expError:  nil,
		},
		{
			name:      "Nil reply",
			mockReply: nil,
			mockError: nil,
			expReply:  nil,
			expError:  nil,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			handler := func(_ context.Context, _ interface{}) (interface{}, error) {
				return test.mockReply, test.mockError
			}

			reply, err := errors.UnaryServerInterceptor(nil, nil, nil, handler)
			assert.Equal(t, test.expReply, reply)
			assert.Equal(t, test.expError, err)
		})
	}
}
