package errors

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"

	proto "github.com/kelda-inc/blimp/pkg/proto/errors"
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
			mockError: errors.New("grpc"),
			expError:  errors.New("grpc"),
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
			mockError: errors.New("grpc"),
			expError:  errors.New("grpc"),
		},
		{
			name: "Custom error - non-nil custom error",
			mockReply: &MsgWithCustomError{
				Error: Marshal(NewFriendlyError("friendly error")),
			},
			mockError: nil,
			expError:  NewFriendlyError("friendly error"),
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

			err := UnaryClientInterceptor(nil, "", nil, test.mockReply, nil, invoker)
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
			mockError: errors.New("grpc"),
			expReply:  &MsgWithoutCustomError{},
			expError:  errors.New("grpc"),
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
			mockError: errors.New("grpc"),
			expReply: &MsgWithCustomError{
				Error: Marshal(errors.New("grpc")),
			},
			expError: nil,
		},
		{
			name:      "Custom error - non-nil custom error",
			mockReply: &MsgWithCustomError{},
			mockError: NewFriendlyError("friendly error"),
			expReply: &MsgWithCustomError{
				Error: Marshal(NewFriendlyError("friendly error")),
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

			reply, err := UnaryServerInterceptor(nil, nil, nil, handler)
			assert.Equal(t, test.expReply, reply)
			assert.Equal(t, test.expError, err)
		})
	}
}
