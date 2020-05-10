package errors

import (
	proto "github.com/kelda-inc/blimp/pkg/proto/errors"
)

// Marshal converts an error (that may contain custom Kelda error types) into
// an error that can be transmitted over gRPC, and unmarshalled on the other
// side.
func Marshal(err error) *proto.Error {
	if err == nil {
		return nil
	}

	if contextErr, ok := err.(ContextError); ok {
		return &proto.Error{
			ContextError: &proto.ContextError{
				Context: contextErr.Context(),
				Error:   Marshal(contextErr.Cause()),
			},
		}
	}

	if friendlyErr, ok := err.(FriendlyError); ok {
		return &proto.Error{
			FriendlyError: &proto.FriendlyError{
				FriendlyMessage: friendlyErr.FriendlyMessage(),
			},
		}
	}

	return &proto.Error{Text: err.Error()}
}

// Unmarshal reconstructs an error created by Marshal. It also takes the error
// returned by gRPC for easy handling in client logic.
func Unmarshal(grpcErr error, protoErr *proto.Error) error {
	if grpcErr != nil {
		return grpcErr
	}
	return unmarshalProtoError(protoErr)
}

func unmarshalProtoError(protoErr *proto.Error) error {
	if protoErr == nil {
		return nil
	}

	if protoErr.FriendlyError != nil {
		return friendlyErrorImpl{
			message: protoErr.FriendlyError.FriendlyMessage,
		}
	}

	if protoErr.ContextError != nil {
		return contextErrorImpl{
			err:     unmarshalProtoError(protoErr.ContextError.Error),
			context: protoErr.ContextError.Context,
		}
	}

	return New(protoErr.Text)
}
