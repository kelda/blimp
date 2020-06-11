package errors

import (
	"context"
	"reflect"

	"google.golang.org/grpc"

	proto "github.com/kelda/blimp/pkg/proto/errors"
)

func UnaryClientInterceptor(ctx context.Context, method string, req, reply interface{},
	cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {

	grpcErr := invoker(ctx, method, req, reply, cc, opts...)
	protoErr, ok := getWrappedError(reply)
	if !ok {
		protoErr = nil
	}

	return Unmarshal(grpcErr, protoErr)
}

func UnaryServerInterceptor(ctx context.Context, req interface{}, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	m, err := handler(ctx, req)
	// If `m` has a Error field, try to set it.
	if setWrappedError(m, err) {
		return m, nil
	}
	return m, err
}

// getWrappedError returns the value of the error contained within the protobuf
// message.
func getWrappedError(msg interface{}) (*proto.Error, bool) {
	// Use Indirect to resolve the pointer.
	val := reflect.Indirect(reflect.ValueOf(msg))
	if val.Kind() != reflect.Struct {
		return nil, false
	}

	errVal := val.FieldByName("Error")
	if !errVal.IsValid() {
		return nil, false
	}

	err, ok := errVal.Interface().(*proto.Error)
	return err, ok
}

func setWrappedError(msg interface{}, err error) bool {
	// Use Indirect to resolve the pointer.
	val := reflect.Indirect(reflect.ValueOf(msg))
	if val.Kind() != reflect.Struct {
		return false
	}

	errVal := val.FieldByName("Error")
	if !errVal.IsValid() {
		return false
	}

	_, ok := errVal.Interface().(*proto.Error)
	if !ok {
		return false
	}

	if !errVal.CanSet() {
		return false
	}

	errVal.Set(reflect.ValueOf(Marshal(err)))
	return true
}
