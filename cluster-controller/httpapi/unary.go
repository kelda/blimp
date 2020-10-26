package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"

	// We use jsonpb rather than google.golang.org/protobuf/encoding/protojson
	// because we're still using v1 rather than v2 protobufs.
	"github.com/golang/protobuf/jsonpb"
	"github.com/golang/protobuf/proto"

	"github.com/kelda/blimp/pkg/errors"
)

type UnaryHandler struct{ RPC interface{} }

func (uh UnaryHandler) Handler() (http.HandlerFunc, error) {
	handler := reflect.ValueOf(uh.RPC)

	// Validate the function signature.
	if kind := handler.Type().Kind(); kind != reflect.Func {
		return nil, errors.New("must be a function, got %s", kind)
	}

	// Validate the function arguments.
	if numArgs := handler.Type().NumIn(); numArgs != 2 {
		return nil, errors.New("must take exactly two arguments, got %d", numArgs)
	}

	ctxArgType := handler.Type().In(0)
	if !ctxArgType.Implements(reflect.TypeOf((*context.Context)(nil)).Elem()) {
		return nil, errors.New("first argument must be a context.Context")
	}

	reqArgType := handler.Type().In(1)
	if !reqArgType.Implements(reflect.TypeOf((*proto.Message)(nil)).Elem()) {
		return nil, errors.New("second argument must be a protobuf message")
	}

	// Validate the function return arguments.
	if numRet := handler.Type().NumOut(); numRet != 2 {
		return nil, errors.New("must return exactly two values, got %d", numRet)
	}

	respValType := handler.Type().Out(0)
	if !respValType.Implements(reflect.TypeOf((*proto.Message)(nil)).Elem()) {
		return nil, errors.New("first return argument must be a protobuf message")
	}

	errValType := handler.Type().Out(1)
	if !errValType.Implements(reflect.TypeOf((*error)(nil)).Elem()) {
		return nil, errors.New("second return argument must be an error")
	}

	execReq := func(req *http.Request) unaryHTTPResponse {
		defer req.Body.Close()
		protoReq := reflect.New(reqArgType.Elem()).Interface().(proto.Message)
		if err := jsonpb.Unmarshal(req.Body, protoReq); err != nil {
			return unaryHTTPResponse{
				Status: http.StatusBadRequest,
				Error:  errors.WithContext("unmarshal request", err),
			}
		}

		res := handler.Call([]reflect.Value{
			reflect.ValueOf(req.Context()),
			reflect.ValueOf(protoReq),
		})

		if !res[1].IsNil() {
			err := res[1].Interface().(error)
			if err != nil {
				return unaryHTTPResponse{
					Status: http.StatusInternalServerError,
					Error:  err,
				}
			}
		}

		return unaryHTTPResponse{
			Status: http.StatusOK,
			Result: res[0].Interface().(proto.Message),
		}
	}

	return func(w http.ResponseWriter, req *http.Request) {
		resp := execReq(req)
		w.WriteHeader(resp.Status)
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			fmt.Fprintf(w, "Failed to marshal response (%+v): %s\n", resp, err)
		}
	}, nil
}

// unaryHTTPResponse defines the standard response format to HTTP unary requests.
type unaryHTTPResponse struct {
	Status int
	Result proto.Message
	Error  error
}

func (resp unaryHTTPResponse) MarshalJSON() ([]byte, error) {
	type errorDetailsJSON struct {
		Details string `json:"details"`
	}
	type unaryHTTPResponseJSON struct {
		Result json.RawMessage   `json:"result"`
		Error  *errorDetailsJSON `json:"error,omitempty"`
	}

	var toMarshal unaryHTTPResponseJSON

	if resp.Result != nil {
		jsonMarshaler := jsonpb.Marshaler{}
		resultJSON, err := jsonMarshaler.MarshalToString(resp.Result)
		if err != nil {
			return nil, err
		}
		toMarshal.Result = json.RawMessage([]byte(resultJSON))
	}

	if resp.Error != nil {
		toMarshal.Error = &errorDetailsJSON{
			Details: resp.Error.Error(),
		}
	}

	return json.Marshal(toMarshal)
}
