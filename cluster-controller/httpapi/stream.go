package httpapi

import (
	"context"
	"net/http"
	"reflect"

	"github.com/golang/protobuf/jsonpb"
	"github.com/golang/protobuf/proto"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/metadata"

	"github.com/kelda/blimp/pkg/errors"
)

// StreamHandler defines how gRPC streams should be invoked.
type StreamHandler struct {
	RequestType proto.Message
	RPC         StreamRPC
}

type StreamRPC func(proto.Message, WebSocketStream) error

// WebSocketStream satisfies the methods of grpc.ServerStream so that shims
// can avoid redefining the methods. Shims should forward calls from their typed
// Send methods to the SendProtoMessage method.
type WebSocketStream struct {
	messages chan<- proto.Message
	ctx      context.Context
}

// SendProtoMessage should be called by the typed Send message of shims to
// forward stream messages to the websocket.
func (s WebSocketStream) SendProtoMessage(msg proto.Message) error {
	select {
	case <-s.ctx.Done():
		return errors.New("connection closed")
	case s.messages <- msg:
		return nil
	}
}

func (s WebSocketStream) SetHeader(_ metadata.MD) error {
	return errors.New("unimplemented")
}
func (s WebSocketStream) SendHeader(_ metadata.MD) error {
	return errors.New("unimplemented")
}
func (s WebSocketStream) SetTrailer(_ metadata.MD) {}

func (s WebSocketStream) Context() context.Context {
	return s.ctx
}
func (s WebSocketStream) SendMsg(_ interface{}) error {
	return errors.New("unimplemented")
}
func (s WebSocketStream) RecvMsg(_ interface{}) error {
	return errors.New("unimplemented")
}

func (handler StreamHandler) Handler() (func(http.ResponseWriter, *http.Request), error) {
	// Validate that the RequestType field is as expected.
	if handler.RequestType == nil {
		return nil, errors.New("RequestType must be set")
	}

	if reflect.TypeOf(handler.RequestType).Kind() != reflect.Ptr {
		return nil, errors.New("RequestType's concrete type must be a pointer")
	}

	return func(w http.ResponseWriter, r *http.Request) {
		upgrader := &websocket.Upgrader{}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.WithError(err).Warn("Failed to upgrade connection")
			return
		}

		err = handler.forward(conn)
		if err == nil {
			return
		}

		if err := conn.WriteJSON(unaryHTTPResponse{Error: err}); err != nil {
			if websocket.IsCloseError(err, websocket.CloseGoingAway) {
				return
			}
			log.WithError(err).Warn("Failed to send stream update")
		}
	}, nil
}

func (handler StreamHandler) forward(conn *websocket.Conn) error {
	_, reqJSON, err := conn.ReadMessage()
	if err != nil {
		return errors.WithContext("read request", err)
	}

	// The Handler method guarantees that RequestType's concrete type is a
	// pointer.
	reqType := reflect.TypeOf(handler.RequestType).Elem()
	protoReq := reflect.New(reqType).Interface().(proto.Message)
	if err := jsonpb.UnmarshalString(string(reqJSON), protoReq); err != nil {
		return errors.WithContext("unmarshal request", err)
	}

	// Forward messages from the gRPC stream to the websockets stream.
	ctx, cancel := context.WithCancel(context.Background())
	messages := make(chan proto.Message)
	wsStream := WebSocketStream{messages: messages, ctx: ctx}
	doneForwarding := make(chan struct{})
	go func() {
		// Signal to wsStream that messages will no longer be forwarded.
		defer cancel()
		defer close(doneForwarding)
		for {
			select {
			case msg := <-messages:
				if err := conn.WriteJSON(unaryHTTPResponse{Result: msg}); err != nil {
					if !websocket.IsCloseError(err, websocket.CloseGoingAway) {
						log.WithError(err).Warn("Failed to send stream update")
					}
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	err = handler.RPC(protoReq, wsStream)
	cancel()

	// Block until the forwarder goroutine has returned to avoid concurrent
	// writes to the websocket connection.
	<-doneForwarding
	return err
}
