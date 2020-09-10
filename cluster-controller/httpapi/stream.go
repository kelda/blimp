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

func (handler StreamHandler) Handler() (http.HandlerFunc, error) {
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
		defer conn.Close()

		// The client's first message should always be the protobuf request.
		_, reqJSON, err := conn.ReadMessage()
		if err != nil {
			log.WithError(err).Warn("Failed to read client stream request")
			return
		}

		// Shut down the forwarder if the connection closes.
		forwardCtx, cancelForward := context.WithCancel(context.Background())
		defer cancelForward()
		go func() {
			for {
				_, _, err := conn.ReadMessage()
				if err != nil {
					// err could be non-nil if the client gracefully closes the
					// connection with a Close message, or if the connection
					// breaks. Either way, we should stop sending messages
					// back.
					cancelForward()
					return
				}
			}
		}()

		err = handler.forward(forwardCtx, conn, string(reqJSON))
		if err == nil {
			return
		}

		select {
		// If the forwarder exited because the context was cancelled, don't
		// bother sending any more messages.
		case <-forwardCtx.Done():
			return
		default:
		}

		if err := conn.WriteJSON(unaryHTTPResponse{Error: err}); err != nil {
			log.WithError(err).Warn("Failed to send final stream update")
		}

		if err := conn.WriteMessage(websocket.CloseMessage, []byte{}); err != nil {
			log.WithError(err).Warn("Failed to send websocket close")
		}
	}, nil
}

func (handler StreamHandler) forward(ctx context.Context, conn *websocket.Conn, reqJSON string) error {
	// The Handler method guarantees that RequestType's concrete type is a
	// pointer.
	reqType := reflect.TypeOf(handler.RequestType).Elem()
	protoReq := reflect.New(reqType).Interface().(proto.Message)
	if err := jsonpb.UnmarshalString(string(reqJSON), protoReq); err != nil {
		return errors.WithContext("unmarshal request", err)
	}

	// Forward messages from the gRPC stream to the websockets stream.
	messages := make(chan proto.Message)
	wsStream := WebSocketStream{messages: messages, ctx: ctx}
	ctx, cancel := context.WithCancel(ctx)
	doneForwarding := make(chan struct{})
	go func() {
		defer close(doneForwarding)
		for {
			select {
			case msg := <-messages:
				if err := conn.WriteJSON(unaryHTTPResponse{Result: msg}); err != nil {
					log.WithError(err).Warn("Failed to send stream update")
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	err := handler.RPC(protoReq, wsStream)
	cancel()

	// Block until the forwarder goroutine has returned to avoid concurrent
	// writes to the websocket connection.
	<-doneForwarding
	return err
}
