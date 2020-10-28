package main

import (
	"context"
	"testing"

	"google.golang.org/grpc/metadata"

	"github.com/kelda/blimp/pkg/errors"
	"github.com/kelda/blimp/pkg/proto/node"
	"github.com/stretchr/testify/assert"
)

type mockTunnelClient struct {
	recvData []byte
}

func (t *mockTunnelClient) Send(_ *node.TunnelMsg) error {
	// Send it down the imaginary pipe!
	return nil
}

func (t *mockTunnelClient) Recv() (*node.TunnelMsg, error) {
	return &node.TunnelMsg{Msg: &node.TunnelMsg_Buf{Buf: t.recvData}}, nil
}

// Implement grpc.ClientStream. (Or rather, don't implement...)
func(t *mockTunnelClient) Header() (metadata.MD, error) {
	return nil, errors.New("not implemented")
}
func(t *mockTunnelClient) Trailer() metadata.MD {
	return nil
}
func(t *mockTunnelClient) CloseSend() error {
	return errors.New("not implemented")
}
func(t *mockTunnelClient) Context() context.Context {
	return nil
}
func(t *mockTunnelClient) SendMsg(_ interface{}) error {
	return errors.New("not implemented")
}
func(t *mockTunnelClient) RecvMsg(_ interface{}) error {
	return errors.New("not implemented")
}

func TestReadPending(t *testing.T) {
	tunnelClient := &mockTunnelClient{recvData: []byte("12345678")}
	conn := &tunnelConn{tunnel: tunnelClient}

	dest := make([]byte, 4)
	expectedResults := [][]byte{
		[]byte("1234"),
		[]byte("5678"),
		[]byte("1234"),
		[]byte("5678"),
	}

	for _, expected := range expectedResults {
		n, err := conn.Read(dest)
		assert.NoError(t, err)
		assert.Equal(t, n, len(dest))
		assert.EqualValues(t, dest, expected)
	}
}
