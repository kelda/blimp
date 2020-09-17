package main

import (
	"context"
	"io"
	"net"
	"regexp"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/kelda/blimp/pkg/errors"
	"github.com/kelda/blimp/pkg/proto/node"
)

// tunnelConn implements net.Conn from an underlying tunnel client.
type tunnelConn struct {
	// tunnel is the underlying tunnel client.
	tunnel node.Controller_TunnelClient
	// pendingData contains any extra data that we receieved but was not read
	// because the buffer was too small.
	pendingData []byte
}

// dialTunnelContext dials a network connection over a tunnel, and expects addr
// to be the blimp.dev subdomain to connect to instead of an actual network
// address. The subdomain should be the namespace, followed by the token.
// Note, from net.Dialer.DialContext: If the context expires before the
// connection is complete, an error is returned. Once successfully connected,
// any expiration of the context will not affect the connection.
func (s *server) dialTunnelContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" {
		// http.Transport should only ever make TCP connections.
		panic("unexpected network type")
	}

	// The address should be in the format hostname:port. We ignore the port.
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, errors.WithContext("tunnel dial parse address", err)
	}
	hostRegexp := regexp.MustCompile(`^([a-f0-9]{32})([a-f0-9]{8})$`)
	matches := hostRegexp.FindStringSubmatch(host)
	if len(matches) != 3 {
		return nil, errors.New("unexpected namespace format: %q", host)
	}

	// matches[0] contains the entire match, matches[1] and matches[2] are the
	// submatches.
	namespace := matches[1]
	token := matches[2]

	nodeController, err := s.getNodeControllerConn(ctx, namespace)
	if err != nil {
		return nil, errors.WithContext("get node controller connection", err)
	}

	// We can't use ctx here. If ctx is canceled once the connection is
	// established, that should be a no-op.  However, the context here is used
	// for the duration of the stream, and canceling it will terminate the
	// stream.
	tunnel, err := nodeController.ExposedTunnel(context.Background())
	if err != nil {
		return nil, errors.New("failed to establish tunnel")
	}

	err = tunnel.Send(&node.TunnelMsg{Msg: &node.TunnelMsg_Header{
		Header: &node.TunnelHeader{
			Token:     token,
			Namespace: namespace,
		}}})
	if err != nil {
		//nolint:errcheck // Nothing we could do to handle this anyway.
		tunnel.CloseSend()
		return nil, errors.WithContext("send tunnel header", err)
	}

	return &tunnelConn{
		tunnel: tunnel,
	}, nil
}

func (tc *tunnelConn) Read(b []byte) (n int, err error) {
	if len(tc.pendingData) > 0 {
		n = copy(b, tc.pendingData)
		if n < len(tc.pendingData) {
			tc.pendingData = tc.pendingData[n:]
		} else {
			tc.pendingData = nil
		}
		return n, nil
	}

	msg, err := tc.tunnel.Recv()
	if err == io.EOF || status.Code(err) == codes.Canceled {
		// We attempt to send EOF and close the stream if possible, but it
		// probably won't work and that's ok.
		//nolint:errcheck
		tc.Close()
		return 0, err
	}
	if err != nil {
		return 0, errors.WithContext("recv on tunnel", err)
	}
	if eof := msg.GetEof(); eof != nil {
		return 0, io.EOF
	}

	msgBuf := msg.GetBuf()
	n = copy(b, msgBuf)
	if n < len(msgBuf) {
		tc.pendingData = msgBuf[n:]
	}
	return n, nil
}

func (tc *tunnelConn) Write(b []byte) (n int, err error) {
	err = tc.tunnel.Send(&node.TunnelMsg{Msg: &node.TunnelMsg_Buf{Buf: b}})
	if err == io.EOF || status.Code(err) == codes.Canceled {
		// We attempt to send EOF and close the stream if possible, but it
		// probably won't work and that's ok.
		//nolint:errcheck
		tc.Close()
		return 0, err
	}
	if err != nil {
		return 0, errors.WithContext("send to tunnel", err)
	}

	return len(b), nil
}

func (tc *tunnelConn) Close() error {
	eofErr := tc.tunnel.Send(&node.TunnelMsg{Msg: &node.TunnelMsg_Eof{Eof: &node.EOF{}}})
	closeErr := tc.tunnel.CloseSend()
	if eofErr != nil {
		return eofErr
	}
	return closeErr
}

// I don't think it's actually that important to implement these for our
// usecase, but they are needed to implement net.Conn.
func (tc *tunnelConn) LocalAddr() net.Addr {
	// TODO
	return nil
}
func (tc *tunnelConn) RemoteAddr() net.Addr {
	// TODO
	return nil
}
func (tc *tunnelConn) SetDeadline(t time.Time) error {
	// TODO
	return nil
}
func (tc *tunnelConn) SetReadDeadline(t time.Time) error {
	// TODO
	return nil
}
func (tc *tunnelConn) SetWriteDeadline(t time.Time) error {
	// TODO
	return nil
}
