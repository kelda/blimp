package tunnel

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/kelda-inc/blimp/pkg/auth"
	"github.com/kelda-inc/blimp/pkg/proto/sandbox"
)

type tunnel interface {
	Send(*sandbox.TunnelMsg) error
	Recv() (*sandbox.TunnelMsg, error)
}

func ServerHeader(namespace string, nsrv sandbox.Controller_TunnelServer) (
	name string, port uint32, err error) {

	msg, err := nsrv.Recv()
	if err != nil {
		return "", 0, err
	}

	header := msg.GetHeader()
	if header == nil {
		msg := fmt.Sprintf("first message must be a header")
		return "", 0, status.New(codes.Internal, msg).Err()
	}

	user, err := auth.ParseIDToken(header.GetToken())
	if err != nil {
		return "", 0, fmt.Errorf("bad token: %w", err)
	}

	if user.Namespace != namespace {
		return "", 0, fmt.Errorf("user is only allowed to access namespace %q", user.Namespace)
	}

	return header.Name, header.Port, nil
}

func ServerStream(nsrv sandbox.Controller_TunnelServer, stream net.Conn) {
	streamBidirectional(stream, nsrv, func() {})
}

// TODO, How does this thing get cleaned up?  Do we leak a go routine here?
func Client(scc sandbox.ControllerClient, ln net.Listener, token,
	name string, port uint32) error {

	for {
		stream, err := ln.Accept()
		if err != nil {
			return err
		}

		go connect(scc, stream, token, name, port)
	}

	return nil
}

func connect(scc sandbox.ControllerClient, stream net.Conn,
	token, name string, port uint32) {
	defer stream.Close()

	fields := log.Fields{"name": name, "port": port}
	log.WithFields(fields).Debug("new connection")
	defer log.WithFields(fields).Debug("finish connection")

	ctx, cancel := context.WithCancel(context.Background())
	tnl, err := scc.Tunnel(ctx)
	if err != nil {
		log.WithFields(fields).WithError(err).Error("failed to establish tunnel")
		return
	}

	err = tnl.Send(&sandbox.TunnelMsg{Msg: &sandbox.TunnelMsg_Header{
		Header: &sandbox.TunnelHeader{
			Token: token,
			Name:  name,
			Port:  port,
		}}})
	if err != nil {
		log.WithFields(fields).WithError(err).Error("failed to send tunnel connect")
		tnl.CloseSend()
		return
	}

	streamBidirectional(stream, tnl, cancel)
}

func streamBidirectional(stream net.Conn, tnl tunnel, cancel func()) {
	var wg sync.WaitGroup
	wg.Add(2)

	streamDone := make(chan struct{})

	go func() {
		tunnelToStream(stream, tnl)
		close(streamDone)
		wg.Done()

	}()

	go func() {
		streamToTunnel(stream, tnl, streamDone)
		cancel()
		wg.Done()
	}()

	wg.Wait()
	stream.Close()
}

type readResult struct {
	err error
	buf []byte
}

// There's no good way to cancel a stream read when the other end of the
// connection closes, so we need to roll our own.
func asyncReadStream(stream io.Reader, bufChan <-chan []byte,
	resultChan chan<- readResult) {

	for {
		buf := <-bufChan
		if buf == nil {
			close(resultChan)
			return
		}

		n, err := stream.Read(buf)
		resultChan <- readResult{
			err: err,
			buf: buf[:n],
		}
	}
}

func streamToTunnel(stream io.Reader, tnl tunnel, done <-chan struct{}) {
	var buf [1024 * 1024]byte

	bufChan := make(chan []byte)
	defer close(bufChan)

	resultChan := make(chan readResult)
	go asyncReadStream(stream, bufChan, resultChan)

loop:
	for {
		var result readResult

		bufChan <- buf[:]
		select {
		case <-done:
			break loop
		case result = <-resultChan:
		}

		if result.buf != nil {
			msg := sandbox.TunnelMsg{
				Msg: &sandbox.TunnelMsg_Buf{Buf: result.buf}}
			if err := tnl.Send(&msg); err != nil {
				log.WithError(err).Debug("tunnel send error")
				return
			}
		}

		err := result.err
		if err == io.EOF {
			break loop
		} else if err != nil {
			log.WithError(err).Debug("failed to read from local")
			break loop
		}
	}

	msg := sandbox.TunnelMsg{
		Msg: &sandbox.TunnelMsg_Eof{Eof: &sandbox.EOF{}}}
	if err := tnl.Send(&msg); err != nil &&
		status.Code(err) != codes.Canceled {
		log.WithError(err).Debug("failed to send eof")
	}
}

func tunnelToStream(stream io.ReadWriter, tnl tunnel) {
	for {
		msg, err := tnl.Recv()
		switch {
		case err == io.EOF:
			return
		case status.Code(err) == codes.Canceled:
			return
		case err != nil:
			log.WithError(err).Debug("failed to receive on tunnel")
			return
		}

		if eof := msg.GetEof(); eof != nil {
			return
		}

		buf := msg.GetBuf()
		if buf == nil {
			// This shouldn't happen.  The other end of the
			// connection isn't following protocol and sent us the
			// wrong type of msg. Panicking seems too much though,
			// so just error and close the connection.
			log.Error("tunnel protocol error. expected buffer")
			return
		}

		if _, err := stream.Write(buf); err != nil {
			return
		}
	}
}
