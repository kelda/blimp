package util

import (
	"bytes"
	"context"
	"io"
	"time"

	"github.com/kelda/blimp/pkg/errors"
)

// StreamReader provides convenience methods for reading from io streams.
type StreamReader struct {
	streamChan chan ReadResult
}

type ReadResult struct {
	Bytes []byte
	Error error
}

// NewStreamReader returns a new StreamReader
func NewStreamReader(stream io.Reader) StreamReader {
	sr := StreamReader{make(chan ReadResult)}
	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := stream.Read(buf)

			cpy := make([]byte, n)
			copy(cpy, buf)
			sr.streamChan <- ReadResult{
				Bytes: cpy,
				Error: err,
			}
		}
	}()
	return sr
}

// ReadUntilTimeout reads from the stream until nothing new has been written in `timeout`.
func (sr StreamReader) ReadUntilTimeout(ctx context.Context, timeout time.Duration) ([]byte, error) {
	combined := bytes.NewBuffer(nil)
	for {
		select {
		case <-ctx.Done():
			return nil, errors.New("cancelled")
		case <-time.After(timeout):
			return combined.Bytes(), nil
		case r := <-sr.streamChan:
			if r.Error != nil {
				return nil, r.Error
			}
			if _, err := combined.Write(r.Bytes); err != nil {
				return nil, errors.WithContext("copy", err)
			}
		}
	}
}

// Read reads from the stream and sends the result on the channel.
func (sr StreamReader) Read(ctx context.Context) chan ReadResult {
	result := make(chan ReadResult, 1)

	go func() {
		select {
		case <-ctx.Done():
			result <- ReadResult{Error: errors.New("cancelled")}
		case r := <-sr.streamChan:
			result <- r
		}
		close(result)
	}()
	return result
}
