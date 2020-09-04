package httpapi

import (
	"bytes"
	"context"
	"io/ioutil"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kelda/blimp/pkg/errors"
	"github.com/kelda/blimp/pkg/proto/cluster"
)

func TestHTTPAPI(t *testing.T) {
	tests := []struct {
		name     string
		handlers map[string]interface{}

		endpoint  string
		body      []byte
		expResp   []byte
		expNewErr error
	}{
		{
			name: "Basic",
			handlers: map[string]interface{}{
				"/api/check-version": func(_ context.Context, req *cluster.CheckVersionRequest) (*cluster.CheckVersionResponse, error) {
					if req.Version != "exp-req" {
						panic("bad req val")
					}
					return &cluster.CheckVersionResponse{Version: "version resp"}, nil
				},
			},
			endpoint: "/api/check-version",
			body:     []byte(`{"version": "exp-req"}`),
			expResp: []byte(`{"result":{"version":"version resp"}}
`),
		},
		{
			name: "Error",
			handlers: map[string]interface{}{
				"/api/check-version": func(_ context.Context, _ *cluster.CheckVersionRequest) (*cluster.CheckVersionResponse, error) {
					return &cluster.CheckVersionResponse{}, errors.New("message")
				},
			},
			endpoint: "/api/check-version",
			body:     []byte(`{"version": "exp-req"}`),
			expResp: []byte(`{"result":null,"error":{"details":"message"}}
`),
		},
		{
			name: "BadFunctionType",
			handlers: map[string]interface{}{
				"/api/check-version": func(_ context.Context) error {
					return nil
				},
			},
			expNewErr: errors.WithContext("create handler for /api/check-version", errors.New("must take exactly two arguments, got 1")),
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			server, err := New("", test.handlers)
			require.Equal(t, test.expNewErr, err)

			if err != nil {
				return
			}

			req := httptest.NewRequest("POST", test.endpoint, bytes.NewBuffer(test.body))
			resp := httptest.NewRecorder()
			server.Handler.ServeHTTP(resp, req)

			body, err := ioutil.ReadAll(resp.Body)
			require.NoError(t, err)
			assert.Equal(t, test.expResp, body)
		})
	}

}
