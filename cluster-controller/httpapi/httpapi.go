package httpapi

import (
	"fmt"
	"net/http"

	"github.com/kelda/blimp/pkg/errors"
)

type Handler interface {
	Handler() (http.HandlerFunc, error)
}

// NewServer creates a http.Server that provides a JSON interface for gRPC handlers.
func NewServer(addr string, handlers map[string]Handler) (*http.Server, error) {
	mux := http.NewServeMux()
	for route, handlerGetter := range handlers {
		h, err := handlerGetter.Handler()
		if err != nil {
			return nil, errors.WithContext(fmt.Sprintf("create handler for %s", route), err)
		}
		mux.HandleFunc(route, h)
	}

	return &http.Server{
		Addr:    addr,
		Handler: mux,
	}, nil
}
