//go:build !linux

package suritaptraefik

import (
	"context"
	"errors"
	"net/http"
)

// Middleware is unavailable outside Linux (suritap uses memfd/eventfd).
func Middleware(_ context.Context, cfg *Config, next http.Handler) (http.Handler, error) {
	if cfg == nil {
		return next, nil
	}
	return nil, errors.New("suritap: only supported on Linux")
}

// WrapConn returns conn unchanged outside Linux.
func WrapConn(_ context.Context, _ string, conn WriteCloser) WriteCloser { return conn }
