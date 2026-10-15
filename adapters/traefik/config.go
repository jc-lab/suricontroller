// Package suritaptraefik connects Traefik (or any Go HTTP/TCP proxy) to
// the Suricata suritap plugin.
//
// It does not import Traefik: a small patch (deploy/traefik) wires it in.
//
//   - HTTP (all versions, including h2 and h3) is tapped per request
//     after TLS termination: the request is normalized to HTTP/1.1 and
//     inspected on its own synthetic flow before it is routed; blocked
//     requests get 403.
//   - TCP routers that terminate TLS are tapped as a byte stream: the
//     decrypted connection is wrapped and every read is inspected before
//     it reaches the upstream.
//
// Configuration is per entry point (static configuration
// entryPoints.<name>.suritap).
package suritaptraefik

import (
	"context"
	"net"

	plugin "github.com/jc-lab/suritap-traefik"
)

// Config is the entry point configuration (Traefik static configuration
// entryPoints.<name>.suritap); it is the plugin's configuration.
type Config = plugin.Config

// WriteCloser matches Traefik's tcp.WriteCloser.
type WriteCloser interface {
	net.Conn
	CloseWrite() error
}

type entryPointKey struct{}

// WithEntryPoint records the entry point name in a context.
func WithEntryPoint(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, entryPointKey{}, name)
}

// EntryPointFrom returns the entry point name recorded by WithEntryPoint.
func EntryPointFrom(ctx context.Context) string {
	name, _ := ctx.Value(entryPointKey{}).(string)
	return name
}
