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
)

// Config is the entry point configuration (Traefik static configuration
// entryPoints.<name>.suritap). Durations are strings such as "50ms".
type Config struct {
	SocketDir         string `description:"Directory of the Suricata suritap worker sockets." json:"socketDir,omitempty" toml:"socketDir,omitempty" yaml:"socketDir,omitempty" export:"true"`
	Mode              string `description:"prevent (block on drop verdicts, default) or detect (never wait for verdicts)." json:"mode,omitempty" toml:"mode,omitempty" yaml:"mode,omitempty" export:"true"`
	FailPolicy        string `description:"What to do without a verdict (Suricata down, timeout): open (default) or closed." json:"failPolicy,omitempty" toml:"failPolicy,omitempty" yaml:"failPolicy,omitempty" export:"true"`
	Timeout           string `description:"Verdict timeout (default 100ms)." json:"timeout,omitempty" toml:"timeout,omitempty" yaml:"timeout,omitempty" export:"true"`
	MaxRequestBody    int64  `description:"Request bodies up to this size are buffered and inspected before forwarding (default 1048576); larger ones are inspected while streaming." json:"maxRequestBody,omitempty" toml:"maxRequestBody,omitempty" yaml:"maxRequestBody,omitempty" export:"true"`
	Response          string `description:"Response inspection: off, detect (default) or prevent." json:"response,omitempty" toml:"response,omitempty" yaml:"response,omitempty" export:"true"`
	MaxResponseBuffer int64  `description:"Prevent mode: responses up to this size are inspected complete before they are sent (default 65536); larger ones are inspected while streaming and aborted on a drop." json:"maxResponseBuffer,omitempty" toml:"maxResponseBuffer,omitempty" yaml:"maxResponseBuffer,omitempty" export:"true"`
	Name              string `description:"Client name reported to Suricata (default traefik)." json:"name,omitempty" toml:"name,omitempty" yaml:"name,omitempty" export:"true"`
}

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
