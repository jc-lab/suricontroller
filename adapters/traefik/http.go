//go:build linux

package suritaptraefik

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"time"

	plugin "github.com/jc-lab/suricontroller/adapters/traefik-plugin"
	"github.com/jc-lab/suricontroller/pkg/suritap"
)

// Middleware wraps the entry point HTTP handler (Traefik patch hook). The
// entry point name comes from the context (WithEntryPoint). The HTTP logic
// is the Traefik plugin's (adapters/traefik-plugin); this build only swaps
// its socket transport for the shared-memory client.
func Middleware(ctx context.Context, cfg *Config, next http.Handler) (http.Handler, error) {
	if cfg == nil {
		return next, nil
	}
	t, err := ForEntryPoint(EntryPointFrom(ctx), cfg)
	if err != nil {
		return nil, err
	}
	return plugin.NewHandler(next, cfg, t.entryPoint, shmTransport{t})
}

var errBlocked = errors.New("suritap: blocked")

func init() {
	plugin.Logf = func(warn bool, format string, args ...interface{}) {
		if warn {
			Logger.Warn("suritap: " + sprintf(format, args...))
		} else {
			Logger.Debug("suritap: " + sprintf(format, args...))
		}
	}
}

// shmTransport adapts the shared-memory client to the plugin's Transport.
type shmTransport struct{ t *Tap }

func toAddrPort(a plugin.Addr) netip.AddrPort {
	ip, _ := netip.AddrFromSlice(a.IP)
	return netip.AddrPortFrom(ip.Unmap(), uint16(a.Port))
}

func (s shmTransport) Open(src, dst plugin.Addr, meta []plugin.Meta) (plugin.Conn, error) {
	m := make([]suritap.Meta, len(meta))
	for i, x := range meta {
		m[i] = suritap.Meta{Tag: suritap.MetaTag(x.Tag), Value: x.Value}
	}
	c, err := s.t.openRaw(toAddrPort(src), toAddrPort(dst), m)
	if err != nil {
		return nil, err
	}
	return shmConn{c}, nil
}

func (s shmTransport) Close() error { return nil }

type shmConn struct{ c *suritap.Conn }

func (c shmConn) CID() uint64 { return c.c.CID() }

func (c shmConn) Send(deadline time.Time, dir plugin.Dir, data []byte) error {
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	return c.c.Send(ctx, suritap.Dir(dir), data)
}

func (c shmConn) Inspect(deadline time.Time, dir plugin.Dir, data []byte) (plugin.Verdict, error) {
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	v, err := c.c.Inspect(ctx, suritap.Dir(dir), data)
	if err != nil {
		return plugin.Verdict{}, err
	}
	out := plugin.Verdict{Action: plugin.Action(v.Action), Reason: uint8(v.Reason)}
	for _, a := range v.Alerts {
		out.SIDs = append(out.SIDs, a.SID)
	}
	return out, nil
}

func (c shmConn) Close(reset bool) error { return c.c.Close(reset) }
