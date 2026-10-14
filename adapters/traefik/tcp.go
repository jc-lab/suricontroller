//go:build linux

package suritaptraefik

import (
	"context"
	"crypto/tls"
	"io"
	"sync"
	"sync/atomic"

	"github.com/jc-lab/suricontroller/pkg/suritap"
)

// WrapConn wraps a TLS-terminated connection of a TCP router (Traefik
// patch hook). It returns conn unchanged when the context's entry point
// has no suritap configuration.
func WrapConn(ctx context.Context, router string, conn WriteCloser) WriteCloser {
	t := Lookup(EntryPointFrom(ctx))
	if t == nil {
		return conn
	}
	return t.WrapConn(router, conn)
}

// WrapConn taps a decrypted byte stream: in prevent mode every read is
// inspected before it is returned to the proxy (client to upstream);
// writes (upstream to client) follow the response mode. A drop closes the
// connection.
func (t *Tap) WrapConn(router string, conn WriteCloser) WriteCloser {
	t.Stats.Requests.Add(1)
	return &tapConn{WriteCloser: conn, t: t, router: router}
}

type tapConn struct {
	WriteCloser
	t      *Tap
	router string

	once    sync.Once
	sc      *suritap.Conn
	blocked atomic.Bool
	eofSent atomic.Bool
}

func (c *tapConn) session() *suritap.Conn {
	c.once.Do(func() {
		meta := []suritap.Meta{{Tag: suritap.MetaProto, Value: "tcp"}}
		if c.router != "" {
			meta = append(meta, suritap.Meta{Tag: suritap.MetaRoute, Value: c.router})
		}
		if cs, ok := c.WriteCloser.(interface{ ConnectionState() tls.ConnectionState }); ok {
			st := cs.ConnectionState()
			if st.ServerName != "" {
				meta = append(meta, suritap.Meta{Tag: suritap.MetaSNI, Value: st.ServerName})
			}
			if st.NegotiatedProtocol != "" {
				meta = append(meta, suritap.Meta{Tag: suritap.MetaALPN, Value: st.NegotiatedProtocol})
			}
		}
		sc, err := c.t.open(addrOf(c.RemoteAddr()), addrOf(c.LocalAddr()), meta)
		if err != nil {
			c.t.Stats.Unavailable.Add(1)
			return
		}
		c.sc = sc
	})
	return c.sc
}

// check returns true when data must not pass.
func (c *tapConn) check(m mode, dir suritap.Dir, data []byte, what string) bool {
	if m == modeOff {
		return false
	}
	sc := c.session()
	if sc == nil {
		return c.t.s.failClosed && m == modePrevent
	}
	blocked, v := c.t.verdict(context.Background(), sc, m, dir, data)
	if blocked {
		logBlock(c.t.entryPoint, sc.CID(), what, v)
	}
	return blocked
}

func (c *tapConn) block() (int, error) {
	if !c.blocked.Swap(true) {
		_ = c.WriteCloser.Close()
	}
	return 0, errBlocked
}

func (c *tapConn) Read(p []byte) (int, error) {
	if c.blocked.Load() {
		return 0, errBlocked
	}
	n, err := c.WriteCloser.Read(p)
	if n > 0 && c.check(c.t.s.mode, suritap.ToServer, p[:n], "tcp stream") {
		return c.block()
	}
	if err == io.EOF && c.sc != nil && !c.eofSent.Swap(true) {
		_ = c.sc.EOF(context.Background(), suritap.ToServer)
	}
	return n, err
}

func (c *tapConn) Write(p []byte) (int, error) {
	if c.blocked.Load() {
		return 0, errBlocked
	}
	if len(p) > 0 && c.check(c.t.s.response, suritap.ToClient, p, "tcp stream response") {
		return c.block()
	}
	return c.WriteCloser.Write(p)
}

func (c *tapConn) CloseWrite() error {
	if c.sc != nil {
		_ = c.sc.EOF(context.Background(), suritap.ToClient)
	}
	return c.WriteCloser.CloseWrite()
}

func (c *tapConn) Close() error {
	if c.sc != nil {
		_ = c.sc.Close(c.blocked.Load())
	}
	return c.WriteCloser.Close()
}
