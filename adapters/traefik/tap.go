//go:build linux

package suritaptraefik

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jc-lab/suricontroller/pkg/suritap"
)

type mode int

const (
	modeOff mode = iota
	modeDetect
	modePrevent
)

func parseMode(s string, def mode, allowOff bool) (mode, error) {
	switch strings.ToLower(s) {
	case "":
		return def, nil
	case "detect":
		return modeDetect, nil
	case "prevent":
		return modePrevent, nil
	case "off":
		if allowOff {
			return modeOff, nil
		}
	}
	return 0, fmt.Errorf("invalid mode %q", s)
}

type settings struct {
	dir        string
	name       string
	mode       mode
	response   mode
	failClosed bool
	timeout    time.Duration
}

func parseSettings(c *Config) (settings, error) {
	s := settings{dir: c.SocketDir, name: c.Name, timeout: 100 * time.Millisecond}
	if s.dir == "" {
		s.dir = "/run/suritap"
	}
	if s.name == "" {
		s.name = "traefik"
	}
	var err error
	if s.mode, err = parseMode(c.Mode, modePrevent, false); err != nil {
		return s, fmt.Errorf("suritap.mode: %w", err)
	}
	if s.response, err = parseMode(c.Response, modeDetect, true); err != nil {
		return s, fmt.Errorf("suritap.response: %w", err)
	}
	switch strings.ToLower(c.FailPolicy) {
	case "", "open":
	case "closed":
		s.failClosed = true
	default:
		return s, fmt.Errorf("suritap.failPolicy: invalid value %q", c.FailPolicy)
	}
	if c.Timeout != "" {
		if s.timeout, err = time.ParseDuration(c.Timeout); err != nil || s.timeout <= 0 {
			return s, fmt.Errorf("suritap.timeout: invalid duration %q", c.Timeout)
		}
	}
	return s, nil
}

// Logger receives block decisions and transport errors.
var Logger = slog.Default()

func sprintf(format string, args ...interface{}) string { return fmt.Sprintf(format, args...) }

// Stats are cumulative counters of a Tap.
type Stats struct {
	Requests, Blocked, Failures, Unavailable atomic.Uint64
}

// Tap inspects the traffic of one entry point.
type Tap struct {
	entryPoint string
	s          settings

	mu       sync.Mutex
	client   *suritap.Client
	retryAt  time.Time
	dialFunc func() (*suritap.Client, error)

	Stats Stats
}

// New creates a Tap; the connection to Suricata is made lazily and
// re-established after failures.
func New(entryPoint string, cfg *Config) (*Tap, error) {
	s, err := parseSettings(cfg)
	if err != nil {
		return nil, err
	}
	t := &Tap{entryPoint: entryPoint, s: s}
	t.dialFunc = func() (*suritap.Client, error) {
		return suritap.Dial(s.dir, suritap.Options{Name: s.name})
	}
	return t, nil
}

var errUnavailable = errors.New("suritap: Suricata unavailable")

const redialDelay = time.Second

func (t *Tap) conn() (*suritap.Client, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.client != nil {
		return t.client, nil
	}
	if time.Now().Before(t.retryAt) {
		return nil, errUnavailable
	}
	c, err := t.dialFunc()
	if err != nil {
		t.retryAt = time.Now().Add(redialDelay)
		Logger.Warn("suritap: cannot reach Suricata", "entryPoint", t.entryPoint, "dir", t.s.dir, "err", err)
		return nil, err
	}
	t.client = c
	return c, nil
}

// reset drops a client whose sessions failed so that the next use dials
// again (the client itself re-dials dead sessions, this covers a
// restarted Suricata with a different worker count).
func (t *Tap) reset(c *suritap.Client) {
	t.mu.Lock()
	if t.client == c {
		t.client = nil
		t.retryAt = time.Now().Add(redialDelay)
	}
	t.mu.Unlock()
	_ = c.Close()
}

// Close releases the connection to Suricata.
func (t *Tap) Close() error {
	t.mu.Lock()
	c := t.client
	t.client = nil
	t.mu.Unlock()
	if c != nil {
		return c.Close()
	}
	return nil
}

func parseAddr(s string) netip.AddrPort {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	}
	return netip.AddrPort{}
}

// open announces a connection of the TCP tap.
func (t *Tap) open(src, dst netip.AddrPort, meta []suritap.Meta) (*suritap.Conn, error) {
	meta = append(meta, suritap.Meta{Tag: suritap.MetaProxy, Value: "traefik"}, suritap.Meta{Tag: suritap.MetaEndpoint, Value: t.entryPoint})
	return t.openRaw(src, dst, meta)
}

// openRaw announces a connection; src/dst of different or unknown families
// are mapped onto the source family.
func (t *Tap) openRaw(src, dst netip.AddrPort, meta []suritap.Meta) (*suritap.Conn, error) {
	if !src.IsValid() {
		return nil, fmt.Errorf("suritap: unusable client address")
	}
	if !dst.IsValid() || dst.Addr().Is4() != src.Addr().Is4() {
		if src.Addr().Is4() {
			dst = netip.AddrPortFrom(netip.IPv4Unspecified(), dst.Port())
		} else {
			dst = netip.AddrPortFrom(netip.IPv6Unspecified(), dst.Port())
		}
	}
	c, err := t.conn()
	if err != nil {
		return nil, err
	}
	conn, err := c.Open(suritap.OpenParams{Src: src, Dst: dst, Meta: meta})
	if errors.Is(err, suritap.ErrClosed) {
		t.reset(c)
	}
	return conn, err
}

// verdict sends data and reports whether the traffic must be blocked.
// In detect mode it never waits.
func (t *Tap) verdict(ctx context.Context, conn *suritap.Conn, m mode, dir suritap.Dir, data []byte) (bool, *suritap.Verdict) {
	if m == modeOff {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, t.s.timeout)
	defer cancel()
	if m == modeDetect {
		if err := conn.Send(ctx, dir, data); err != nil {
			t.Stats.Failures.Add(1)
		}
		return false, nil
	}
	v, err := conn.Inspect(ctx, dir, data)
	switch {
	case err != nil:
		t.Stats.Failures.Add(1)
		Logger.Debug("suritap: no verdict", "entryPoint", t.entryPoint, "cid", conn.CID(), "err", err)
		return t.s.failClosed, nil
	case v.Action == suritap.Drop:
		t.Stats.Blocked.Add(1)
		return true, &v
	case v.Action == suritap.Error:
		t.Stats.Failures.Add(1)
		return t.s.failClosed, &v
	}
	return false, &v
}

func logBlock(entryPoint string, cid uint64, what string, v *suritap.Verdict) {
	attrs := []any{"entryPoint", entryPoint, "cid", cid, "what", what}
	if v != nil {
		var sids []uint32
		for _, a := range v.Alerts {
			sids = append(sids, a.SID)
		}
		attrs = append(attrs, "reason", v.Reason.String(), "sids", sids)
	}
	Logger.Warn("suritap: blocked", attrs...)
}

var (
	registryMu sync.Mutex
	registry   = map[string]*Tap{}
)

// ForEntryPoint returns the Tap of an entry point, creating it on first
// use (the HTTP and HTTPS servers of an entry point share it).
func ForEntryPoint(name string, cfg *Config) (*Tap, error) {
	registryMu.Lock()
	defer registryMu.Unlock()
	if t, ok := registry[name]; ok {
		return t, nil
	}
	t, err := New(name, cfg)
	if err != nil {
		return nil, fmt.Errorf("entry point %q: %w", name, err)
	}
	registry[name] = t
	Logger.Info("suritap: enabled", "entryPoint", name, "dir", t.s.dir, "mode", modeName(t.s.mode), "response", modeName(t.s.response))
	return t, nil
}

// Lookup returns the Tap of an entry point or nil.
func Lookup(name string) *Tap {
	registryMu.Lock()
	defer registryMu.Unlock()
	return registry[name]
}

func modeName(m mode) string {
	switch m {
	case modeDetect:
		return "detect"
	case modePrevent:
		return "prevent"
	}
	return "off"
}

// addrOf extracts an address from a net.Addr.
func addrOf(a net.Addr) netip.AddrPort {
	if a == nil {
		return netip.AddrPort{}
	}
	return parseAddr(a.String())
}
