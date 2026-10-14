package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// CookieSessionConfig configures a CookieSession.
type CookieSessionConfig struct {
	// Login verifies credentials.
	Login PasswordLogin
	// Secret signs session cookies (at least 32 bytes).
	Secret []byte
	// TTL of a session (default 12h).
	TTL time.Duration
	// CookieName (default "suricontroller_session").
	CookieName string
	// CookiePath (default "/").
	CookiePath string
	// Insecure omits the Secure cookie attribute (plain HTTP deployments).
	Insecure bool
	// MaxAttempts per remote address and minute (default 10).
	MaxAttempts int
}

// CookieSession is a Provider that keeps HMAC-signed session cookies after a
// password login. It implements Provider, PasswordLogin and SessionIssuer.
type CookieSession struct {
	cfg     CookieSessionConfig
	limiter *attemptLimiter
	now     func() time.Time
}

// NewCookieSession creates a CookieSession.
func NewCookieSession(cfg CookieSessionConfig) (*CookieSession, error) {
	if cfg.Login == nil {
		return nil, errors.New("auth: Login is required")
	}
	if len(cfg.Secret) < 32 {
		return nil, errors.New("auth: session secret must be at least 32 bytes")
	}
	if cfg.TTL <= 0 {
		cfg.TTL = 12 * time.Hour
	}
	if cfg.CookieName == "" {
		cfg.CookieName = "suricontroller_session"
	}
	if cfg.CookiePath == "" {
		cfg.CookiePath = "/"
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 10
	}
	return &CookieSession{cfg: cfg, limiter: newAttemptLimiter(cfg.MaxAttempts, time.Minute), now: time.Now}, nil
}

type sessionClaims struct {
	Sub   string   `json:"sub"`
	Name  string   `json:"name,omitempty"`
	Roles []string `json:"roles,omitempty"`
	Exp   int64    `json:"exp"`
}

// Authenticate implements Provider.
func (s *CookieSession) Authenticate(r *http.Request) (*Principal, error) {
	c, err := r.Cookie(s.cfg.CookieName)
	if err != nil {
		return nil, ErrUnauthenticated
	}
	claims, err := s.verify(c.Value)
	if err != nil {
		return nil, ErrUnauthenticated
	}
	return &Principal{ID: claims.Sub, DisplayName: claims.Name, Roles: claims.Roles}, nil
}

// Login implements PasswordLogin with per-address rate limiting. The remote
// address is taken from the context (see WithRemoteAddr).
func (s *CookieSession) Login(ctx context.Context, username, password string) (*Principal, error) {
	addr := remoteAddrFromContext(ctx)
	if !s.limiter.allow(addr, s.now()) {
		return nil, errors.New("auth: too many login attempts, try again later")
	}
	return s.cfg.Login.Login(ctx, username, password)
}

// IssueSession implements SessionIssuer.
func (s *CookieSession) IssueSession(h http.Header, p *Principal) error {
	exp := s.now().Add(s.cfg.TTL)
	value, err := s.sign(sessionClaims{Sub: p.ID, Name: p.DisplayName, Roles: p.Roles, Exp: exp.Unix()})
	if err != nil {
		return err
	}
	h.Add("Set-Cookie", (&http.Cookie{
		Name:     s.cfg.CookieName,
		Value:    value,
		Path:     s.cfg.CookiePath,
		Expires:  exp,
		HttpOnly: true,
		Secure:   !s.cfg.Insecure,
		SameSite: http.SameSiteStrictMode,
	}).String())
	return nil
}

// ClearSession implements SessionIssuer.
func (s *CookieSession) ClearSession(h http.Header) {
	h.Add("Set-Cookie", (&http.Cookie{
		Name:     s.cfg.CookieName,
		Value:    "",
		Path:     s.cfg.CookiePath,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   !s.cfg.Insecure,
		SameSite: http.SameSiteStrictMode,
	}).String())
}

func (s *CookieSession) sign(c sessionClaims) (string, error) {
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	p := base64.RawURLEncoding.EncodeToString(payload)
	return p + "." + base64.RawURLEncoding.EncodeToString(s.mac(p)), nil
}

func (s *CookieSession) verify(v string) (*sessionClaims, error) {
	p, sig, ok := strings.Cut(v, ".")
	if !ok {
		return nil, ErrUnauthenticated
	}
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || !hmac.Equal(got, s.mac(p)) {
		return nil, ErrUnauthenticated
	}
	payload, err := base64.RawURLEncoding.DecodeString(p)
	if err != nil {
		return nil, ErrUnauthenticated
	}
	var c sessionClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, ErrUnauthenticated
	}
	if s.now().Unix() >= c.Exp {
		return nil, ErrUnauthenticated
	}
	return &c, nil
}

func (s *CookieSession) mac(payload string) []byte {
	m := hmac.New(sha256.New, s.cfg.Secret)
	m.Write([]byte("suricontroller-session\x00"))
	m.Write([]byte(payload))
	return m.Sum(nil)
}

type remoteAddrKey struct{}

// WithRemoteAddr stores the client address used for login rate limiting.
// IPv6 addresses are grouped by /64, since a client usually controls a
// whole prefix.
func WithRemoteAddr(ctx context.Context, addr string) context.Context {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		addr = host
	}
	if ip := net.ParseIP(addr); ip != nil && ip.To4() == nil {
		addr = ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
	}
	return context.WithValue(ctx, remoteAddrKey{}, addr)
}

func remoteAddrFromContext(ctx context.Context) string {
	v, _ := ctx.Value(remoteAddrKey{}).(string)
	return v
}

// attemptLimiter is a fixed-window counter per key.
type attemptLimiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	seen   map[string]*window
	swept  time.Time
}

type window struct {
	start time.Time
	count int
}

func newAttemptLimiter(max int, w time.Duration) *attemptLimiter {
	return &attemptLimiter{max: max, window: w, seen: map[string]*window{}}
}

func (l *attemptLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.seen) >= 10000 && now.Sub(l.swept) > l.window {
		l.swept = now
		for k, w := range l.seen {
			if now.Sub(w.start) > l.window {
				delete(l.seen, k)
			}
		}
	}
	if len(l.seen) >= 100000 {
		// Under a flood of distinct addresses fall back to one shared
		// bucket rather than growing without bound.
		key = "*"
	}
	w, ok := l.seen[key]
	if !ok || now.Sub(w.start) > l.window {
		l.seen[key] = &window{start: now, count: 1}
		return true
	}
	w.count++
	return w.count <= l.max
}
