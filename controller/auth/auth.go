// Package auth defines how the controller authenticates and authorizes
// management API requests. Programs embedding the controller can replace
// every piece: implement Provider (and optionally PasswordLogin,
// SessionIssuer or ExternalLogin) and Authorizer.
package auth

import (
	"context"
	"errors"
	"net/http"
)

// ErrUnauthenticated is returned when a request carries no valid credentials.
var ErrUnauthenticated = errors.New("auth: unauthenticated")

// ErrInvalidCredentials is returned by PasswordLogin for a wrong
// username/password.
var ErrInvalidCredentials = errors.New("auth: invalid credentials")

// ErrPermissionDenied is returned by an Authorizer.
var ErrPermissionDenied = errors.New("auth: permission denied")

// Principal is an authenticated user.
type Principal struct {
	ID          string
	DisplayName string
	Roles       []string
	Attrs       map[string]string
}

// Provider resolves the principal of an HTTP request (session cookie,
// bearer token, trusted proxy header, ...). It returns ErrUnauthenticated
// when the request has no valid credentials.
type Provider interface {
	Authenticate(r *http.Request) (*Principal, error)
}

// PasswordLogin is implemented by providers supporting username/password
// login.
type PasswordLogin interface {
	Login(ctx context.Context, username, password string) (*Principal, error)
}

// SessionIssuer is implemented by providers that keep a session after a
// successful login (e.g. a cookie).
type SessionIssuer interface {
	IssueSession(h http.Header, p *Principal) error
	ClearSession(h http.Header)
}

// ExternalLogin is implemented by providers that log users in elsewhere
// (OIDC, SSO portal). The web UI redirects to LoginURL.
type ExternalLogin interface {
	LoginURL(returnTo string) string
}

// Action is a kind of access.
type Action string

const (
	ActionRead  Action = "read"
	ActionWrite Action = "write"
)

// Resource names used by the management API.
const (
	ResourceSystem = "system"
	ResourceNodes  = "nodes"
	ResourceRepos  = "repos"
	ResourceRules  = "rules"
	ResourceDeploy = "deploy"
	ResourceLogs   = "logs"
)

// Authorizer decides whether a principal may perform an action.
type Authorizer interface {
	Authorize(ctx context.Context, p *Principal, action Action, resource string) error
}

// AllowAll authorizes every authenticated principal.
type AllowAll struct{}

// Authorize implements Authorizer.
func (AllowAll) Authorize(context.Context, *Principal, Action, string) error { return nil }

type principalKey struct{}

// WithPrincipal returns a context carrying p.
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// FromContext returns the principal stored in ctx, or nil.
func FromContext(ctx context.Context) *Principal {
	p, _ := ctx.Value(principalKey{}).(*Principal)
	return p
}

// Name returns a display name for audit records and git authors.
func (p *Principal) Name() string {
	if p == nil {
		return "system"
	}
	if p.DisplayName != "" {
		return p.DisplayName
	}
	return p.ID
}
