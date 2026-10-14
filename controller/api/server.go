// Package api implements the management API (Connect) on top of the
// controller services.
package api

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"connectrpc.com/connect"

	"github.com/jc-lab/suricontroller/controller/agentgw"
	"github.com/jc-lab/suricontroller/controller/auth"
	"github.com/jc-lab/suricontroller/controller/configrepo"
	"github.com/jc-lab/suricontroller/controller/deploy"
	"github.com/jc-lab/suricontroller/controller/gitrepo"
	"github.com/jc-lab/suricontroller/controller/logs"
	"github.com/jc-lab/suricontroller/controller/nodes"
	"github.com/jc-lab/suricontroller/controller/rules"
	"github.com/jc-lab/suricontroller/controller/store"
	agentv1 "github.com/jc-lab/suricontroller/gen/suricontroller/agent/v1"
	"github.com/jc-lab/suricontroller/gen/suricontroller/api/v1/apiv1connect"
	"github.com/jc-lab/suricontroller/pkg/sshkey"
)

// Server holds the dependencies of the API handlers.
type Server struct {
	Store      store.Store
	Auth       auth.Provider
	Authorizer auth.Authorizer
	Gateway    *agentgw.Gateway
	Nodes      *nodes.Service
	Rules      *rules.Service
	Deploy     *deploy.Service
	Logs       *logs.Service
	RulesRepo  *gitrepo.Repo
	ConfigRepo *gitrepo.Repo
	HostKey    *sshkey.PublicKey
	AgentPath  string
	Version    string
	Logger     *slog.Logger
	// ConfValidator validates disable/enable/drop/modify files on write.
	ConfValidator configrepo.ConfValidator
	// TrustProxyHeaders uses X-Forwarded-For / CF-Connecting-IP as the
	// client address for login rate limiting.
	TrustProxyHeaders bool
}

const pkgPrefix = "/suricontroller.api.v1."

// publicProcedures can be called without authentication.
var publicProcedures = map[string]bool{
	apiv1connect.AuthServiceGetAuthInfoProcedure: true,
	apiv1connect.AuthServiceLoginProcedure:       true,
}

// Handler returns the HTTP handler serving all API services. Mount it with
// the API prefix stripped.
func (s *Server) Handler() http.Handler {
	if s.Logger == nil {
		s.Logger = slog.Default()
	}
	if s.Authorizer == nil {
		s.Authorizer = auth.AllowAll{}
	}
	// Request size limits apply to the decompressed message; the public auth
	// service gets a tiny one.
	small, normal, large := connect.WithReadMaxBytes(16<<10), connect.WithReadMaxBytes(1<<20), connect.WithReadMaxBytes(32<<20)
	mux := http.NewServeMux()
	mux.Handle(apiv1connect.NewAuthServiceHandler(&authService{s}, small))
	mux.Handle(apiv1connect.NewSystemServiceHandler(&systemService{s}, normal))
	mux.Handle(apiv1connect.NewNodeServiceHandler(&nodeService{s}, normal))
	mux.Handle(apiv1connect.NewRepoServiceHandler(&repoService{s}, large))
	mux.Handle(apiv1connect.NewRuleServiceHandler(&ruleService{s}, normal))
	mux.Handle(apiv1connect.NewDeployServiceHandler(&deployService{s}, normal))
	mux.Handle(apiv1connect.NewLogServiceHandler(&logService{s}, normal))
	mux.HandleFunc("GET /logs/download", s.downloadLog)
	return s.middleware(mux)
}

// clientAddr returns the client address used for rate limiting.
func (s *Server) clientAddr(r *http.Request) string {
	if s.TrustProxyHeaders {
		if v := r.Header.Get("Cf-Connecting-Ip"); v != "" {
			return v
		}
		// The rightmost entry was added by the trusted proxy; entries to
		// its left are client-controlled.
		if v := r.Header.Values("X-Forwarded-For"); len(v) > 0 {
			parts := strings.Split(v[len(v)-1], ",")
			if last := strings.TrimSpace(parts[len(parts)-1]); last != "" {
				return last
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

var errorWriter = connect.NewErrorWriter()

func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := auth.WithRemoteAddr(r.Context(), s.clientAddr(r))
		procedure := r.URL.Path
		p, err := s.Auth.Authenticate(r)
		if err == nil && p == nil {
			err = auth.ErrUnauthenticated
		}
		if err == nil {
			ctx = auth.WithPrincipal(ctx, p)
		}
		if !publicProcedures[procedure] {
			if err != nil {
				s.writeError(w, r, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required")))
				return
			}
			if !isConnectRequest(r) && r.Method != http.MethodGet {
				// Browsers cannot send these headers cross-site without a CORS
				// preflight, which protects cookie sessions against CSRF.
				s.writeError(w, r, connect.NewError(connect.CodePermissionDenied, errors.New("missing Connect protocol headers")))
				return
			}
			if action, resource, ok := permission(procedure); ok {
				if err := s.Authorizer.Authorize(ctx, p, action, resource); err != nil {
					s.writeError(w, r, connect.NewError(connect.CodePermissionDenied, err))
					return
				}
			}
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) writeError(w http.ResponseWriter, r *http.Request, err *connect.Error) {
	if errorWriter.IsSupported(r) {
		_ = errorWriter.Write(w, r, err)
		return
	}
	code := http.StatusForbidden
	if err.Code() == connect.CodeUnauthenticated {
		code = http.StatusUnauthorized
	}
	http.Error(w, err.Message(), code)
}

func isConnectRequest(r *http.Request) bool {
	if r.Header.Get("Connect-Protocol-Version") != "" {
		return true
	}
	ct := r.Header.Get("Content-Type")
	return strings.HasPrefix(ct, "application/grpc") || strings.HasPrefix(ct, "application/connect+") || ct == "application/proto"
}

// permission maps a procedure (or the download endpoint) to an action and
// resource for the Authorizer.
func permission(procedure string) (auth.Action, string, bool) {
	if procedure == "/logs/download" {
		return auth.ActionRead, auth.ResourceLogs, true
	}
	rest, ok := strings.CutPrefix(procedure, pkgPrefix)
	if !ok {
		return "", "", false
	}
	svc, method, ok := strings.Cut(rest, "/")
	if !ok {
		return "", "", false
	}
	resource := map[string]string{
		"SystemService": auth.ResourceSystem,
		"NodeService":   auth.ResourceNodes,
		"RepoService":   auth.ResourceRepos,
		"RuleService":   auth.ResourceRules,
		"DeployService": auth.ResourceDeploy,
		"LogService":    auth.ResourceLogs,
	}[svc]
	if resource == "" {
		return "", "", false
	}
	action := auth.ActionWrite
	for _, prefix := range []string{"List", "Get", "Read", "Tail", "Diff", "Preview"} {
		if strings.HasPrefix(method, prefix) {
			action = auth.ActionRead
			break
		}
	}
	return action, resource, true
}

// toConnectError maps service errors to Connect codes.
func toConnectError(err error) error {
	if err == nil {
		return nil
	}
	var ce *connect.Error
	if errors.As(err, &ce) {
		return err
	}
	switch {
	case errors.Is(err, store.ErrNotFound), errors.Is(err, gitrepo.ErrNotFound), errors.Is(err, rules.ErrUnknownProvider):
		return connect.NewError(connect.CodeNotFound, err)
	case errors.Is(err, store.ErrAlreadyExists):
		return connect.NewError(connect.CodeAlreadyExists, err)
	case errors.Is(err, nodes.ErrInvalidArgument), errors.Is(err, deploy.ErrInvalidArgument),
		errors.Is(err, gitrepo.ErrInvalidPath), errors.Is(err, configrepo.ErrInvalidPath):
		return connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, gitrepo.ErrConflict), errors.Is(err, gitrepo.ErrNoChanges):
		return connect.NewError(connect.CodeFailedPrecondition, err)
	case errors.Is(err, auth.ErrInvalidCredentials), errors.Is(err, auth.ErrUnauthenticated):
		return connect.NewError(connect.CodeUnauthenticated, err)
	case errors.Is(err, auth.ErrPermissionDenied):
		return connect.NewError(connect.CodePermissionDenied, err)
	case errors.Is(err, context.Canceled):
		return connect.NewError(connect.CodeCanceled, err)
	}
	return connect.NewError(connect.CodeInternal, err)
}

func invalid(format string) error {
	return connect.NewError(connect.CodeInvalidArgument, errors.New(format))
}

// audit records an administrative action; failures are only logged.
func (s *Server) audit(ctx context.Context, action, target, detail string) {
	p := auth.FromContext(ctx)
	if err := s.Store.AppendAudit(ctx, &store.AuditEntry{Principal: p.Name(), Action: action, Target: target, Detail: detail, Time: nowFunc()}); err != nil {
		s.Logger.Warn("audit log", "err", err)
	}
}

func logTypeValid(t agentv1.LogType) bool {
	return logs.TypeName(t) != ""
}
