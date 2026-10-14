// Package controller is the embeddable suri-controller. A host program
// creates a Controller with New, mounts AgentHandler and APIHandler on its
// own HTTP server and calls Run.
//
//	ctl, err := controller.New(controller.Options{DataDir: dir, Auth: provider})
//	mux.Handle("/agent/v1/connect", ctl.AgentHandler())
//	mux.Handle("/api/", http.StripPrefix("/api", ctl.APIHandler()))
//	go ctl.Run(ctx)
package controller

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/jc-lab/suricontroller/controller/agentgw"
	"github.com/jc-lab/suricontroller/controller/api"
	"github.com/jc-lab/suricontroller/controller/auth"
	"github.com/jc-lab/suricontroller/controller/deploy"
	"github.com/jc-lab/suricontroller/controller/gitrepo"
	"github.com/jc-lab/suricontroller/controller/logs"
	"github.com/jc-lab/suricontroller/controller/nodes"
	"github.com/jc-lab/suricontroller/controller/render"
	"github.com/jc-lab/suricontroller/controller/rules"
	"github.com/jc-lab/suricontroller/controller/store"
	"github.com/jc-lab/suricontroller/controller/store/sqlite"
	agentv1 "github.com/jc-lab/suricontroller/gen/suricontroller/agent/v1"
	"github.com/jc-lab/suricontroller/pkg/noiseconn"
	"github.com/jc-lab/suricontroller/pkg/sshkey"
	"github.com/jc-lab/suricontroller/pkg/version"
	"github.com/jc-lab/suricontroller/pkg/wire"
)

// HostKeyComment is the comment of the controller host public key.
const HostKeyComment = "suri-controller"

// Hooks are optional callbacks for embedding programs.
type Hooks struct {
	NodeConnected    func(nodeID string)
	NodeDisconnected func(nodeID string)
	ApplyReported    func(nodeID string, r *agentv1.ApplyReport)
}

// Options configures a Controller.
type Options struct {
	// DataDir holds the host key, database, git repositories, bundles and
	// logs (unless replaced below).
	DataDir string
	// HostKey is the controller key. Nil loads or creates {DataDir}/hostkey.
	HostKey *sshkey.PrivateKey
	// Store persists controller state. Nil uses SQLite in DataDir.
	Store store.Store
	// Auth authenticates management API requests (required).
	Auth auth.Provider
	// Authorizer authorizes API requests. Nil allows every authenticated
	// principal.
	Authorizer auth.Authorizer
	// LogSink receives agent logs. Nil stores them in {DataDir}/logs.
	LogSink logs.Sink
	// RuleProviderTypes replaces the built-in provider types.
	RuleProviderTypes []rules.TypeInfo
	// HTTPClient is used to download rules.
	HTTPClient *http.Client
	// DisableETOpen creates the default ET Open provider disabled on first
	// start (air-gapped installations).
	DisableETOpen bool
	// AgentPath is the path where AgentHandler is mounted (informational,
	// shown in the UI). Default wire.AgentPath.
	AgentPath string
	// TrustProxyHeaders trusts X-Forwarded-For / CF-Connecting-IP for the
	// client address (login rate limiting, logs).
	TrustProxyHeaders bool
	Logger            *slog.Logger
	Hooks             Hooks
}

// Controller is a running suri-controller instance.
type Controller struct {
	opts      Options
	log       *slog.Logger
	hostKey   *sshkey.PrivateKey
	store     store.Store
	ownsStore bool

	rulesRepo  *gitrepo.Repo
	configRepo *gitrepo.Repo
	renderer   *render.Renderer
	gw         *agentgw.Gateway
	nodes      *nodes.Service
	rules      *rules.Service
	deploy     *deploy.Service
	logs       *logs.Service
	api        http.Handler

	runOnce sync.Once
}

// New creates a controller. It does not start background work; call Run.
func New(opts Options) (*Controller, error) {
	if opts.DataDir == "" {
		return nil, errors.New("controller: DataDir is required")
	}
	if opts.Auth == nil {
		return nil, errors.New("controller: Auth is required")
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.AgentPath == "" {
		opts.AgentPath = wire.AgentPath
	}
	if err := os.MkdirAll(opts.DataDir, 0o750); err != nil {
		return nil, err
	}
	c := &Controller{opts: opts, log: opts.Logger}
	ok := false
	defer func() {
		if !ok {
			c.Close()
		}
	}()

	c.hostKey = opts.HostKey
	if c.hostKey == nil {
		k, created, err := sshkey.LoadOrGenerate(filepath.Join(opts.DataDir, "hostkey"), HostKeyComment)
		if err != nil {
			return nil, fmt.Errorf("controller: host key: %w", err)
		}
		if created {
			c.log.Info("generated controller host key", "public_key", k.Public(HostKeyComment).String())
		}
		c.hostKey = k
	}

	c.store = opts.Store
	if c.store == nil {
		st, err := sqlite.Open(filepath.Join(opts.DataDir, "controller.db"))
		if err != nil {
			return nil, fmt.Errorf("controller: open database: %w", err)
		}
		c.store, c.ownsStore = st, true
	}

	var err error
	if c.rulesRepo, err = gitrepo.Open(filepath.Join(opts.DataDir, "git", "rules.git")); err != nil {
		return nil, fmt.Errorf("controller: rules repository: %w", err)
	}
	if c.configRepo, err = gitrepo.Open(filepath.Join(opts.DataDir, "git", "config.git")); err != nil {
		return nil, fmt.Errorf("controller: config repository: %w", err)
	}
	if c.renderer, err = render.New(render.Config{
		Rules: c.rulesRepo, Config: c.configRepo, Key: c.hostKey.Key,
		CacheDir: filepath.Join(opts.DataDir, "bundles"), Logger: opts.Logger,
	}); err != nil {
		return nil, err
	}

	ctx := context.Background()
	if c.nodes, err = nodes.New(ctx, c.store); err != nil {
		return nil, err
	}
	static, err := noiseconn.KeyPair(c.hostKey.X25519())
	if err != nil {
		return nil, err
	}
	c.gw = agentgw.New(agentgw.Config{
		StaticKey:         static,
		Nodes:             c.nodes,
		Handler:           (*hub)(c),
		Logger:            opts.Logger,
		ControllerVersion: version.Version,
		TrustProxyHeaders: opts.TrustProxyHeaders,
	})
	if c.logs, err = logs.New(ctx, logs.Config{
		Store: c.store, Sink: opts.LogSink, Dir: filepath.Join(opts.DataDir, "logs"), Logger: opts.Logger,
		OnPolicyChange: func() { c.deploy.Trigger("") },
	}); err != nil {
		return nil, err
	}
	c.deploy = deploy.New(deploy.Config{
		Store: c.store, Rules: c.rulesRepo, Config: c.configRepo, Renderer: c.renderer,
		GlobalLogPolicy: c.logs.GlobalPolicy,
		Push: func(nodeID string, ds *agentv1.DesiredState) error {
			s := c.gw.Session(nodeID)
			if s == nil {
				return errors.New("node is offline")
			}
			return s.SendDesired(ds)
		},
		Logger: opts.Logger,
	})
	c.rules = rules.New(rules.Config{
		Store: c.store, Repo: c.rulesRepo, Logger: opts.Logger, HTTPClient: opts.HTTPClient, Types: opts.RuleProviderTypes,
		DisableETOpen: opts.DisableETOpen,
		OnCommit: func(string) {
			if err := c.deploy.OnCommit(context.Background(), deploy.KindRules); err != nil {
				c.log.Error("deploy rules commit", "err", err)
			}
		},
	})
	if err := c.rules.Init(ctx); err != nil {
		return nil, err
	}
	c.nodes.OnChange = func(id string) {
		if n, err := c.store.GetNode(context.Background(), id); err == nil && !n.Enabled {
			c.gw.Disconnect(id)
		}
		c.deploy.Trigger(id)
	}

	srv := &api.Server{
		Store: c.store, Auth: opts.Auth, Authorizer: opts.Authorizer, Gateway: c.gw, Nodes: c.nodes,
		Rules: c.rules, Deploy: c.deploy, Logs: c.logs, RulesRepo: c.rulesRepo, ConfigRepo: c.configRepo,
		HostKey: c.hostKey.Public(HostKeyComment), AgentPath: opts.AgentPath, Version: version.Version,
		Logger: opts.Logger, ConfValidator: render.ValidateConf, TrustProxyHeaders: opts.TrustProxyHeaders,
	}
	c.api = srv.Handler()
	ok = true
	return c, nil
}

// HostPublicKey returns the controller host public key line to pin in agent
// configuration.
func (c *Controller) HostPublicKey() string { return c.hostKey.Public(HostKeyComment).String() }

// AgentHandler serves agent WebSocket connections.
func (c *Controller) AgentHandler() http.Handler { return c.gw }

// APIHandler serves the management API; mount it with its prefix stripped.
func (c *Controller) APIHandler() http.Handler { return c.api }

// Nodes returns the node service for programmatic use.
func (c *Controller) Nodes() *nodes.Service { return c.nodes }

// Deploy returns the deploy service for programmatic use.
func (c *Controller) Deploy() *deploy.Service { return c.deploy }

// Rules returns the rule provider service for programmatic use.
func (c *Controller) Rules() *rules.Service { return c.rules }

// Logs returns the log service for programmatic use.
func (c *Controller) Logs() *logs.Service { return c.logs }

// RulesRepo returns the rules repository.
func (c *Controller) RulesRepo() *gitrepo.Repo { return c.rulesRepo }

// ConfigRepo returns the config repository.
func (c *Controller) ConfigRepo() *gitrepo.Repo { return c.configRepo }

// Store returns the store.
func (c *Controller) Store() store.Store { return c.store }

// Run starts the background workers (rule downloads, deployment, log
// writing) and blocks until ctx is cancelled.
func (c *Controller) Run(ctx context.Context) error {
	started := false
	c.runOnce.Do(func() { started = true })
	if !started {
		return errors.New("controller: Run called twice")
	}
	var wg sync.WaitGroup
	for _, fn := range []func(context.Context){c.rules.Run, c.deploy.Run, c.logs.Run, c.maintenance} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fn(ctx)
		}()
	}
	<-ctx.Done()
	for _, s := range c.gw.Sessions() {
		s.Close()
	}
	wg.Wait()
	return nil
}

// Close releases resources. Call after Run returned.
func (c *Controller) Close() error {
	var errs []error
	if c.logs != nil {
		errs = append(errs, c.logs.Close())
	}
	if c.ownsStore && c.store != nil {
		errs = append(errs, c.store.Close())
	}
	return errors.Join(errs...)
}

// hub adapts the controller to agentgw.Handler.
type hub Controller

func (h *hub) OnConnect(ctx context.Context, s *agentgw.Session, hello *agentv1.Hello) error {
	if err := h.nodes.RecordHello(ctx, s.NodeID, hello); err != nil {
		return err
	}
	if h.opts.Hooks.NodeConnected != nil {
		h.opts.Hooks.NodeConnected(s.NodeID)
	}
	// Rendering can take long after a restart (cold cache); push the desired
	// state asynchronously so the session's control loop starts right away.
	go func() {
		if err := h.deploy.OnConnect(s.Context(), s.NodeID); err != nil && s.Context().Err() == nil {
			h.log.Error("compute desired state", "node", s.NodeID, "err", err)
		}
	}()
	return nil
}

func (h *hub) OnDisconnect(s *agentgw.Session) {
	h.nodes.RecordDisconnect(context.Background(), s.NodeID)
	h.log.Info("agent disconnected", "node", s.NodeID)
	if h.opts.Hooks.NodeDisconnected != nil {
		h.opts.Hooks.NodeDisconnected(s.NodeID)
	}
}

func (h *hub) OnStatus(s *agentgw.Session, st *agentv1.StatusReport) {
	h.nodes.RecordStatus(s.NodeID, st)
}

func (h *hub) OnApplyReport(s *agentgw.Session, r *agentv1.ApplyReport) {
	if err := h.deploy.OnApplyReport(context.Background(), s.NodeID, r); err != nil {
		h.log.Error("record apply report", "node", s.NodeID, "err", err)
	}
	if h.opts.Hooks.ApplyReported != nil {
		h.opts.Hooks.ApplyReported(s.NodeID, r)
	}
}

func (h *hub) OnLogBatch(s *agentgw.Session, b *agentv1.LogBatch) {
	if err := h.logs.Ingest(s.NodeID, b); err != nil {
		h.log.Debug("ingest logs", "node", s.NodeID, "err", err)
	}
}

// OpenBlob serves only the bundle currently desired for the node, so a node
// cannot download another node's configuration.
func (h *hub) OpenBlob(ctx context.Context, nodeID, bundleID string) (io.ReadSeekCloser, int64, error) {
	n, err := h.store.GetNode(ctx, nodeID)
	if err != nil {
		return nil, 0, err
	}
	if n.Desired.GetBundle().GetBundleId() != bundleID {
		return nil, 0, errors.New("bundle is not assigned to this node")
	}
	return h.renderer.Open(bundleID)
}

// maintenance repacks the git repositories daily.
func (c *Controller) maintenance(ctx context.Context) {
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		for name, repo := range map[string]*gitrepo.Repo{"rules": c.rulesRepo, "config": c.configRepo} {
			if err := repo.Repack(); err != nil {
				c.log.Warn("repack repository", "repo", name, "err", err)
			}
		}
	}
}
