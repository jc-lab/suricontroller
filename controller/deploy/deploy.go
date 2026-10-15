// Package deploy decides what every node should run. It owns the deploy
// policies of the rules and config repositories (auto / pinned / paused),
// computes each node's desired state, pushes it to connected agents and
// records the apply reports they send back.
package deploy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/jc-lab/suricontroller/controller/gitrepo"
	"github.com/jc-lab/suricontroller/controller/render"
	"github.com/jc-lab/suricontroller/controller/store"
	agentv1 "github.com/jc-lab/suricontroller/gen/suricontroller/agent/v1"
)

// Policy kinds.
const (
	KindRules  = "rules"
	KindConfig = "config"
)

// Policy modes.
const (
	ModeAuto   = "auto"
	ModePinned = "pinned"
	ModePaused = "paused"
)

// historyKeep is the number of apply history entries kept per node.
const historyKeep = 200

// ErrInvalidArgument wraps validation errors.
var ErrInvalidArgument = errors.New("invalid argument")

// Renderer renders node bundles.
type Renderer interface {
	Render(ctx context.Context, rulesCommit, configCommit, nodeID string) (*render.Result, error)
	Preview(ctx context.Context, rulesCommit, configCommit, nodeID string) (*render.Result, error)
	GC(keep map[string]bool, minAge time.Duration) int
}

// Config configures a Service.
type Config struct {
	Store    store.Store
	Rules    *gitrepo.Repo
	Config   *gitrepo.Repo
	Renderer Renderer
	// GlobalLogPolicy returns the log collection policy of nodes without an
	// override.
	GlobalLogPolicy func(ctx context.Context) (*agentv1.LogCollectionPolicy, error)
	// Push sends a desired state to a node if it is connected.
	Push   func(nodeID string, ds *agentv1.DesiredState) error
	Logger *slog.Logger
}

// Service implements deployment.
type Service struct {
	cfg Config
	log *slog.Logger
	now func() time.Time

	policyMu sync.Mutex

	trigMu  sync.Mutex
	pending map[string]bool // node id -> recompute; "" = all nodes
	wake    chan struct{}

	// nodeMu serializes Recompute per node, so inputs, persisted state and
	// pushes stay ordered.
	nodeMuMu sync.Mutex
	nodeMu   map[string]*sync.Mutex
}

// New creates the service.
func New(cfg Config) *Service {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Service{cfg: cfg, log: cfg.Logger.With("component", "deploy"), now: time.Now, pending: map[string]bool{}, wake: make(chan struct{}, 1), nodeMu: map[string]*sync.Mutex{}}
}

func (s *Service) repo(kind string) (*gitrepo.Repo, error) {
	switch kind {
	case KindRules:
		return s.cfg.Rules, nil
	case KindConfig:
		return s.cfg.Config, nil
	}
	return nil, fmt.Errorf("%w: unknown policy kind %q", ErrInvalidArgument, kind)
}

// Policy returns a policy and the current head of its repository.
func (s *Service) Policy(ctx context.Context, kind string) (*store.DeployPolicy, string, error) {
	repo, err := s.repo(kind)
	if err != nil {
		return nil, "", err
	}
	head, err := repo.Head()
	if err != nil {
		return nil, "", err
	}
	p, err := s.cfg.Store.GetDeployPolicy(ctx, kind)
	if errors.Is(err, store.ErrNotFound) {
		return &store.DeployPolicy{Kind: kind, Mode: ModeAuto, EffectiveCommit: head}, head, nil
	}
	if err != nil {
		return nil, "", err
	}
	return p, head, nil
}

// SetPolicy changes a policy. For ModePinned, pinned must name a commit of
// the repository.
func (s *Service) SetPolicy(ctx context.Context, kind, mode, pinned, by string) (*store.DeployPolicy, error) {
	s.policyMu.Lock()
	defer s.policyMu.Unlock()
	repo, err := s.repo(kind)
	if err != nil {
		return nil, err
	}
	p, head, err := s.Policy(ctx, kind)
	if err != nil {
		return nil, err
	}
	switch mode {
	case ModeAuto:
		p.PinnedCommit = ""
		p.EffectiveCommit = head
	case ModePinned:
		full, err := repo.Resolve(pinned)
		if err != nil {
			return nil, fmt.Errorf("%w: commit %q not found", ErrInvalidArgument, pinned)
		}
		p.PinnedCommit = full
		p.EffectiveCommit = full
	case ModePaused:
		p.PinnedCommit = ""
		if p.EffectiveCommit == "" {
			p.EffectiveCommit = head
		}
	default:
		return nil, fmt.Errorf("%w: unknown mode %q", ErrInvalidArgument, mode)
	}
	p.Kind, p.Mode, p.UpdatedAt, p.UpdatedBy = kind, mode, s.now(), by
	if err := s.cfg.Store.PutDeployPolicy(ctx, p); err != nil {
		return nil, err
	}
	s.log.Info("deploy policy changed", "kind", kind, "mode", mode, "effective", p.EffectiveCommit, "by", by)
	s.Trigger("")
	return p, nil
}

// OnCommit must be called after a commit to the repository of kind. Auto
// policies move to the new head.
func (s *Service) OnCommit(ctx context.Context, kind string) error {
	s.policyMu.Lock()
	defer s.policyMu.Unlock()
	p, head, err := s.Policy(ctx, kind)
	if err != nil {
		return err
	}
	if p.Mode != ModeAuto {
		return nil
	}
	// An unsaved policy derives its effective commit from the head, so it
	// is saved here to keep the deployed commit explicit.
	p.Kind = kind
	p.EffectiveCommit = head
	p.UpdatedAt = s.now()
	if err := s.cfg.Store.PutDeployPolicy(ctx, p); err != nil {
		return err
	}
	s.Trigger("")
	return nil
}

// Trigger schedules a recompute of a node ("" for all nodes).
func (s *Service) Trigger(nodeID string) {
	s.trigMu.Lock()
	s.pending[nodeID] = true
	s.trigMu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// Run processes triggered recomputes and periodic cache GC until ctx is
// cancelled. All nodes are recomputed at start.
func (s *Service) Run(ctx context.Context) {
	// Catch auto policies up with commits made while not running.
	for _, kind := range []string{KindRules, KindConfig} {
		if err := s.OnCommit(ctx, kind); err != nil {
			s.log.Error("catch up deploy policy", "kind", kind, "err", err)
		}
	}
	s.Trigger("")
	gc := time.NewTicker(time.Hour)
	defer gc.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-gc.C:
			s.gc(ctx)
			continue
		case <-s.wake:
		}
		// Coalesce bursts of triggers.
		select {
		case <-ctx.Done():
			return
		case <-time.After(200 * time.Millisecond):
		}
		s.trigMu.Lock()
		pending := s.pending
		s.pending = map[string]bool{}
		s.trigMu.Unlock()
		if pending[""] {
			if err := s.RecomputeAll(ctx); err != nil && ctx.Err() == nil {
				s.log.Error("recompute nodes", "err", err)
			}
			continue
		}
		for id := range pending {
			if _, err := s.Recompute(ctx, id, false); err != nil && !errors.Is(err, store.ErrNotFound) && ctx.Err() == nil {
				s.log.Error("recompute node", "node", id, "err", err)
			}
		}
	}
}

// RecomputeAll recomputes every node.
func (s *Service) RecomputeAll(ctx context.Context) error {
	nodes, err := s.cfg.Store.ListNodes(ctx)
	if err != nil {
		return err
	}
	for _, n := range nodes {
		if _, err := s.Recompute(ctx, n.ID, false); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			s.log.Error("recompute node", "node", n.ID, "err", err)
		}
	}
	return nil
}

// commits returns the effective rules and config commits.
func (s *Service) commits(ctx context.Context) (string, string, error) {
	rp, _, err := s.Policy(ctx, KindRules)
	if err != nil {
		return "", "", err
	}
	cp, _, err := s.Policy(ctx, KindConfig)
	if err != nil {
		return "", "", err
	}
	return rp.EffectiveCommit, cp.EffectiveCommit, nil
}

// Recompute computes the desired state of a node, persists it (bumping the
// generation when it changed) and pushes it to the agent when it changed or
// when force is set. It returns the desired state.
func (s *Service) Recompute(ctx context.Context, nodeID string, force bool) (*agentv1.DesiredState, error) {
	s.nodeMuMu.Lock()
	mu, ok := s.nodeMu[nodeID]
	if !ok {
		mu = &sync.Mutex{}
		s.nodeMu[nodeID] = mu
	}
	s.nodeMuMu.Unlock()
	mu.Lock()
	defer mu.Unlock()

	rulesCommit, configCommit, err := s.commits(ctx)
	if err != nil {
		return nil, err
	}
	global, err := s.cfg.GlobalLogPolicy(ctx)
	if err != nil {
		return nil, err
	}
	n, err := s.cfg.Store.GetNode(ctx, nodeID)
	if err != nil {
		return nil, err
	}
	if !n.Enabled {
		return n.Desired, nil
	}
	// Render outside the store transaction; it can take a while.
	var bundleRef *agentv1.BundleRef
	var renderErr error
	if rulesCommit != "" || configCommit != "" {
		res, err := s.cfg.Renderer.Render(ctx, rulesCommit, configCommit, nodeID)
		if err != nil {
			renderErr = err
		} else {
			bundleRef = &agentv1.BundleRef{BundleId: res.ID, RulesCommit: rulesCommit, ConfigCommit: configCommit, Size: uint64(res.Size)}
		}
	}

	changed := false
	n, err = s.cfg.Store.UpdateNode(ctx, nodeID, func(n *store.Node) error {
		ds := &agentv1.DesiredState{
			Bundle:         bundleRef,
			InterfaceModes: interfaceModes(n),
			EndpointModes:  endpointModes(n),
			LogPolicy:      n.LogPolicy,
		}
		if ds.LogPolicy == nil {
			ds.LogPolicy = global
		}
		if renderErr != nil {
			// Keep the previous bundle; other changes still go through.
			ds.Bundle = n.Desired.GetBundle()
			n.DesiredError = renderErr.Error()
		} else {
			n.DesiredError = ""
		}
		prev := n.Desired
		if prev != nil {
			ds.Generation = prev.Generation
			cmp := proto.Clone(prev).(*agentv1.DesiredState)
			cmp.Generation = ds.Generation
			if proto.Equal(cmp, ds) {
				return nil
			}
		}
		ds.Generation++
		n.Desired = ds
		changed = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	if renderErr != nil {
		s.log.Warn("render failed", "node", nodeID, "err", renderErr)
	}
	if (changed || force) && n.Desired != nil {
		if err := s.cfg.Push(nodeID, n.Desired); err != nil {
			s.log.Debug("push desired state", "node", nodeID, "err", err)
		}
	}
	return n.Desired, nil
}

// interfaceModes builds the desired mode of every interface the agent
// manages. IPS is downgraded to IDS when the agent does not allow it.
func interfaceModes(n *store.Node) map[string]agentv1.InterfaceMode {
	out := map[string]agentv1.InterfaceMode{}
	for _, ifc := range n.Hello.GetInterfaces() {
		mode, ok := n.InterfaceModes[ifc.Name]
		if !ok || mode == agentv1.InterfaceMode_INTERFACE_MODE_UNSPECIFIED {
			mode = agentv1.InterfaceMode_INTERFACE_MODE_OFF
		}
		if mode == agentv1.InterfaceMode_INTERFACE_MODE_IPS && !ifc.IpsAllowed {
			mode = agentv1.InterfaceMode_INTERFACE_MODE_IDS
		}
		out[ifc.Name] = mode
	}
	return out
}

// endpointModes builds the desired mode of every suritap endpoint the agent
// manages (nil without any). Prevent is downgraded to Detect when the agent
// does not allow it.
func endpointModes(n *store.Node) map[string]agentv1.EndpointMode {
	eps := n.Hello.GetTap().GetEndpoints()
	if len(eps) == 0 {
		return nil
	}
	out := map[string]agentv1.EndpointMode{}
	for _, ep := range eps {
		mode, ok := n.EndpointModes[ep.Name]
		if !ok || mode == agentv1.EndpointMode_ENDPOINT_MODE_UNSPECIFIED {
			mode = agentv1.EndpointMode_ENDPOINT_MODE_OFF
		}
		if mode == agentv1.EndpointMode_ENDPOINT_MODE_PREVENT && !ep.PreventAllowed {
			mode = agentv1.EndpointMode_ENDPOINT_MODE_DETECT
		}
		out[ep.Name] = mode
	}
	return out
}

// OnConnect computes and always pushes the desired state to a node that
// just connected.
func (s *Service) OnConnect(ctx context.Context, nodeID string) error {
	_, err := s.Recompute(ctx, nodeID, true)
	return err
}

// OnApplyReport records an apply report.
func (s *Service) OnApplyReport(ctx context.Context, nodeID string, r *agentv1.ApplyReport) error {
	_, err := s.cfg.Store.UpdateNode(ctx, nodeID, func(n *store.Node) error {
		n.LastReport = r
		n.LastReportAt = s.now()
		if r.Applied != nil {
			n.Applied = r.Applied
		}
		return nil
	})
	if err != nil {
		return err
	}
	switch r.Status {
	case agentv1.ApplyStatus_APPLY_STATUS_SUCCEEDED, agentv1.ApplyStatus_APPLY_STATUS_FAILED, agentv1.ApplyStatus_APPLY_STATUS_ROLLED_BACK:
		if err := s.cfg.Store.AppendApplyHistory(ctx, &store.ApplyHistoryEntry{NodeID: nodeID, Report: r, CreatedAt: s.now()}); err != nil {
			return err
		}
		if r.Status != agentv1.ApplyStatus_APPLY_STATUS_SUCCEEDED {
			s.log.Warn("apply failed on node", "node", nodeID, "generation", r.Generation, "stage", r.Stage.String(), "message", r.Message)
		}
	}
	return nil
}

// Preview renders a node's bundle for the given commits ("" = effective).
func (s *Service) Preview(ctx context.Context, nodeID, rulesCommit, configCommit string) (*render.Result, error) {
	effRules, effConfig, err := s.commits(ctx)
	if err != nil {
		return nil, err
	}
	if rulesCommit == "" {
		rulesCommit = effRules
	} else if rulesCommit, err = s.cfg.Rules.Resolve(rulesCommit); err != nil {
		return nil, fmt.Errorf("%w: rules commit not found", ErrInvalidArgument)
	}
	if configCommit == "" {
		configCommit = effConfig
	} else if configCommit, err = s.cfg.Config.Resolve(configCommit); err != nil {
		return nil, fmt.Errorf("%w: config commit not found", ErrInvalidArgument)
	}
	return s.cfg.Renderer.Preview(ctx, rulesCommit, configCommit, nodeID)
}

func (s *Service) gc(ctx context.Context) {
	nodes, err := s.cfg.Store.ListNodes(ctx)
	if err != nil {
		return
	}
	keep := map[string]bool{}
	for _, n := range nodes {
		if id := n.Desired.GetBundle().GetBundleId(); id != "" {
			keep[id] = true
		}
		if id := n.Applied.GetBundle().GetBundleId(); id != "" {
			keep[id] = true
		}
	}
	if n := s.cfg.Renderer.GC(keep, 6*time.Hour); n > 0 {
		s.log.Info("removed unused bundles", "count", n)
	}
	_ = s.cfg.Store.PruneApplyHistory(ctx, historyKeep)
}
