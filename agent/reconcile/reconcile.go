// Package reconcile applies the desired state sent by the controller:
// policy check, bundle download and verification, configuration rendering,
// `suricata -T` validation, firewall steering, activation with rollback,
// and health checking. It also restores the last applied state at boot and
// re-applies it when the node user edits the local configuration.
package reconcile

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	yaml "go.yaml.in/yaml/v3"
	"google.golang.org/protobuf/proto"

	"github.com/jc-lab/suricontroller/agent/config"
	"github.com/jc-lab/suricontroller/agent/engine"
	"github.com/jc-lab/suricontroller/agent/firewall"
	"github.com/jc-lab/suricontroller/agent/state"
	agentv1 "github.com/jc-lab/suricontroller/gen/suricontroller/agent/v1"
	"github.com/jc-lab/suricontroller/pkg/bundle"
	"github.com/jc-lab/suricontroller/pkg/overlay"
	"github.com/jc-lab/suricontroller/pkg/ruleset"
	"github.com/jc-lab/suricontroller/pkg/yamlmerge"
)

// Fetcher downloads a bundle from offset, returning the remaining bytes and
// the total size.
type Fetcher func(ctx context.Context, bundleID string, offset uint64) (io.ReadCloser, uint64, error)

// Instance describes a running instance for log collection.
type Instance struct {
	Name      string
	LogDir    string
	Effective *yaml.Node
}

// Deps are the reconciler's collaborators.
type Deps struct {
	Config     *config.Config
	State      *state.Store
	Engine     engine.Runtime
	EngineInfo engine.Info
	Firewall   firewall.Backend
	// HostKey returns the key that verifies bundle signatures: the host key
	// of the controller the agent is connected to (nil before the first
	// connection when the endpoint is learned at run time).
	HostKey func() ed25519.PublicKey
	Logger  *slog.Logger
	// Report sends an apply report to the controller, if connected.
	Report func(*agentv1.ApplyReport)
	// OnInstances is called whenever the running instances changed.
	OnInstances func([]Instance)
	// OnLogPolicy is called when the log collection policy changes.
	OnLogPolicy func(*agentv1.LogCollectionPolicy)
	// QueueSupport reports a kernel that cannot steer traffic to NFQUEUE
	// (nil: supported or unknown).
	QueueSupport func(context.Context) error
}

// Reconciler applies desired states, one at a time.
type Reconciler struct {
	d   Deps
	log *slog.Logger

	fetchMu sync.Mutex
	fetch   Fetcher

	mu       sync.Mutex
	pending  *agentv1.DesiredState
	wake     chan struct{}
	cur      current
	warnings []*agentv1.Warning

	// retry holds a desired state whose apply failed transiently; it is
	// re-applied at retryAt unless a newer desired state arrives.
	retry        *agentv1.DesiredState
	retryAt      time.Time
	retryBackoff time.Duration

	// HOME_NET interface addresses (homenet.go).
	homeMu           sync.Mutex
	home             homeAddrs
	homePending      homeAddrs
	homePendingSince time.Time
	homeReloadAt     time.Time
}

// current is what is applied and running.
type current struct {
	applied   *agentv1.AppliedState
	logPolicy *agentv1.LogCollectionPolicy
	specs     []engine.InstanceSpec
	rendered  map[string][]byte // running config path -> content
	instances []Instance
	fw        firewall.Plan
	localHash string
}

// New creates a reconciler.
func New(d Deps) *Reconciler {
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	if d.Report == nil {
		d.Report = func(*agentv1.ApplyReport) {}
	}
	return &Reconciler{d: d, log: d.Logger.With("component", "reconcile"), wake: make(chan struct{}, 1)}
}

// SetFetcher sets (or with nil, clears) the bundle downloader.
func (r *Reconciler) SetFetcher(f Fetcher) {
	r.fetchMu.Lock()
	r.fetch = f
	r.fetchMu.Unlock()
}

// Submit queues a desired state; only the latest pending one is applied.
func (r *Reconciler) Submit(ds *agentv1.DesiredState) {
	r.mu.Lock()
	r.pending = ds
	r.retry = nil
	r.mu.Unlock()
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

// Applied returns the applied state (for Hello).
func (r *Reconciler) Applied() *agentv1.AppliedState {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cur.applied == nil {
		return nil
	}
	return proto.Clone(r.cur.applied).(*agentv1.AppliedState)
}

// Warnings returns current configuration warnings.
func (r *Reconciler) Warnings() []*agentv1.Warning {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.warnings)
}

// Instances returns the running instances.
func (r *Reconciler) Instances() []Instance {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.cur.instances)
}

// Restore starts the last applied state. Call it once before Run.
func (r *Reconciler) Restore(ctx context.Context) { r.restore(ctx) }

// Run applies submitted desired states until ctx is cancelled. Every 30
// seconds it re-checks the firewall steering and the local configuration.
func (r *Reconciler) Run(ctx context.Context) error {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	home := time.NewTicker(homeNetPoll)
	defer home.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case now := <-home.C:
			r.checkHomeNet(ctx, now)
		case <-r.wake:
			r.mu.Lock()
			ds := r.pending
			r.pending = nil
			r.mu.Unlock()
			if ds != nil {
				r.applyAndReport(ctx, ds)
			}
		case <-t.C:
			r.periodic(ctx)
			r.mu.Lock()
			ds := r.retry
			due := ds != nil && !time.Now().Before(r.retryAt)
			r.mu.Unlock()
			if due {
				r.log.Info("retrying failed apply", "generation", ds.Generation)
				r.applyAndReport(ctx, ds)
			}
		}
	}
}

// retryable reports whether a failed apply may succeed when retried
// unchanged. Policy and validation failures are deterministic.
func retryable(rep *agentv1.ApplyReport) bool {
	switch rep.Status {
	case agentv1.ApplyStatus_APPLY_STATUS_ROLLED_BACK:
		return true
	case agentv1.ApplyStatus_APPLY_STATUS_FAILED:
		switch rep.Stage {
		case agentv1.ApplyStage_APPLY_STAGE_DOWNLOAD, agentv1.ApplyStage_APPLY_STAGE_VERIFY,
			agentv1.ApplyStage_APPLY_STAGE_FIREWALL, agentv1.ApplyStage_APPLY_STAGE_DONE:
			return true
		}
	}
	return false
}

func (r *Reconciler) applyAndReport(ctx context.Context, ds *agentv1.DesiredState) {
	rep := r.apply(ctx, ds)
	r.mu.Lock()
	switch {
	case retryable(rep) && (r.pending == nil):
		if r.retry == nil || r.retry.Generation != ds.Generation {
			r.retryBackoff = time.Minute
		} else {
			r.retryBackoff = min(r.retryBackoff*2, 30*time.Minute)
		}
		r.retry, r.retryAt = ds, time.Now().Add(r.retryBackoff)
	default:
		r.retry = nil
	}
	r.mu.Unlock()
	r.d.Report(rep)
}

// plan is the part of the desired state that affects the engine.
type plan struct {
	bundleID string
	modes    map[string]agentv1.InterfaceMode
}

func (p plan) interfaces(mode agentv1.InterfaceMode) []string {
	var out []string
	for name, m := range p.modes {
		if m == mode {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func planOf(a *agentv1.AppliedState) plan {
	p := plan{modes: map[string]agentv1.InterfaceMode{}}
	if a == nil {
		return p
	}
	p.bundleID = a.GetBundle().GetBundleId()
	maps.Copy(p.modes, a.InterfaceModes)
	return p
}

func (p plan) equal(o plan) bool {
	norm := func(m map[string]agentv1.InterfaceMode) map[string]agentv1.InterfaceMode {
		out := map[string]agentv1.InterfaceMode{}
		for k, v := range m {
			if v != agentv1.InterfaceMode_INTERFACE_MODE_OFF && v != agentv1.InterfaceMode_INTERFACE_MODE_UNSPECIFIED {
				out[k] = v
			}
		}
		return out
	}
	return p.bundleID == o.bundleID && maps.Equal(norm(p.modes), norm(o.modes))
}

func (r *Reconciler) fwPlan(p plan) firewall.Plan {
	lo, hi, _ := r.d.Config.QueueRange()
	return firewall.Plan{Interfaces: p.interfaces(agentv1.InterfaceMode_INTERFACE_MODE_IPS), QueueFirst: lo, QueueLast: hi, FailOpen: r.d.Config.FailOpen()}
}

// rendered is the outcome of rendering a plan.
type renderedPlan struct {
	specs     []engine.InstanceSpec
	files     map[string][]byte
	instances []Instance
	shadowed  []string
}

// render builds the instance specs of a plan. Staging configs reference the
// release directory directly (for validation); running configs reference the
// stable active directory so a bundle change only needs a rule reload.
func (r *Reconciler) render(p plan, staging bool) (*renderedPlan, error) {
	cfg := r.d.Config
	base, err := r.loadBase()
	if err != nil {
		return nil, err
	}
	var managed *yaml.Node
	rulesDir := ""
	if p.bundleID != "" {
		root := r.d.State.ActiveDir()
		if staging {
			root = r.d.State.ReleaseDir(p.bundleID)
		}
		rulesDir = filepath.Join(root, "rules")
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(bundle.PathControllerYAML)))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		if len(b) > 0 {
			if managed, err = yamlmerge.Parse(b); err != nil {
				return nil, fmt.Errorf("controller.yaml: %w", err)
			}
		}
	}
	out := &renderedPlan{files: map[string][]byte{}}
	add := func(name string, capture engine.CaptureMode, ifaces []string, queues []uint16, homeIfaces []string) error {
		runDir := filepath.Join(cfg.RunDir, name)
		in := engine.RenderInput{
			Instance: name, Capture: capture, Interfaces: ifaces, BaseConfig: cfg.Suricata.BaseConfig, Base: base,
			Managed: managed, RulesDir: rulesDir, LocalRulesDir: cfg.Suricata.LocalRulesDir, LogDir: cfg.LogDir(name),
			SocketPath: filepath.Join(runDir, "suricata.sock"), PidFile: filepath.Join(runDir, "suricata.pid"),
			AllowLua: cfg.Suricata.AllowLua, FailOpen: cfg.FailOpen(), HomeNetAddrs: r.homeNetFor(homeIfaces),
		}
		res, err := engine.Render(in)
		if err != nil {
			return err
		}
		file := "suricata.yaml"
		if staging {
			file = "staging.yaml"
		}
		path := filepath.Join(runDir, file)
		h := sha256.New()
		// HOME_NET addresses only need a rule reload (reloadHomeNet).
		h.Write(res.Static)
		fmt.Fprintf(h, "\x00%s\x00%v\x00%v", capture, ifaces, queues)
		out.specs = append(out.specs, engine.InstanceSpec{
			Name: name, Capture: capture, Interfaces: ifaces, Queues: queues, ConfigPath: path,
			ConfigHash: hex.EncodeToString(h.Sum(nil)), SocketPath: in.SocketPath, PidFile: in.PidFile, LogDir: in.LogDir,
		})
		out.files[path] = res.YAML
		eff, err := yamlmerge.Parse(res.YAML)
		if err != nil {
			return err
		}
		out.instances = append(out.instances, Instance{Name: name, LogDir: in.LogDir, Effective: eff})
		for _, s := range res.Shadowed {
			if !slices.Contains(out.shadowed, s) {
				out.shadowed = append(out.shadowed, s)
			}
		}
		return nil
	}
	if ids := p.interfaces(agentv1.InterfaceMode_INTERFACE_MODE_IDS); len(ids) > 0 {
		if err := add(config.InstanceIDS, engine.CaptureAFPacket, ids, nil, ids); err != nil {
			return nil, err
		}
	}
	if ips := p.interfaces(agentv1.InterfaceMode_INTERFACE_MODE_IPS); len(ips) > 0 {
		lo, hi, _ := cfg.QueueRange()
		var queues []uint16
		for q := lo; q <= hi; q++ {
			queues = append(queues, q)
			if q == hi {
				break
			}
		}
		if err := add(config.InstanceIPS, engine.CaptureNFQ, nil, queues, ips); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (r *Reconciler) loadBase() (*yaml.Node, error) {
	b, err := os.ReadFile(r.d.Config.Suricata.BaseConfig)
	if errors.Is(err, os.ErrNotExist) {
		return yamlmerge.NewMap(), nil
	}
	if err != nil {
		return nil, err
	}
	n, err := yamlmerge.Parse(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", r.d.Config.Suricata.BaseConfig, err)
	}
	return n, nil
}

func writeFiles(files map[string][]byte) error {
	for p, b := range files {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		if err := state.WriteFileAtomic(p, b, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// localHash fingerprints the node user's configuration.
func (r *Reconciler) localHash() string {
	h := sha256.New()
	if b, err := os.ReadFile(r.d.Config.Suricata.BaseConfig); err == nil {
		h.Write(b)
	}
	files, _ := filepath.Glob(filepath.Join(r.d.Config.Suricata.LocalRulesDir, "*.rules"))
	sort.Strings(files)
	for _, f := range files {
		if fi, err := os.Stat(f); err == nil {
			fmt.Fprintf(h, "\x00%s:%d:%d", f, fi.Size(), fi.ModTime().UnixNano())
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (r *Reconciler) setWarnings(shadowed []string, extra ...*agentv1.Warning) {
	var ws []*agentv1.Warning
	if len(shadowed) > 0 {
		ws = append(ws, &agentv1.Warning{Code: "shadowed_keys", Message: "local settings overridden by the controller: " + strings.Join(shadowed, ", ")})
	}
	ws = append(ws, extra...)
	r.mu.Lock()
	r.warnings = ws
	r.mu.Unlock()
}

// restore starts the last applied state at boot.
func (r *Reconciler) restore(ctx context.Context) {
	st, err := r.d.State.Load()
	if err != nil {
		r.log.Error("load state", "err", err)
		st = &state.State{}
	}
	if st.LogPolicy != nil && r.d.OnLogPolicy != nil {
		r.d.OnLogPolicy(st.LogPolicy)
	}
	r.mu.Lock()
	r.cur.logPolicy = st.LogPolicy
	r.mu.Unlock()
	if st.Applied == nil {
		return
	}
	p := planOf(st.Applied)
	if p.bundleID != "" && (!state.ValidID(p.bundleID) || !r.d.State.HasRelease(p.bundleID)) {
		r.log.Warn("applied bundle is missing; starting without managed rules", "bundle", p.bundleID)
		p.bundleID = ""
		st.Applied.Bundle = nil
		st.Applied.Generation = 0
	}
	if err := r.d.State.Activate(p.bundleID); err != nil {
		r.log.Error("activate release", "err", err)
	}
	rp, err := r.render(p, false)
	if err != nil {
		r.log.Error("render restored state", "err", err)
		return
	}
	if err := writeFiles(rp.files); err != nil {
		r.log.Error("write configuration", "err", err)
		return
	}
	fw := r.fwPlan(p)
	if err := r.d.Firewall.Apply(ctx, fw); err != nil {
		r.log.Error("apply firewall", "err", err)
	}
	if err := r.d.Engine.Ensure(ctx, rp.specs); err != nil {
		r.log.Error("start suricata", "err", err)
	}
	r.mu.Lock()
	r.cur = current{applied: st.Applied, logPolicy: st.LogPolicy, specs: rp.specs, rendered: rp.files, instances: rp.instances, fw: fw, localHash: r.localHash()}
	r.mu.Unlock()
	r.setWarnings(rp.shadowed)
	if r.d.OnInstances != nil {
		r.d.OnInstances(rp.instances)
	}
	r.log.Info("restored applied state", "generation", st.Applied.Generation, "bundle", p.bundleID, "instances", len(rp.specs))
}

type report struct {
	r     *Reconciler
	rep   *agentv1.ApplyReport
	start time.Time
}

func (rp *report) progress(stage agentv1.ApplyStage, msg string) {
	rp.rep.Stage, rp.rep.Status, rp.rep.Message = stage, agentv1.ApplyStatus_APPLY_STATUS_IN_PROGRESS, msg
	rp.r.d.Report(proto.Clone(rp.rep).(*agentv1.ApplyReport))
}

func (rp *report) finish(status agentv1.ApplyStatus, stage agentv1.ApplyStage, msg string) *agentv1.ApplyReport {
	rp.rep.Status, rp.rep.Stage, rp.rep.Message = status, stage, msg
	rp.rep.FinishedAtUnixMs = time.Now().UnixMilli()
	rp.rep.Applied = rp.r.Applied()
	if status != agentv1.ApplyStatus_APPLY_STATUS_SUCCEEDED {
		rp.r.log.Warn("apply failed", "generation", rp.rep.Generation, "stage", stage.String(), "message", msg)
	} else {
		rp.r.log.Info("applied desired state", "generation", rp.rep.Generation, "took", time.Since(rp.start).Round(time.Millisecond))
	}
	return rp.rep
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "..." + s[len(s)-n:]
}

// apply applies one desired state and returns the final report.
func (r *Reconciler) apply(ctx context.Context, ds *agentv1.DesiredState) *agentv1.ApplyReport {
	start := time.Now()
	rp := &report{r: r, start: start, rep: &agentv1.ApplyReport{Generation: ds.Generation, StartedAtUnixMs: start.UnixMilli()}}
	cfg := r.d.Config

	if ds.LogPolicy != nil {
		r.mu.Lock()
		r.cur.logPolicy = ds.LogPolicy
		r.mu.Unlock()
		if r.d.OnLogPolicy != nil {
			r.d.OnLogPolicy(ds.LogPolicy)
		}
	}
	newApplied := &agentv1.AppliedState{Generation: ds.Generation, Bundle: ds.Bundle, InterfaceModes: map[string]agentv1.InterfaceMode{}}
	for name, mode := range ds.InterfaceModes {
		if mode == agentv1.InterfaceMode_INTERFACE_MODE_UNSPECIFIED {
			mode = agentv1.InterfaceMode_INTERFACE_MODE_OFF
		}
		newApplied.InterfaceModes[name] = mode
	}
	p := planOf(newApplied)
	if p.bundleID != "" && !state.ValidID(p.bundleID) {
		return rp.finish(agentv1.ApplyStatus_APPLY_STATUS_FAILED, agentv1.ApplyStage_APPLY_STAGE_POLICY, "invalid bundle id")
	}

	r.mu.Lock()
	old := r.cur
	r.mu.Unlock()
	if old.applied != nil && planOf(old.applied).equal(p) {
		if err := r.commit(newApplied, old); err != nil {
			return rp.finish(agentv1.ApplyStatus_APPLY_STATUS_FAILED, agentv1.ApplyStage_APPLY_STAGE_DONE, err.Error())
		}
		return rp.finish(agentv1.ApplyStatus_APPLY_STATUS_SUCCEEDED, agentv1.ApplyStage_APPLY_STAGE_DONE, "already applied")
	}

	// POLICY: the agent configuration is authoritative.
	for name, mode := range p.modes {
		if mode == agentv1.InterfaceMode_INTERFACE_MODE_OFF {
			continue
		}
		if !cfg.Managed(name) {
			return rp.finish(agentv1.ApplyStatus_APPLY_STATUS_FAILED, agentv1.ApplyStage_APPLY_STAGE_POLICY, fmt.Sprintf("interface %s is not managed by this agent", name))
		}
		switch mode {
		case agentv1.InterfaceMode_INTERFACE_MODE_IPS:
			if !cfg.IPSAllowed(name) {
				return rp.finish(agentv1.ApplyStatus_APPLY_STATUS_FAILED, agentv1.ApplyStage_APPLY_STAGE_POLICY, fmt.Sprintf("IPS mode is not allowed on %s", name))
			}
			if !r.d.EngineInfo.NFQ {
				return rp.finish(agentv1.ApplyStatus_APPLY_STATUS_FAILED, agentv1.ApplyStage_APPLY_STAGE_POLICY, "suricata was built without NFQ support")
			}
			if r.d.QueueSupport != nil {
				if err := r.d.QueueSupport(ctx); err != nil {
					return rp.finish(agentv1.ApplyStatus_APPLY_STATUS_FAILED, agentv1.ApplyStage_APPLY_STAGE_POLICY, "IPS is unavailable on "+name+": "+err.Error())
				}
			}
		case agentv1.InterfaceMode_INTERFACE_MODE_IDS:
			if !r.d.EngineInfo.AFPacket {
				return rp.finish(agentv1.ApplyStatus_APPLY_STATUS_FAILED, agentv1.ApplyStage_APPLY_STAGE_POLICY, "suricata was built without AF_PACKET support")
			}
		default:
			return rp.finish(agentv1.ApplyStatus_APPLY_STATUS_FAILED, agentv1.ApplyStage_APPLY_STAGE_POLICY, fmt.Sprintf("invalid mode for %s", name))
		}
	}

	// DOWNLOAD + VERIFY
	if p.bundleID != "" && !r.d.State.HasRelease(p.bundleID) {
		rp.progress(agentv1.ApplyStage_APPLY_STAGE_DOWNLOAD, "downloading bundle")
		if err := r.download(ctx, ds.Bundle); err != nil {
			return rp.finish(agentv1.ApplyStatus_APPLY_STATUS_FAILED, agentv1.ApplyStage_APPLY_STAGE_DOWNLOAD, err.Error())
		}
		if err := r.extract(p.bundleID); err != nil {
			_ = os.Remove(r.d.State.BundlePath(p.bundleID))
			return rp.finish(agentv1.ApplyStatus_APPLY_STATUS_FAILED, agentv1.ApplyStage_APPLY_STAGE_VERIFY, err.Error())
		}
	}

	// RENDER + VALIDATE (staging configuration)
	staging, err := r.render(p, true)
	if err != nil {
		return rp.finish(agentv1.ApplyStatus_APPLY_STATUS_FAILED, agentv1.ApplyStage_APPLY_STAGE_RENDER, err.Error())
	}
	if err := writeFiles(staging.files); err != nil {
		return rp.finish(agentv1.ApplyStatus_APPLY_STATUS_FAILED, agentv1.ApplyStage_APPLY_STAGE_RENDER, err.Error())
	}
	for _, s := range staging.shadowed {
		rp.rep.Warnings = append(rp.rep.Warnings, &agentv1.Warning{Code: "shadowed_key", Message: s})
	}
	if len(staging.specs) > 0 {
		rp.progress(agentv1.ApplyStage_APPLY_STAGE_VALIDATE, "validating configuration")
	}
	for _, spec := range staging.specs {
		res, err := r.d.Engine.Validate(ctx, spec)
		if err != nil {
			return rp.finish(agentv1.ApplyStatus_APPLY_STATUS_FAILED, agentv1.ApplyStage_APPLY_STAGE_VALIDATE, err.Error())
		}
		if !res.OK {
			rp.rep.Detail = tail(res.Output, 8<<10)
			for _, e := range res.RuleErrors {
				rp.rep.RuleErrors = append(rp.rep.RuleErrors, &agentv1.RuleError{File: e.File, Line: uint32(e.Line), Sid: uint32(e.SID), Message: e.Message})
			}
			return rp.finish(agentv1.ApplyStatus_APPLY_STATUS_FAILED, agentv1.ApplyStage_APPLY_STAGE_VALIDATE,
				fmt.Sprintf("suricata -T failed for instance %s", spec.Name))
		}
	}

	// FIREWALL
	newFw := r.fwPlan(p)
	if err := r.d.Firewall.Apply(ctx, newFw); err != nil {
		_ = r.d.Firewall.Apply(ctx, old.fw)
		return rp.finish(agentv1.ApplyStatus_APPLY_STATUS_FAILED, agentv1.ApplyStage_APPLY_STAGE_FIREWALL, err.Error())
	}

	// ACTIVATE
	rp.progress(agentv1.ApplyStage_APPLY_STAGE_ACTIVATE, "activating")
	oldActive := r.d.State.ActiveID()
	rollback := func(stage agentv1.ApplyStage, cause error) *agentv1.ApplyReport {
		msg := cause.Error()
		if err := r.rollback(ctx, old, oldActive); err != nil {
			msg += "; rollback failed: " + err.Error()
		}
		return rp.finish(agentv1.ApplyStatus_APPLY_STATUS_ROLLED_BACK, stage, msg)
	}
	if err := r.d.State.Activate(p.bundleID); err != nil {
		return rollback(agentv1.ApplyStage_APPLY_STAGE_ACTIVATE, err)
	}
	running, err := r.render(p, false)
	if err != nil {
		return rollback(agentv1.ApplyStage_APPLY_STAGE_ACTIVATE, err)
	}
	if err := writeFiles(running.files); err != nil {
		return rollback(agentv1.ApplyStage_APPLY_STAGE_ACTIVATE, err)
	}
	if err := r.d.Engine.Ensure(ctx, running.specs); err != nil {
		return rollback(agentv1.ApplyStage_APPLY_STAGE_ACTIVATE, err)
	}
	if p.bundleID != planOf(old.applied).bundleID {
		for _, spec := range running.specs {
			if !kept(old.specs, spec) {
				continue // freshly started with the new rules
			}
			rctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
			err := r.d.Engine.ReloadRules(rctx, spec.Name)
			cancel()
			if err != nil {
				return rollback(agentv1.ApplyStage_APPLY_STAGE_ACTIVATE, fmt.Errorf("reload rules of %s: %w", spec.Name, err))
			}
		}
	}

	// HEALTHCHECK
	for _, st := range r.d.Engine.Status(ctx) {
		if !st.Running {
			return rollback(agentv1.ApplyStage_APPLY_STAGE_HEALTHCHECK, fmt.Errorf("instance %s is not running: %s", st.Name, st.LastError))
		}
		if st.RulesFailed > 0 {
			rp.rep.Warnings = append(rp.rep.Warnings, &agentv1.Warning{Code: "rules_failed", Message: fmt.Sprintf("%s: %d rules failed to load", st.Name, st.RulesFailed)})
		}
	}

	next := current{
		applied: newApplied, specs: running.specs, rendered: running.files, instances: running.instances,
		fw: newFw, localHash: r.localHash(),
	}
	if err := r.commit(newApplied, next); err != nil {
		return rp.finish(agentv1.ApplyStatus_APPLY_STATUS_FAILED, agentv1.ApplyStage_APPLY_STAGE_DONE, err.Error())
	}
	r.setWarnings(running.shadowed)
	if r.d.OnInstances != nil {
		r.d.OnInstances(running.instances)
	}
	r.d.State.Prune(p.bundleID, planOf(old.applied).bundleID)
	return rp.finish(agentv1.ApplyStatus_APPLY_STATUS_SUCCEEDED, agentv1.ApplyStage_APPLY_STAGE_DONE, "applied")
}

func kept(old []engine.InstanceSpec, s engine.InstanceSpec) bool {
	for _, o := range old {
		if o.Name == s.Name && o.ConfigHash == s.ConfigHash {
			return true
		}
	}
	return false
}

// commit records applied as the current state and persists it.
func (r *Reconciler) commit(applied *agentv1.AppliedState, next current) error {
	r.mu.Lock()
	next.applied = applied
	next.logPolicy = r.cur.logPolicy
	r.cur = next
	st := &state.State{Applied: applied, LogPolicy: next.logPolicy}
	r.mu.Unlock()
	return r.d.State.Save(st)
}

// rollback restores the previous running state.
func (r *Reconciler) rollback(ctx context.Context, old current, oldActive string) error {
	var errs []error
	if err := r.d.State.Activate(oldActive); err != nil {
		errs = append(errs, err)
	}
	if err := writeFiles(old.rendered); err != nil {
		errs = append(errs, err)
	}
	if err := r.d.Firewall.Apply(ctx, old.fw); err != nil {
		errs = append(errs, err)
	}
	if err := r.d.Engine.Ensure(ctx, old.specs); err != nil {
		errs = append(errs, err)
	}
	for _, s := range old.specs {
		rctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
		_ = r.d.Engine.ReloadRules(rctx, s.Name)
		cancel()
	}
	return errors.Join(errs...)
}

// download fetches a bundle into the state directory, resuming a partial
// download.
func (r *Reconciler) download(ctx context.Context, ref *agentv1.BundleRef) error {
	r.fetchMu.Lock()
	fetch := r.fetch
	r.fetchMu.Unlock()
	if fetch == nil {
		return errors.New("not connected to the controller")
	}
	final := r.d.State.BundlePath(ref.BundleId)
	if _, err := os.Stat(final); err == nil {
		return nil
	}
	part := final + ".part"
	var offset uint64
	if fi, err := os.Stat(part); err == nil {
		offset = uint64(fi.Size())
	}
	if ref.Size > 0 && offset >= ref.Size {
		offset = 0
	}
	rc, size, err := fetch(ctx, ref.BundleId, offset)
	if err != nil && offset > 0 {
		offset = 0
		rc, size, err = fetch(ctx, ref.BundleId, 0)
	}
	if err != nil {
		return err
	}
	defer rc.Close()
	if size > uint64(bundle.DefaultLimits.MaxTotalBytes) {
		return fmt.Errorf("bundle too large (%d bytes)", size)
	}
	flags := os.O_CREATE | os.O_WRONLY | os.O_APPEND
	if offset == 0 {
		flags |= os.O_TRUNC
	}
	f, err := os.OpenFile(part, flags, 0o600)
	if err != nil {
		return err
	}
	n, err := io.Copy(f, io.LimitReader(rc, int64(size-offset)))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("download interrupted after %d bytes: %w", offset+uint64(n), err)
	}
	if offset+uint64(n) != size {
		return fmt.Errorf("download incomplete: %d of %d bytes", offset+uint64(n), size)
	}
	return os.Rename(part, final)
}

// extract verifies a downloaded bundle and writes it to its release
// directory.
func (r *Reconciler) extract(id string) error {
	f, err := os.Open(r.d.State.BundlePath(id))
	if err != nil {
		return err
	}
	defer f.Close()
	key := r.d.HostKey()
	if key == nil {
		return errors.New("controller host key unknown")
	}
	b, err := bundle.Read(f, id, key, bundle.DefaultLimits)
	if err != nil {
		return err
	}
	if b.Manifest.NodeID != r.d.Config.NodeID {
		return fmt.Errorf("bundle was rendered for node %q", b.Manifest.NodeID)
	}
	if y, ok := b.Files[bundle.PathControllerYAML]; ok {
		root, err := yamlmerge.Parse(y)
		if err != nil {
			return fmt.Errorf("controller.yaml: %w", err)
		}
		if err := overlay.Check(root); err != nil {
			return err
		}
	}
	if !r.d.Config.Suricata.AllowLua {
		if n, err := luaRules(b.Files[bundle.PathRules]); err != nil {
			return err
		} else if n > 0 {
			return fmt.Errorf("bundle contains %d enabled lua rules; set suricata.allow_lua in agent.yaml to allow them", n)
		}
	}
	tmp := r.d.State.ReleaseDir(id) + ".tmp"
	_ = os.RemoveAll(tmp)
	if err := b.WriteTo(tmp); err != nil {
		return err
	}
	return os.Rename(tmp, r.d.State.ReleaseDir(id))
}

func luaRules(rules []byte) (int, error) {
	parsed, err := ruleset.ParseFile("suricata.rules", bytes.NewReader(rules))
	if err != nil {
		return 0, err
	}
	n := 0
	for _, rule := range parsed {
		if rule.Enabled && rule.UsesLua() {
			n++
		}
	}
	return n, nil
}

// periodic re-applies the firewall steering if it disappeared and picks up
// local configuration changes.
func (r *Reconciler) periodic(ctx context.Context) {
	r.mu.Lock()
	cur := r.cur
	r.mu.Unlock()
	if ok, err := r.d.Firewall.Check(ctx, cur.fw); err == nil && !ok {
		r.log.Warn("firewall steering missing, re-applying")
		if err := r.d.Firewall.Apply(ctx, cur.fw); err != nil {
			r.log.Error("re-apply firewall", "err", err)
		}
	}
	if cur.applied == nil || r.localHash() == cur.localHash {
		return
	}
	r.applyLocalChange(ctx, cur)
}

// applyLocalChange re-renders the current plan after the node user edited
// the base configuration or local rules.
func (r *Reconciler) applyLocalChange(ctx context.Context, cur current) {
	p := planOf(cur.applied)
	hash := r.localHash()
	fail := func(err error) {
		r.log.Error("local configuration change rejected; keeping the running configuration", "err", err)
		r.mu.Lock()
		r.cur.localHash = hash // do not retry until the files change again
		r.mu.Unlock()
		r.setWarnings(nil, &agentv1.Warning{Code: "local_config_invalid", Message: err.Error()})
	}
	staging, err := r.render(p, true)
	if err != nil {
		fail(err)
		return
	}
	if err := writeFiles(staging.files); err != nil {
		fail(err)
		return
	}
	for _, spec := range staging.specs {
		res, err := r.d.Engine.Validate(ctx, spec)
		if err == nil && !res.OK {
			err = fmt.Errorf("suricata -T failed for %s: %s", spec.Name, tail(res.Output, 2048))
		}
		if err != nil {
			fail(err)
			return
		}
	}
	running, err := r.render(p, false)
	if err != nil {
		fail(err)
		return
	}
	if err := writeFiles(running.files); err != nil {
		fail(err)
		return
	}
	if err := r.d.Engine.Ensure(ctx, running.specs); err != nil {
		fail(err)
		return
	}
	for _, spec := range running.specs {
		if kept(cur.specs, spec) {
			rctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
			_ = r.d.Engine.ReloadRules(rctx, spec.Name)
			cancel()
		}
	}
	r.mu.Lock()
	r.cur.specs, r.cur.rendered, r.cur.instances, r.cur.localHash = running.specs, running.files, running.instances, hash
	r.mu.Unlock()
	r.setWarnings(running.shadowed)
	if r.d.OnInstances != nil {
		r.d.OnInstances(running.instances)
	}
	r.log.Info("applied local configuration change")
}
