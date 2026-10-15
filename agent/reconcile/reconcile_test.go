package reconcile

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jc-lab/suricontroller/agent/config"
	"github.com/jc-lab/suricontroller/agent/engine"
	"github.com/jc-lab/suricontroller/agent/firewall"
	"github.com/jc-lab/suricontroller/agent/state"
	agentv1 "github.com/jc-lab/suricontroller/gen/suricontroller/agent/v1"
	"github.com/jc-lab/suricontroller/pkg/bundle"
)

type fakeEngine struct {
	mu          sync.Mutex
	running     map[string]engine.InstanceSpec
	ensureCalls int
	reloads     []string
	validateErr bool
	ensureErr   error
}

func (f *fakeEngine) Info(context.Context) (engine.Info, error) {
	return engine.Info{NFQ: true, AFPacket: true}, nil
}
func (f *fakeEngine) Validate(_ context.Context, spec engine.InstanceSpec) (*engine.ValidationResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.validateErr {
		return &engine.ValidationResult{OK: false, Output: "E: detect: error parsing signature \"alert x (sid:7;)\" from file /r/suricata.rules at line 3",
			RuleErrors: []engine.RuleError{{File: "/r/suricata.rules", Line: 3, SID: 7}}}, nil
	}
	if _, err := os.Stat(spec.ConfigPath); err != nil {
		return nil, err
	}
	return &engine.ValidationResult{OK: true}, nil
}
func (f *fakeEngine) Ensure(_ context.Context, specs []engine.InstanceSpec) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ensureCalls++
	if f.ensureErr != nil {
		err := f.ensureErr
		f.ensureErr = nil // the rollback succeeds
		return err
	}
	f.running = map[string]engine.InstanceSpec{}
	for _, s := range specs {
		f.running[s.Name] = s
	}
	return nil
}
func (f *fakeEngine) ReloadRules(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reloads = append(f.reloads, name)
	return nil
}
func (f *fakeEngine) Signal(string, os.Signal) error { return nil }
func (f *fakeEngine) Status(context.Context) []engine.InstanceStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []engine.InstanceStatus
	for name := range f.running {
		out = append(out, engine.InstanceStatus{Name: name, Running: true})
	}
	return out
}
func (f *fakeEngine) Output() <-chan engine.LogLine { return nil }
func (f *fakeEngine) Stop(context.Context) error    { return nil }

type fakeFirewall struct {
	mu   sync.Mutex
	plan firewall.Plan
}

func (f *fakeFirewall) Name() string { return "fake" }
func (f *fakeFirewall) Apply(_ context.Context, p firewall.Plan) error {
	f.mu.Lock()
	f.plan = p
	f.mu.Unlock()
	return nil
}
func (f *fakeFirewall) Check(context.Context, firewall.Plan) (bool, error) { return true, nil }
func (f *fakeFirewall) Remove(context.Context) error                       { return nil }

type env struct {
	cfg     *config.Config
	st      *state.Store
	eng     *fakeEngine
	fw      *fakeFirewall
	rec     *Reconciler
	key     ed25519.PrivateKey
	bundles map[string][]byte
	reports []*agentv1.ApplyReport
}

func newEnv(t *testing.T, dir string) *env {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	cfg := config.Default()
	cfg.NodeID = "router-01"
	cfg.Interfaces = []config.Interface{{Name: "eth0"}, {Name: "eth1"}}
	cfg.IPS.Enabled = true
	no := false
	cfg.Interfaces[1].IPS = &no
	cfg.StateDir = filepath.Join(dir, "state")
	cfg.RunDir = filepath.Join(dir, "run")
	cfg.Suricata.BaseConfig = filepath.Join(dir, "suricata.yaml")
	cfg.Suricata.LocalRulesDir = filepath.Join(dir, "rules.local")
	cfg.Suricata.Instances = map[string]config.Instance{"ids": {LogDir: filepath.Join(dir, "log/ids")}, "ips": {LogDir: filepath.Join(dir, "log/ips")}}
	os.WriteFile(cfg.Suricata.BaseConfig, []byte("vars:\n  address-groups:\n    HOME_NET: '[192.168.0.0/16]'\n"), 0o644)
	st, err := state.Open(cfg.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	e := &env{cfg: cfg, st: st, eng: &fakeEngine{}, fw: &fakeFirewall{}, key: priv, bundles: map[string][]byte{}}
	e.rec = New(Deps{
		Config: cfg, State: st, Engine: e.eng, EngineInfo: engine.Info{NFQ: true, AFPacket: true}, Firewall: e.fw, HostKey: pub,
		Report: func(r *agentv1.ApplyReport) { e.reports = append(e.reports, r) },
	})
	e.rec.SetFetcher(func(ctx context.Context, id string, offset uint64) (io.ReadCloser, uint64, error) {
		b, ok := e.bundles[id]
		if !ok {
			return nil, 0, errors.New("no such bundle")
		}
		return io.NopCloser(bytes.NewReader(b[offset:])), uint64(len(b)), nil
	})
	return e
}

func (e *env) bundle(t *testing.T, rules string, yaml string) *agentv1.BundleRef {
	t.Helper()
	files := map[string][]byte{bundle.PathRules: []byte(rules)}
	if yaml != "" {
		files[bundle.PathControllerYAML] = []byte(yaml)
	}
	b, err := bundle.Build(bundle.Manifest{NodeID: e.cfg.NodeID}, files, e.key)
	if err != nil {
		t.Fatal(err)
	}
	e.bundles[b.ID] = b.Archive
	return &agentv1.BundleRef{BundleId: b.ID, Size: uint64(len(b.Archive))}
}

func modes(kv ...string) map[string]agentv1.InterfaceMode {
	m := map[string]agentv1.InterfaceMode{}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = agentv1.InterfaceMode(agentv1.InterfaceMode_value["INTERFACE_MODE_"+kv[i+1]])
	}
	return m
}

const rulesA = "alert tcp any any -> any 80 (msg:\"a\"; sid:1; rev:1;)\n"
const rulesB = "alert tcp any any -> any 81 (msg:\"b\"; sid:2; rev:1;)\n"

func TestApplyLifecycle(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	e := newEnv(t, dir)
	b1 := e.bundle(t, rulesA, "vars:\n  address-groups:\n    HOME_NET: '[10.0.0.0/8]'\n")

	rep := e.rec.apply(ctx, &agentv1.DesiredState{Generation: 1, Bundle: b1, InterfaceModes: modes("eth0", "IDS", "eth1", "OFF")})
	if rep.Status != agentv1.ApplyStatus_APPLY_STATUS_SUCCEEDED {
		t.Fatalf("apply 1: %v %s", rep.Status, rep.Message)
	}
	if e.st.ActiveID() != b1.BundleId || e.eng.running["ids"].Interfaces[0] != "eth0" || len(e.eng.running) != 1 {
		t.Fatalf("active=%s running=%v", e.st.ActiveID(), e.eng.running)
	}
	if len(rep.Warnings) != 1 || rep.Warnings[0].Message != "vars.address-groups.HOME_NET" {
		t.Fatalf("shadowed warnings = %v", rep.Warnings)
	}
	running, _ := os.ReadFile(e.eng.running["ids"].ConfigPath)
	if !strings.Contains(string(running), filepath.Join(e.st.ActiveDir(), "rules", "suricata.rules")) {
		t.Fatalf("running config must use the active directory:\n%s", running)
	}

	// Same plan with a new generation: no engine change.
	calls := e.eng.ensureCalls
	rep = e.rec.apply(ctx, &agentv1.DesiredState{Generation: 2, Bundle: b1, InterfaceModes: modes("eth0", "IDS")})
	if rep.Status != agentv1.ApplyStatus_APPLY_STATUS_SUCCEEDED || rep.Message != "already applied" || e.eng.ensureCalls != calls || rep.Applied.Generation != 2 {
		t.Fatalf("already applied: %+v", rep)
	}

	// Rules-only change: the instance keeps running and reloads rules.
	b2 := e.bundle(t, rulesB, "vars:\n  address-groups:\n    HOME_NET: '[10.0.0.0/8]'\n")
	oldHash := e.eng.running["ids"].ConfigHash
	rep = e.rec.apply(ctx, &agentv1.DesiredState{Generation: 3, Bundle: b2, InterfaceModes: modes("eth0", "IDS")})
	if rep.Status != agentv1.ApplyStatus_APPLY_STATUS_SUCCEEDED || e.eng.running["ids"].ConfigHash != oldHash || len(e.eng.reloads) != 1 {
		t.Fatalf("rules change: %+v reloads=%v", rep, e.eng.reloads)
	}
	b, _ := os.ReadFile(filepath.Join(e.st.ActiveDir(), "rules", "suricata.rules"))
	if string(b) != rulesB {
		t.Fatal("active rules not switched")
	}

	// IPS on eth0: second instance + firewall steering.
	rep = e.rec.apply(ctx, &agentv1.DesiredState{Generation: 4, Bundle: b2, InterfaceModes: modes("eth0", "IPS", "eth1", "IDS")})
	if rep.Status != agentv1.ApplyStatus_APPLY_STATUS_SUCCEEDED || len(e.eng.running) != 2 || e.eng.running["ips"].Capture != engine.CaptureNFQ {
		t.Fatalf("ips: %+v running=%v", rep, e.eng.running)
	}
	if len(e.fw.plan.Interfaces) != 1 || e.fw.plan.Interfaces[0] != "eth0" || !e.fw.plan.FailOpen {
		t.Fatalf("firewall plan = %+v", e.fw.plan)
	}

	// Policy: IPS not allowed on eth1, unknown interfaces rejected.
	for _, m := range []map[string]agentv1.InterfaceMode{modes("eth1", "IPS"), modes("wan9", "IDS")} {
		rep = e.rec.apply(ctx, &agentv1.DesiredState{Generation: 5, Bundle: b2, InterfaceModes: m})
		if rep.Status != agentv1.ApplyStatus_APPLY_STATUS_FAILED || rep.Stage != agentv1.ApplyStage_APPLY_STAGE_POLICY || rep.Applied.Generation != 4 {
			t.Fatalf("policy: %+v", rep)
		}
	}

	// Validation failure keeps the running state.
	b3 := e.bundle(t, "alert bad\n", "")
	e.eng.validateErr = true
	rep = e.rec.apply(ctx, &agentv1.DesiredState{Generation: 6, Bundle: b3, InterfaceModes: modes("eth0", "IPS", "eth1", "IDS")})
	e.eng.validateErr = false
	if rep.Status != agentv1.ApplyStatus_APPLY_STATUS_FAILED || rep.Stage != agentv1.ApplyStage_APPLY_STAGE_VALIDATE || len(rep.RuleErrors) != 1 || rep.RuleErrors[0].Sid != 7 {
		t.Fatalf("validate: %+v", rep)
	}
	if e.st.ActiveID() != b2.BundleId {
		t.Fatal("active changed after failed validation")
	}

	// Activation failure rolls back.
	e.eng.ensureErr = errors.New("suricata exited during startup")
	rep = e.rec.apply(ctx, &agentv1.DesiredState{Generation: 7, Bundle: b1, InterfaceModes: modes("eth0", "IDS")})
	if rep.Status != agentv1.ApplyStatus_APPLY_STATUS_ROLLED_BACK || e.st.ActiveID() != b2.BundleId || len(e.eng.running) != 2 || rep.Applied.Generation != 4 {
		t.Fatalf("rollback: %+v active=%s running=%v", rep, e.st.ActiveID(), e.eng.running)
	}
	if len(e.fw.plan.Interfaces) != 1 {
		t.Fatal("firewall not rolled back")
	}

	// A new reconciler restores the applied state at boot.
	e2 := newEnv(t, dir)
	e2.rec.restore(ctx)
	if len(e2.eng.running) != 2 || e2.rec.Applied().Generation != 4 || len(e2.fw.plan.Interfaces) != 1 {
		t.Fatalf("restore: running=%v applied=%v", e2.eng.running, e2.rec.Applied())
	}
}

func TestRejectsBadBundles(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, t.TempDir())
	lua := e.bundle(t, "alert tcp any any -> any any (msg:\"l\"; lua:x.lua; sid:9; rev:1;)\n", "")
	rep := e.rec.apply(ctx, &agentv1.DesiredState{Generation: 1, Bundle: lua, InterfaceModes: modes("eth0", "IDS")})
	if rep.Status != agentv1.ApplyStatus_APPLY_STATUS_FAILED || rep.Stage != agentv1.ApplyStage_APPLY_STAGE_VERIFY || !strings.Contains(rep.Message, "lua") {
		t.Fatalf("lua: %+v", rep)
	}
	// A bundle signed by another key is rejected.
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	b, _ := bundle.Build(bundle.Manifest{NodeID: "router-01"}, map[string][]byte{bundle.PathRules: []byte(rulesA)}, other)
	e.bundles[b.ID] = b.Archive
	rep = e.rec.apply(ctx, &agentv1.DesiredState{Generation: 2, Bundle: &agentv1.BundleRef{BundleId: b.ID, Size: uint64(len(b.Archive))}, InterfaceModes: modes("eth0", "IDS")})
	if rep.Status != agentv1.ApplyStatus_APPLY_STATUS_FAILED || rep.Stage != agentv1.ApplyStage_APPLY_STAGE_VERIFY {
		t.Fatalf("signature: %+v", rep)
	}
	// Not connected.
	e.rec.SetFetcher(nil)
	ok := e.bundle(t, rulesA, "")
	rep = e.rec.apply(ctx, &agentv1.DesiredState{Generation: 3, Bundle: ok, InterfaceModes: modes("eth0", "IDS")})
	if rep.Status != agentv1.ApplyStatus_APPLY_STATUS_FAILED || rep.Stage != agentv1.ApplyStage_APPLY_STAGE_DOWNLOAD {
		t.Fatalf("offline: %+v", rep)
	}
}

func TestLocalChangeReapplies(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, t.TempDir())
	rep := e.rec.apply(ctx, &agentv1.DesiredState{Generation: 1, InterfaceModes: modes("eth0", "IDS")})
	if rep.Status != agentv1.ApplyStatus_APPLY_STATUS_SUCCEEDED {
		t.Fatal(rep.Message)
	}
	hash := e.eng.running["ids"].ConfigHash
	os.WriteFile(e.cfg.Suricata.BaseConfig, []byte("vars:\n  address-groups:\n    HOME_NET: '[172.16.0.0/12]'\n"), 0o644)
	e.rec.periodic(ctx)
	if e.eng.running["ids"].ConfigHash == hash {
		t.Fatal("local change not applied")
	}
	// An invalid local change is reported and the running config kept.
	hash = e.eng.running["ids"].ConfigHash
	os.WriteFile(e.cfg.Suricata.BaseConfig, []byte("vars:\n  address-groups:\n    HOME_NET: '[10.1.0.0/16]'\n"), 0o644)
	e.eng.validateErr = true
	e.rec.periodic(ctx)
	if e.eng.running["ids"].ConfigHash != hash || len(e.rec.Warnings()) != 1 || e.rec.Warnings()[0].Code != "local_config_invalid" {
		t.Fatalf("invalid local change: warnings=%v", e.rec.Warnings())
	}
}

func TestRejectsInvalidBundleID(t *testing.T) {
	e := newEnv(t, t.TempDir())
	outside := filepath.Join(t.TempDir(), "outside")
	os.MkdirAll(filepath.Join(outside, "rules"), 0o755)
	rel, _ := filepath.Rel(e.st.Dir()+"/releases", outside)
	rep := e.rec.apply(context.Background(), &agentv1.DesiredState{Generation: 1, Bundle: &agentv1.BundleRef{BundleId: rel}, InterfaceModes: modes("eth0", "IDS")})
	if rep.Status != agentv1.ApplyStatus_APPLY_STATUS_FAILED || rep.Stage != agentv1.ApplyStage_APPLY_STAGE_POLICY {
		t.Fatalf("traversal id: %+v", rep)
	}
	if e.st.ActiveID() != "" {
		t.Fatal("active changed")
	}
}

func TestTransientFailureIsRetried(t *testing.T) {
	e := newEnv(t, t.TempDir())
	ok := e.bundle(t, rulesA, "")
	e.rec.SetFetcher(nil) // offline: DOWNLOAD fails
	ds := &agentv1.DesiredState{Generation: 1, Bundle: ok, InterfaceModes: modes("eth0", "IDS")}
	e.rec.applyAndReport(context.Background(), ds)
	if e.rec.retry == nil || time.Until(e.rec.retryAt) < 50*time.Second {
		t.Fatalf("retry not scheduled: %v %v", e.rec.retry, e.rec.retryAt)
	}
	e.rec.applyAndReport(context.Background(), ds)
	if time.Until(e.rec.retryAt) < 110*time.Second {
		t.Fatal("backoff not increased")
	}
	// Deterministic failures are not retried.
	e.eng.validateErr = true
	e.rec.applyAndReport(context.Background(), &agentv1.DesiredState{Generation: 2, InterfaceModes: modes("eth0", "IDS")})
	if e.rec.retry != nil {
		t.Fatal("validation failure scheduled for retry")
	}
}

// Without kernel NFQUEUE support (e.g. OpenWrt without kmod-nft-queue) an
// IPS request fails in the POLICY stage with what to install, before the
// firewall is touched; IDS still applies.
func TestIPSWithoutQueueSupport(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, t.TempDir())
	e.rec.d.QueueSupport = func(context.Context) error {
		return errors.New("the kernel lacks NFQUEUE support (opkg install kmod-nft-queue kmod-nfnetlink-queue)")
	}
	rep := e.rec.apply(ctx, &agentv1.DesiredState{Generation: 1, InterfaceModes: modes("eth0", "IPS")})
	if rep.Status != agentv1.ApplyStatus_APPLY_STATUS_FAILED || rep.Stage != agentv1.ApplyStage_APPLY_STAGE_POLICY ||
		!strings.Contains(rep.Message, "kmod-nft-queue") {
		t.Fatalf("IPS: %v %v %s", rep.Status, rep.Stage, rep.Message)
	}
	if len(e.fw.plan.Interfaces) != 0 {
		t.Fatalf("firewall touched: %+v", e.fw.plan)
	}
	rep = e.rec.apply(ctx, &agentv1.DesiredState{Generation: 2, InterfaceModes: modes("eth0", "IDS")})
	if rep.Status != agentv1.ApplyStatus_APPLY_STATUS_SUCCEEDED {
		t.Fatalf("IDS: %v %s", rep.Status, rep.Message)
	}
}
