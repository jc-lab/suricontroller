// Package agent is suri-node-agent: it keeps a session with the
// controller, applies the desired state it receives, reports status and
// ships the selected logs.
package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jc-lab/suricontroller/agent/collector"
	"github.com/jc-lab/suricontroller/agent/config"
	"github.com/jc-lab/suricontroller/agent/conn"
	"github.com/jc-lab/suricontroller/agent/engine"
	"github.com/jc-lab/suricontroller/agent/firewall"
	"github.com/jc-lab/suricontroller/agent/platform"
	"github.com/jc-lab/suricontroller/agent/reconcile"
	"github.com/jc-lab/suricontroller/agent/state"
	agentv1 "github.com/jc-lab/suricontroller/gen/suricontroller/agent/v1"
	"github.com/jc-lab/suricontroller/pkg/sshkey"
	"github.com/jc-lab/suricontroller/pkg/version"
)

// Options configures New.
type Options struct {
	Logger *slog.Logger
	// LogTee, if set, receives the collector's agent-log writer so the
	// agent's own log can be shipped to the controller.
	LogTee *LogTee
	// Engine overrides the Suricata runtime (tests).
	Engine engine.Runtime
	// Firewall overrides the firewall backend (tests).
	Firewall firewall.Backend
}

// Agent is a running suri-node-agent.
type Agent struct {
	cfg     *config.Config
	log     *slog.Logger
	key     *sshkey.PrivateKey
	hostKey *sshkey.PublicKey
	fs      platform.HostFS
	ex      platform.Exec
	info    platform.Info
	eng     engine.Runtime
	engInfo engine.Info
	fw      firewall.Backend
	st      *state.Store
	rec     *reconcile.Reconciler
	col     *collector.Collector
	client  *http.Client

	mu   sync.Mutex
	sess *conn.Session
	// clockOffset corrects handshake timestamps on hosts with a wrong clock
	// (e.g. routers without RTC before NTP sync).
	clockOffset time.Duration
	// statusNow requests an immediate status report.
	statusNow chan struct{}
}

// LoadKey loads the agent key, creating it on first start.
func LoadKey(cfg *config.Config) (*sshkey.PrivateKey, bool, error) {
	return sshkey.LoadOrGenerate(cfg.KeyFile, cfg.NodeID)
}

// New prepares an agent.
func New(ctx context.Context, cfg *config.Config, opts Options) (*Agent, error) {
	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}
	a := &Agent{cfg: cfg, log: log, statusNow: make(chan struct{}, 1)}
	var err error
	var created bool
	if a.key, created, err = LoadKey(cfg); err != nil {
		return nil, fmt.Errorf("agent key: %w", err)
	}
	if created {
		log.Info("generated agent key; register this public key on the controller", "public_key", a.key.Public(cfg.NodeID).String())
	}
	if a.hostKey, err = sshkey.ParsePublicKey(cfg.Controller.HostKey); err != nil {
		return nil, err
	}

	switch cfg.Platform.Profile {
	case config.ProfileDocker:
		a.fs = platform.HostFS{Root: cfg.Platform.HostRoot}
		a.ex = platform.ChrootExec{Root: cfg.Platform.HostRoot, Fallback: platform.LocalExec{}}
	default:
		a.fs = platform.HostFS{Root: "/"}
		a.ex = platform.LocalExec{}
	}
	a.info = platform.Probe(ctx, a.fs, a.ex)

	a.eng = opts.Engine
	if a.eng == nil {
		// Native profiles run Suricata as a supervised child process too
		// until service-manager runtimes (procd, systemd) are added.
		a.eng = &engine.Supervisor{Binary: cfg.Suricata.Binary, ExtraArgs: cfg.Suricata.ExtraArgs, Logger: log, ValidateTimeout: cfg.Suricata.ValidateTimeout}
	}
	if a.engInfo, err = a.eng.Info(ctx); err != nil {
		return nil, err
	}
	a.fw = opts.Firewall
	if a.fw == nil {
		if a.fw, err = firewall.New(cfg.Platform.Firewall, a.ex); err != nil {
			return nil, err
		}
	}
	if a.st, err = state.Open(cfg.StateDir); err != nil {
		return nil, err
	}

	var extra []collector.Source
	for _, s := range cfg.Logs.ExtraSources {
		t := map[string]agentv1.LogType{"eve": agentv1.LogType_LOG_TYPE_EVE, "suricata": agentv1.LogType_LOG_TYPE_SURICATA,
			"fast": agentv1.LogType_LOG_TYPE_FAST, "stats": agentv1.LogType_LOG_TYPE_STATS}[s.Type]
		if t == agentv1.LogType_LOG_TYPE_UNSPECIFIED {
			return nil, fmt.Errorf("logs.extra_sources: unknown type %q", s.Type)
		}
		extra = append(extra, collector.Source{Type: t, Instance: s.Instance, Path: s.Path})
	}
	colCfg := collector.Config{
		QueueMaxBytes: int64(cfg.Logs.QueueMaxBytes),
		StartAtEnd:    cfg.Logs.StartPosition == "end",
		OffsetsFile:   filepath.Join(cfg.StateDir, "collector-offsets.json"),
		Extra:         extra,
		Reopen:        func(inst string) error { return a.eng.Signal(inst, sighup) },
		Logger:        log,
	}
	if cfg.Logs.Rotation.Enabled {
		colCfg.RotateMaxSize, colCfg.RotateKeep = int64(cfg.Logs.Rotation.MaxSize), cfg.Logs.Rotation.Keep
	}
	a.col = collector.New(colCfg)
	if opts.LogTee != nil {
		opts.LogTee.SetTarget(a.col.AgentLogWriter())
	}
	a.rec = reconcile.New(reconcile.Deps{
		Config: cfg, State: a.st, Engine: a.eng, EngineInfo: a.engInfo, Firewall: a.fw, HostKey: a.hostKey.Key, Logger: log,
		Report: a.report,
		OnInstances: func(insts []reconcile.Instance) {
			out := make([]collector.Instance, len(insts))
			for i, in := range insts {
				out[i] = collector.Instance{Name: in.Name, LogDir: in.LogDir, Effective: in.Effective}
			}
			a.col.SetInstances(out)
			a.pokeStatus()
		},
		OnLogPolicy: a.col.SetPolicy,
	})
	if a.client, err = httpClient(cfg); err != nil {
		return nil, err
	}
	return a, nil
}

func httpClient(cfg *config.Config) (*http.Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: cfg.Controller.TLSInsecureSkipVerify}
	if cfg.Controller.CAFile != "" {
		pem, err := os.ReadFile(cfg.Controller.CAFile)
		if err != nil {
			return nil, err
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("controller.ca_file: no certificates found")
		}
		tlsCfg.RootCAs = pool
	}
	return &http.Client{Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: tlsCfg}}, nil
}

// ReopenLogs asks every running Suricata instance to reopen its log files
// (after an external logrotate).
func (a *Agent) ReopenLogs() {
	for _, in := range a.eng.Status(context.Background()) {
		if err := a.eng.Signal(in.Name, sighup); err != nil {
			a.log.Warn("reopen logs", "instance", in.Name, "err", err)
		}
	}
}

// PublicKey returns the agent public key line.
func (a *Agent) PublicKey() string { return a.key.Public(a.cfg.NodeID).String() }

// Run runs the agent until ctx is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	a.log.Info("suri-node-agent starting", "version", version.Version, "node", a.cfg.NodeID, "suricata", a.engInfo.Version,
		"firewall", a.fw.Name(), "os", a.info.OSName+" "+a.info.OSVersion)
	a.rec.Restore(ctx)
	var wg sync.WaitGroup
	for _, fn := range []func(context.Context){
		func(ctx context.Context) { _ = a.rec.Run(ctx) },
		a.col.Run,
		a.pumpEngineOutput,
	} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fn(ctx)
		}()
	}
	a.connectLoop(ctx)
	wg.Wait()
	stopCtx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	_ = a.eng.Stop(stopCtx)
	// Remove NFQUEUE steering: with fail-closed IPS, rules left without a
	// listener would drop all traffic of the IPS interfaces. Restored at the
	// next start.
	if err := a.fw.Remove(stopCtx); err != nil {
		a.log.Error("remove firewall steering", "err", err)
	}
	return nil
}

func (a *Agent) pumpEngineOutput(ctx context.Context) {
	out := a.eng.Output()
	for {
		select {
		case <-ctx.Done():
			return
		case l, ok := <-out:
			if !ok {
				return
			}
			a.col.PushEngineLine(l.Instance, l.Line)
		}
	}
}

func (a *Agent) session() *conn.Session {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.sess
}

func (a *Agent) setSession(s *conn.Session) {
	a.mu.Lock()
	a.sess = s
	a.mu.Unlock()
	if s != nil {
		a.rec.SetFetcher(s.FetchBlob)
	} else {
		a.rec.SetFetcher(nil)
	}
}

func (a *Agent) report(r *agentv1.ApplyReport) {
	if s := a.session(); s != nil {
		if err := s.Notify(&agentv1.Envelope{Body: &agentv1.Envelope_ApplyReport{ApplyReport: r}}); err != nil {
			a.log.Debug("send apply report", "err", err)
		}
	}
}

func (a *Agent) handle(_ context.Context, env *agentv1.Envelope) (*agentv1.Envelope, error) {
	if ds := env.GetDesiredState(); ds != nil {
		a.rec.Submit(ds)
	}
	return nil, nil
}

func (a *Agent) connectLoop(ctx context.Context) {
	backoff := time.Second
	headers := http.Header{}
	for k, v := range a.cfg.Controller.Headers {
		headers.Set(k, v)
	}
	for ctx.Err() == nil {
		offset := a.clockOffset
		sess, err := conn.Dial(ctx, conn.Config{
			URL: a.cfg.Controller.URL, Headers: headers, HTTPClient: a.client, Key: a.key, ServerKey: a.hostKey,
			NodeID: a.cfg.NodeID, AgentVersion: version.Version, Now: func() time.Time { return time.Now().Add(offset) },
		}, a.hello(), a.handle)
		if err != nil {
			var re *conn.RejectedError
			switch {
			case errors.As(err, &re) && re.Reason == agentv1.RejectReason_REJECT_REASON_CLOCK_SKEW && !re.ServerTime.IsZero():
				a.clockOffset = time.Until(re.ServerTime)
				a.log.Warn("local clock differs from the controller; correcting handshake time", "offset", a.clockOffset.Round(time.Second))
				sleep(ctx, time.Second)
				continue
			case errors.As(err, &re) && re.Reason == agentv1.RejectReason_REJECT_REASON_UNKNOWN_KEY:
				a.log.Error("controller does not know this agent; register its public key", "public_key", a.PublicKey())
				backoff = max(backoff, 30*time.Second)
			case errors.As(err, &re):
				a.log.Error("controller rejected this agent", "reason", re.Reason.String())
				backoff = max(backoff, 30*time.Second)
			default:
				a.log.Warn("connect to controller failed", "err", err, "retry_in", backoff)
			}
			sleep(ctx, jitter(backoff))
			backoff = min(backoff*2, time.Minute)
			continue
		}
		backoff = time.Second
		a.log.Info("connected to controller", "url", a.cfg.Controller.URL, "controller_version", sess.HelloAck().ControllerVersion)
		a.setSession(sess)
		sessCtx, cancel := context.WithCancel(ctx)
		interval := time.Duration(sess.HelloAck().StatusIntervalSeconds) * time.Second
		go a.statusLoop(sessCtx, sess, interval)
		go a.shipLogs(sessCtx, sess)
		err = sess.Run(sessCtx)
		cancel()
		a.setSession(nil)
		if ctx.Err() == nil {
			a.log.Warn("disconnected from controller", "err", err)
			sleep(ctx, jitter(time.Second))
		}
	}
}

func jitter(d time.Duration) time.Duration {
	return d/2 + time.Duration(rand.Int64N(int64(d)))
}

func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

func (a *Agent) shipLogs(ctx context.Context, sess *conn.Session) {
	for ctx.Err() == nil {
		ms, err := sess.OpenLogs()
		if err != nil {
			sleep(ctx, time.Second)
			continue
		}
		if err := a.col.Ship(ctx, ms); err != nil && ctx.Err() == nil {
			a.log.Debug("log stream ended", "err", err)
			sleep(ctx, time.Second)
		}
	}
}

func (a *Agent) pokeStatus() {
	select {
	case a.statusNow <- struct{}{}:
	default:
	}
}

func (a *Agent) statusLoop(ctx context.Context, sess *conn.Session, interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if err := sess.Notify(&agentv1.Envelope{Body: &agentv1.Envelope_Status{Status: a.status(ctx)}}); err != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-a.statusNow:
		}
	}
}

func (a *Agent) interfaces() []*agentv1.InterfaceInfo {
	var out []*agentv1.InterfaceInfo
	for _, ifc := range a.cfg.Interfaces {
		st := platform.Interface(ifc.Name)
		out = append(out, &agentv1.InterfaceInfo{Name: ifc.Name, IpsAllowed: a.cfg.IPSAllowed(ifc.Name), Present: st.Present, Up: st.Up, Addresses: st.Addresses})
	}
	return out
}

// MinSuricataVersion is the oldest supported Suricata release.
const MinSuricataVersion = "8.0.5"

// versionLess compares dotted numeric versions ("8.0.10" > "8.0.5").
func versionLess(a, b string) bool {
	pa, pb := strings.Split(strings.Fields(a + " ")[0], "."), strings.Split(b, ".")
	for i := 0; i < max(len(pa), len(pb)); i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(strings.TrimFunc(pa[i], func(r rune) bool { return r < '0' || r > '9' }))
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x != y {
			return x < y
		}
	}
	return false
}

func (a *Agent) warnings() []*agentv1.Warning {
	var ws []*agentv1.Warning
	if a.engInfo.Version != "" && versionLess(a.engInfo.Version, MinSuricataVersion) {
		ws = append(ws, &agentv1.Warning{Code: "suricata_version", Message: "Suricata " + a.engInfo.Version + " is older than the supported " + MinSuricataVersion})
	}
	switch a.info.FlowOffload {
	case "hardware", "software":
		ws = append(ws, &agentv1.Warning{Code: "flow_offload", Message: a.info.FlowOffload + " flow offloading is enabled: offloaded flows bypass Suricata"})
	}
	if a.cfg.IPS.Enabled && a.fw.Name() == "none" {
		ws = append(ws, &agentv1.Warning{Code: "no_firewall", Message: "IPS is allowed but no firewall backend is available to steer traffic to NFQUEUE"})
	}
	for _, ifc := range a.interfaces() {
		if !ifc.Present {
			ws = append(ws, &agentv1.Warning{Code: "interface_missing", Message: "interface " + ifc.Name + " does not exist"})
		}
	}
	return append(ws, a.rec.Warnings()...)
}

func (a *Agent) hello() *agentv1.Hello {
	return &agentv1.Hello{
		NodeId:       a.cfg.NodeID,
		AgentVersion: version.Version,
		Platform: &agentv1.PlatformInfo{
			Profile: a.cfg.Platform.Profile, OsName: a.info.OSName, OsVersion: a.info.OSVersion, Arch: a.info.Arch,
			Hostname: a.info.Hostname, Kernel: a.info.Kernel, FirewallBackend: a.fw.Name(),
		},
		Engine:     &agentv1.EngineInfo{Version: a.engInfo.Version, Features: a.engInfo.Features, Nfq: a.engInfo.NFQ, AfPacket: a.engInfo.AFPacket},
		Interfaces: a.interfaces(),
		Applied:    a.rec.Applied(),
		Warnings:   a.warnings(),
		LogSources: a.col.Sources(),
	}
}

func (a *Agent) status(ctx context.Context) *agentv1.StatusReport {
	st := &agentv1.StatusReport{
		TimeUnixMs: time.Now().UnixMilli(),
		LogQueue:   a.col.Stats(),
		Warnings:   a.warnings(),
		Interfaces: a.interfaces(),
		LogSources: a.col.Sources(),
	}
	for _, in := range a.eng.Status(ctx) {
		st.Instances = append(st.Instances, &agentv1.InstanceStatus{
			Name: in.Name, Capture: string(in.Capture), Running: in.Running, UptimeSeconds: int64(in.Uptime / time.Second),
			RssBytes: in.RSSBytes, Interfaces: in.Interfaces, Counters: in.Counters,
			RulesLoaded: uint32(in.RulesLoaded), RulesFailed: uint32(in.RulesFailed), LastError: in.LastError,
		})
	}
	return st
}

// LogTee forwards writes to a target set later; writes before that are
// dropped.
type LogTee struct {
	mu sync.Mutex
	w  io.Writer
}

// SetTarget sets the writer.
func (t *LogTee) SetTarget(w io.Writer) {
	t.mu.Lock()
	t.w = w
	t.mu.Unlock()
}

// Write implements io.Writer.
func (t *LogTee) Write(p []byte) (int, error) {
	t.mu.Lock()
	w := t.w
	t.mu.Unlock()
	if w != nil {
		_, _ = w.Write(p)
	}
	return len(p), nil
}
