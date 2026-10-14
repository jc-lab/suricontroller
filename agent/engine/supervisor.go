package engine

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jc-lab/suricontroller/agent/engine/unixsock"
)

// counterNames are reported in instance status.
var counterNames = []string{
	"capture.kernel_packets", "capture.kernel_drops", "decoder.pkts", "decoder.bytes",
	"detect.alert", "ips.accepted", "ips.blocked", "ips.rejected", "ips.replaced",
}

// Supervisor runs Suricata instances as child processes and restarts them
// when they exit unexpectedly.
type Supervisor struct {
	Binary    string
	ExtraArgs []string
	Logger    *slog.Logger
	// StartTimeout bounds the wait for an instance to become ready
	// (rule loading can take minutes on small devices).
	StartTimeout time.Duration
	// ValidateTimeout bounds `suricata -T`.
	ValidateTimeout time.Duration

	once  sync.Once
	mu    sync.Mutex
	procs map[string]*proc
	out   chan LogLine
}

type proc struct {
	spec     InstanceSpec
	cmd      *exec.Cmd
	started  time.Time
	done     chan struct{}
	exitErr  error
	stopping bool
	ctl      *unixsock.Client
	tail     *lineRing
	restarts int
	lastErr  string
}

func (s *Supervisor) init() {
	s.once.Do(func() {
		if s.Logger == nil {
			s.Logger = slog.Default()
		}
		if s.Binary == "" {
			s.Binary = "suricata"
		}
		if s.StartTimeout <= 0 {
			s.StartTimeout = 5 * time.Minute
		}
		if s.ValidateTimeout <= 0 {
			s.ValidateTimeout = 5 * time.Minute
		}
		s.procs = map[string]*proc{}
		s.out = make(chan LogLine, 1024)
	})
}

var _ Runtime = (*Supervisor)(nil)

// Info implements Runtime.
func (s *Supervisor) Info(ctx context.Context) (Info, error) {
	s.init()
	out, err := exec.CommandContext(ctx, s.Binary, "--build-info").CombinedOutput()
	if err != nil {
		return Info{}, fmt.Errorf("suricata --build-info: %w: %s", err, bytes.TrimSpace(out))
	}
	return ParseBuildInfo(out), nil
}

// Validate implements Runtime by running `suricata -T`.
func (s *Supervisor) Validate(ctx context.Context, spec InstanceSpec) (*ValidationResult, error) {
	s.init()
	if spec.LogDir != "" {
		if err := os.MkdirAll(spec.LogDir, 0o755); err != nil {
			return nil, err
		}
	}
	ctx, cancel := context.WithTimeout(ctx, s.ValidateTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.Binary, "-T", "-c", spec.ConfigPath)
	out, err := cmd.CombinedOutput()
	res := &ValidationResult{OK: err == nil, Output: string(out), RuleErrors: ParseRuleErrors(string(out))}
	if ctx.Err() != nil {
		return res, fmt.Errorf("suricata -T: %w", ctx.Err())
	}
	var ee *exec.ExitError
	if err != nil && !errors.As(err, &ee) {
		return res, err
	}
	return res, nil
}

func (s *Supervisor) args(spec InstanceSpec) []string {
	args := []string{"-c", spec.ConfigPath, "--pidfile", spec.PidFile}
	switch spec.Capture {
	case CaptureAFPacket:
		args = append(args, "--af-packet")
	case CaptureNFQ:
		for _, q := range spec.Queues {
			args = append(args, "-q", strconv.Itoa(int(q)))
		}
	}
	return append(args, s.ExtraArgs...)
}

// start spawns an instance without waiting for readiness. Callers hold mu.
func (s *Supervisor) start(spec InstanceSpec, restarts int) (*proc, error) {
	for _, d := range []string{filepath.Dir(spec.SocketPath), filepath.Dir(spec.PidFile), spec.LogDir} {
		if d != "" {
			if err := os.MkdirAll(d, 0o755); err != nil {
				return nil, err
			}
		}
	}
	_ = os.Remove(spec.SocketPath)
	_ = os.Remove(spec.PidFile)
	cmd := exec.Command(s.Binary, s.args(spec)...)
	cmd.SysProcAttr = sysProcAttr()
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = cmd.Stdout
	p := &proc{spec: spec, cmd: cmd, done: make(chan struct{}), ctl: &unixsock.Client{Path: spec.SocketPath}, tail: newLineRing(40), restarts: restarts}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	p.started = time.Now()
	s.procs[spec.Name] = p
	go s.pump(p, stdout)
	go func() {
		p.exitErr = cmd.Wait()
		close(p.done)
		s.onExit(p)
	}()
	s.Logger.Info("suricata started", "instance", spec.Name, "pid", cmd.Process.Pid, "capture", spec.Capture)
	return p, nil
}

func (s *Supervisor) pump(p *proc, r io.Reader) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		p.tail.add(line)
		select {
		case s.out <- LogLine{Instance: p.spec.Name, Line: line}:
		default:
		}
	}
}

func restartDelay(attempt int) time.Duration {
	return min(time.Duration(1<<min(attempt, 6))*time.Second, time.Minute)
}

// onExit restarts an instance that exited without being stopped.
func (s *Supervisor) onExit(p *proc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p.stopping || s.procs[p.spec.Name] != p {
		return
	}
	p.lastErr = fmt.Sprintf("exited: %v: %s", p.exitErr, p.tail.last())
	delay := restartDelay(p.restarts)
	s.Logger.Error("suricata exited unexpectedly, restarting", "instance", p.spec.Name, "err", p.exitErr, "delay", delay, "output", p.tail.last())
	s.scheduleRestart(p, p.restarts+1, delay)
}

// scheduleRestart restarts p after delay, retrying with backoff while
// spawning fails (e.g. ENOMEM on a small router). Callers hold mu.
func (s *Supervisor) scheduleRestart(p *proc, attempt int, delay time.Duration) {
	time.AfterFunc(delay, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.procs[p.spec.Name] != p || p.stopping {
			return
		}
		np, err := s.start(p.spec, attempt)
		if err != nil {
			p.lastErr = err.Error()
			s.Logger.Error("restart suricata", "instance", p.spec.Name, "err", err)
			s.scheduleRestart(p, attempt+1, restartDelay(attempt))
			return
		}
		np.lastErr = p.lastErr
	})
}

func (p *proc) exited() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

func (s *Supervisor) waitReady(ctx context.Context, p *proc) error {
	ctx, cancel := context.WithTimeout(ctx, s.StartTimeout)
	defer cancel()
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-p.done:
			return fmt.Errorf("suricata %s exited during startup: %v: %s", p.spec.Name, p.exitErr, p.tail.last())
		case <-ctx.Done():
			return fmt.Errorf("suricata %s did not become ready: %w", p.spec.Name, ctx.Err())
		case <-t.C:
		}
		cctx, ccancel := context.WithTimeout(ctx, 2*time.Second)
		_, err := p.ctl.Uptime(cctx)
		ccancel()
		if err == nil {
			return nil
		}
	}
}

// stop terminates an instance. Callers must not hold mu.
func (s *Supervisor) stop(p *proc) {
	s.mu.Lock()
	p.stopping = true
	s.mu.Unlock()
	select {
	case <-p.done:
		return
	default:
	}
	_ = signalGroup(p.cmd.Process.Pid, syscall.SIGTERM)
	select {
	case <-p.done:
	case <-time.After(30 * time.Second):
		_ = signalGroup(p.cmd.Process.Pid, syscall.SIGKILL)
		<-p.done
	}
	s.Logger.Info("suricata stopped", "instance", p.spec.Name)
}

func sameSpec(a, b InstanceSpec) bool {
	return a.ConfigHash == b.ConfigHash && a.Capture == b.Capture && a.ConfigPath == b.ConfigPath &&
		slices.Equal(a.Queues, b.Queues) && slices.Equal(a.Interfaces, b.Interfaces)
}

// Ensure implements Runtime.
func (s *Supervisor) Ensure(ctx context.Context, specs []InstanceSpec) error {
	s.init()
	want := map[string]InstanceSpec{}
	for _, sp := range specs {
		want[sp.Name] = sp
	}
	s.mu.Lock()
	var toStop []*proc
	for name, p := range s.procs {
		// Dead instances (waiting for a restart) are started again now.
		if sp, ok := want[name]; !ok || !sameSpec(sp, p.spec) || p.exited() {
			toStop = append(toStop, p)
			delete(s.procs, name)
		}
	}
	s.mu.Unlock()
	for _, p := range toStop {
		s.stop(p)
	}
	var started []*proc
	s.mu.Lock()
	for name, sp := range want {
		if _, ok := s.procs[name]; ok {
			continue
		}
		p, err := s.start(sp, 0)
		if err != nil {
			s.mu.Unlock()
			return fmt.Errorf("start suricata %s: %w", name, err)
		}
		started = append(started, p)
	}
	s.mu.Unlock()
	var errs []error
	for _, p := range started {
		if err := s.waitReady(ctx, p); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (s *Supervisor) get(name string) (*proc, error) {
	s.init()
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.procs[name]
	if !ok {
		return nil, fmt.Errorf("suricata instance %s is not running", name)
	}
	return p, nil
}

// ReloadRules implements Runtime.
func (s *Supervisor) ReloadRules(ctx context.Context, instance string) error {
	p, err := s.get(instance)
	if err != nil {
		return err
	}
	return p.ctl.ReloadRules(ctx)
}

// Signal implements Runtime.
func (s *Supervisor) Signal(instance string, sig os.Signal) error {
	p, err := s.get(instance)
	if err != nil {
		return err
	}
	return p.cmd.Process.Signal(sig)
}

// Status implements Runtime.
func (s *Supervisor) Status(ctx context.Context) []InstanceStatus {
	s.init()
	s.mu.Lock()
	procs := make([]*proc, 0, len(s.procs))
	for _, p := range s.procs {
		procs = append(procs, p)
	}
	s.mu.Unlock()
	slices.SortFunc(procs, func(a, b *proc) int { return strings.Compare(a.spec.Name, b.spec.Name) })
	var out []InstanceStatus
	for _, p := range procs {
		s.mu.Lock()
		lastErr := p.lastErr
		s.mu.Unlock()
		st := InstanceStatus{Name: p.spec.Name, Capture: p.spec.Capture, Interfaces: p.spec.Interfaces, LastError: lastErr}
		select {
		case <-p.done:
		default:
			st.Running = true
			st.RSSBytes = rss(p.cmd.Process.Pid)
		}
		if st.Running {
			cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
			if up, err := p.ctl.Uptime(cctx); err == nil {
				st.Uptime = time.Duration(up) * time.Second
				st.Counters, _ = p.ctl.Counters(cctx, counterNames)
				if rs, err := p.ctl.RulesetStats(cctx); err == nil {
					for _, r := range rs {
						st.RulesLoaded += r.RulesLoaded
						st.RulesFailed += r.RulesFailed
					}
				}
			}
			cancel()
		}
		out = append(out, st)
	}
	return out
}

// Output implements Runtime.
func (s *Supervisor) Output() <-chan LogLine {
	s.init()
	return s.out
}

// Stop implements Runtime.
func (s *Supervisor) Stop(ctx context.Context) error {
	return s.Ensure(ctx, nil)
}

// rss returns the resident set size of a process from /proc.
func rss(pid int) uint64 {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "VmRSS:"); ok {
			f := strings.Fields(v)
			if len(f) >= 1 {
				kb, _ := strconv.ParseUint(f[0], 10, 64)
				return kb * 1024
			}
		}
	}
	return 0
}

// lineRing keeps the last lines of process output.
type lineRing struct {
	mu    sync.Mutex
	lines []string
	max   int
}

func newLineRing(max int) *lineRing { return &lineRing{max: max} }

func (r *lineRing) add(l string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lines = append(r.lines, l)
	if len(r.lines) > r.max {
		r.lines = r.lines[len(r.lines)-r.max:]
	}
}

// last returns the most recent lines, preferring error lines.
func (r *lineRing) last() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var errs []string
	for _, l := range r.lines {
		if strings.HasPrefix(l, "E:") || strings.Contains(l, "<Error>") || strings.HasPrefix(l, "Error:") {
			errs = append(errs, l)
		}
	}
	if len(errs) > 0 {
		return strings.Join(errs, "\n")
	}
	n := min(len(r.lines), 5)
	return strings.Join(r.lines[len(r.lines)-n:], "\n")
}
