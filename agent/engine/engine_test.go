package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jc-lab/suricontroller/pkg/yamlmerge"
)

// TestMain lets the test binary act as a fake suricata for supervisor tests.
func TestMain(m *testing.M) {
	if os.Getenv("FAKE_SURICATA") == "1" {
		fakeSuricata()
		return
	}
	os.Exit(m.Run())
}

func fakeSuricata() {
	var cfgPath string
	for i, a := range os.Args {
		if a == "-c" && i+1 < len(os.Args) {
			cfgPath = os.Args[i+1]
		}
	}
	b, err := os.ReadFile(cfgPath)
	if err != nil {
		os.Exit(3)
	}
	root, _ := yamlmerge.Parse(b)
	sock := yamlmerge.GetString(root, "unix-command", "filename")
	fmt.Println("i: suricata: fake engine starting")
	if os.Getenv("FAKE_CRASH") == "1" {
		fmt.Println("E: suricata: fake crash")
		os.Exit(1)
	}
	l, err := net.Listen("unix", sock)
	if err != nil {
		os.Exit(4)
	}
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM)
	go func() {
		<-sigs
		l.Close()
		os.Exit(0)
	}()
	start := time.Now()
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			dec, enc := json.NewDecoder(c), json.NewEncoder(c)
			var hello map[string]any
			if dec.Decode(&hello) != nil {
				return
			}
			enc.Encode(map[string]string{"return": "OK"})
			var req map[string]any
			if dec.Decode(&req) != nil {
				return
			}
			switch req["command"] {
			case "uptime":
				enc.Encode(map[string]any{"return": "OK", "message": int(time.Since(start).Seconds())})
			case "reload-rules":
				enc.Encode(map[string]any{"return": "OK", "message": "done"})
			case "ruleset-stats":
				enc.Encode(map[string]any{"return": "OK", "message": []map[string]int{{"id": 0, "rules_loaded": 5}}})
			case "dump-counters":
				enc.Encode(map[string]any{"return": "OK", "message": map[string]any{"capture": map[string]any{"kernel_packets": 10}}})
			default:
				enc.Encode(map[string]any{"return": "NOK", "message": "unknown"})
			}
		}(c)
	}
}

const testBase = `%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16]"
    EXTERNAL_NET: "!$HOME_NET"
  port-groups:
    HTTP_PORTS: "80"
default-log-dir: /var/log/suricata/
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert
af-packet:
  - interface: eth0
    threads: 2
  - interface: default
    cluster-type: cluster_flow
    copy-mode: ips
logging:
  outputs:
    - console:
        enabled: yes
`

func renderInput(t *testing.T, rulesDir string, managed string) RenderInput {
	t.Helper()
	base, err := yamlmerge.Parse([]byte(testBase))
	if err != nil {
		t.Fatal(err)
	}
	in := RenderInput{
		Instance: "ids", Capture: CaptureAFPacket, Interfaces: []string{"eth0", "br-lan"},
		BaseConfig: "/etc/suricata/suricata.yaml", Base: base, RulesDir: rulesDir,
		LogDir: t.TempDir(), SocketPath: filepath.Join(t.TempDir(), "s.sock"), PidFile: filepath.Join(t.TempDir(), "p.pid"),
	}
	if managed != "" {
		in.Managed, err = yamlmerge.Parse([]byte(managed))
		if err != nil {
			t.Fatal(err)
		}
	}
	return in
}

func TestRenderLayers(t *testing.T) {
	rulesDir := t.TempDir()
	os.WriteFile(filepath.Join(rulesDir, "suricata.rules"), []byte(""), 0o644)
	os.WriteFile(filepath.Join(rulesDir, "classification.config"), []byte(""), 0o644)
	in := renderInput(t, rulesDir, "vars:\n  address-groups:\n    HOME_NET: '[10.0.0.0/8]'\n")
	r, err := Render(in)
	if err != nil {
		t.Fatal(err)
	}
	eff, _ := yamlmerge.Parse(r.YAML)
	if yamlmerge.GetString(eff, "vars", "address-groups", "HOME_NET") != "[10.0.0.0/8]" {
		t.Fatal("managed overlay not applied")
	}
	if yamlmerge.GetString(eff, "default-log-dir") != in.LogDir {
		t.Fatal("log dir not forced")
	}
	if yamlmerge.GetString(eff, "classification-file") != filepath.Join(rulesDir, "classification.config") {
		t.Fatal("classification file")
	}
	if yamlmerge.GetString(eff, "reference-config-file") != "" {
		t.Fatal("reference file set although missing")
	}
	if yamlmerge.GetString(eff, "security", "lua", "allow-rules") != "no" {
		t.Fatal("lua not disabled")
	}
	af := yamlmerge.Get(eff, "af-packet")
	if len(af.Content) != 3 {
		t.Fatalf("af-packet entries = %d", len(af.Content))
	}
	e0, e1 := af.Content[0], af.Content[1]
	if yamlmerge.GetString(e0, "interface") != "eth0" || yamlmerge.GetString(e0, "threads") != "2" || yamlmerge.GetString(e0, "cluster-id") != "99" {
		t.Fatal("eth0 entry should reuse user tuning")
	}
	if yamlmerge.GetString(e1, "interface") != "br-lan" || yamlmerge.GetString(e1, "cluster-type") != "cluster_flow" ||
		yamlmerge.GetString(e1, "cluster-id") != "98" || yamlmerge.Get(e1, "copy-mode") != nil {
		t.Fatal("br-lan entry should be derived from default without copy-mode")
	}
	if len(r.Shadowed) != 1 || r.Shadowed[0] != "vars.address-groups.HOME_NET" {
		t.Fatalf("shadowed = %v", r.Shadowed)
	}

	// Forbidden overlay keys are rejected by the agent too.
	bad := renderInput(t, rulesDir, "outputs: []\n")
	if _, err := Render(bad); err == nil {
		t.Fatal("forbidden overlay accepted")
	}
}

func TestRenderNFQ(t *testing.T) {
	in := renderInput(t, "", "")
	in.Capture, in.Interfaces, in.FailOpen, in.AllowLua = CaptureNFQ, nil, true, true
	r, err := Render(in)
	if err != nil {
		t.Fatal(err)
	}
	eff, _ := yamlmerge.Parse(r.YAML)
	if yamlmerge.GetString(eff, "nfq", "fail-open") != "yes" || yamlmerge.GetString(eff, "nfq", "mode") != "accept" {
		t.Fatal("nfq settings")
	}
	if yamlmerge.Get(eff, "security") != nil {
		t.Fatal("allow_lua should leave security to the user")
	}
}

func TestValidateWithSuricata(t *testing.T) {
	bin, err := exec.LookPath("suricata")
	if err != nil {
		t.Skip("suricata not installed")
	}
	sys, err := os.ReadFile("/etc/suricata/suricata.yaml")
	if err != nil {
		t.Skip("no system suricata.yaml")
	}
	base, err := yamlmerge.Parse(sys)
	if err != nil {
		t.Fatal(err)
	}
	rulesDir := t.TempDir()
	os.WriteFile(filepath.Join(rulesDir, "suricata.rules"), []byte(
		"alert tcp any any -> any 80 (msg:\"ok\"; sid:1; rev:1;)\n# alert tcp any any -> any 81 (msg:\"disabled\"; sid:2; rev:1;)\n"), 0o644)
	in := RenderInput{
		Instance: "ids", Capture: CaptureAFPacket, Interfaces: []string{"lo"}, BaseConfig: "/etc/suricata/suricata.yaml",
		Base: base, RulesDir: rulesDir, LogDir: t.TempDir(), SocketPath: filepath.Join(t.TempDir(), "s.sock"),
		PidFile: filepath.Join(t.TempDir(), "p.pid"),
	}
	in.Managed, _ = yamlmerge.Parse([]byte("vars:\n  address-groups:\n    HOME_NET: '[10.0.0.0/8]'\n"))
	r, err := Render(in)
	if err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(t.TempDir(), "suricata.yaml")
	os.WriteFile(cfg, r.YAML, 0o644)
	sup := &Supervisor{Binary: bin}
	res, err := sup.Validate(context.Background(), InstanceSpec{ConfigPath: cfg, LogDir: in.LogDir})
	if err != nil || !res.OK {
		t.Fatalf("validate: %v\n%s", err, res.Output)
	}

	os.WriteFile(filepath.Join(rulesDir, "suricata.rules"), []byte(
		"alert tcp any any -> any 80 (msg:\"ok\"; sid:1; rev:1;)\nalert tcp any any -> any 80 (msg:\"bad\"; nosuchkeyword:1; sid:2; rev:1;)\n"), 0o644)
	res, err = sup.Validate(context.Background(), InstanceSpec{ConfigPath: cfg, LogDir: in.LogDir})
	if err != nil {
		t.Fatal(err)
	}
	if res.OK || len(res.RuleErrors) != 1 || res.RuleErrors[0].SID != 2 || res.RuleErrors[0].Line != 2 || !strings.Contains(res.RuleErrors[0].Message, "nosuchkeyword") {
		t.Fatalf("expected rule error, got %+v\n%s", res.RuleErrors, res.Output)
	}

	info, err := sup.Info(context.Background())
	if err != nil || info.Version == "" || !info.AFPacket {
		t.Fatalf("info = %+v %v", info, err)
	}
}

func fakeSpec(t *testing.T, name, hash string) InstanceSpec {
	dir := t.TempDir()
	in := renderInput(t, "", "")
	in.SocketPath = filepath.Join(dir, "s.sock")
	r, err := Render(in)
	if err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "suricata.yaml")
	os.WriteFile(cfg, r.YAML, 0o644)
	return InstanceSpec{Name: name, Capture: CaptureAFPacket, ConfigPath: cfg, ConfigHash: hash, SocketPath: in.SocketPath, PidFile: filepath.Join(dir, "pid"), LogDir: in.LogDir}
}

func TestSupervisorLifecycle(t *testing.T) {
	self, _ := os.Executable()
	t.Setenv("FAKE_SURICATA", "1")
	sup := &Supervisor{Binary: self, StartTimeout: 10 * time.Second}
	ctx := context.Background()
	spec := fakeSpec(t, "ids", "h1")
	if err := sup.Ensure(ctx, []InstanceSpec{spec}); err != nil {
		t.Fatal(err)
	}
	p1, _ := sup.get("ids")
	if err := sup.ReloadRules(ctx, "ids"); err != nil {
		t.Fatal(err)
	}
	st := sup.Status(ctx)
	if len(st) != 1 || !st[0].Running || st[0].RulesLoaded != 5 || st[0].Counters["capture.kernel_packets"] != 10 {
		t.Fatalf("status = %+v", st)
	}
	// Same hash: no restart.
	if err := sup.Ensure(ctx, []InstanceSpec{spec}); err != nil {
		t.Fatal(err)
	}
	if p, _ := sup.get("ids"); p != p1 {
		t.Fatal("unchanged spec restarted the instance")
	}
	// New hash: restart.
	spec.ConfigHash = "h2"
	if err := sup.Ensure(ctx, []InstanceSpec{spec}); err != nil {
		t.Fatal(err)
	}
	if p, _ := sup.get("ids"); p == p1 {
		t.Fatal("changed spec did not restart")
	}
	select {
	case <-p1.done:
	default:
		t.Fatal("old process still running")
	}
	// Crash is restarted by the watchdog.
	p2, _ := sup.get("ids")
	p2.cmd.Process.Kill()
	deadline := time.Now().Add(10 * time.Second)
	for {
		p3, err := sup.get("ids")
		if err == nil && p3 != p2 && sup.waitReady(ctx, p3) == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("crashed instance not restarted")
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err := sup.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if len(sup.Status(ctx)) != 0 {
		t.Fatal("instances left after Stop")
	}
}

func TestSupervisorStartFailure(t *testing.T) {
	self, _ := os.Executable()
	t.Setenv("FAKE_SURICATA", "1")
	t.Setenv("FAKE_CRASH", "1")
	sup := &Supervisor{Binary: self, StartTimeout: 10 * time.Second}
	err := sup.Ensure(context.Background(), []InstanceSpec{fakeSpec(t, "ips", "h")})
	if err == nil || !strings.Contains(err.Error(), "fake crash") {
		t.Fatalf("err = %v", err)
	}
	sup.Stop(context.Background())
}

func TestSupervisorRetriesFailedSpawnAndEnsureRevives(t *testing.T) {
	self, _ := os.Executable()
	t.Setenv("FAKE_SURICATA", "1")
	dir := t.TempDir()
	bin := filepath.Join(dir, "suricata")
	if err := os.Symlink(self, bin); err != nil {
		t.Fatal(err)
	}
	sup := &Supervisor{Binary: bin, StartTimeout: 10 * time.Second}
	ctx := context.Background()
	spec := fakeSpec(t, "ids", "h")
	if err := sup.Ensure(ctx, []InstanceSpec{spec}); err != nil {
		t.Fatal(err)
	}
	// Make spawning fail, then kill the instance: the watchdog keeps
	// retrying instead of giving up after one failed start.
	os.Remove(bin)
	p, _ := sup.get("ids")
	p.cmd.Process.Kill()
	time.Sleep(2500 * time.Millisecond)
	os.Symlink(self, bin)
	deadline := time.Now().Add(15 * time.Second)
	for {
		np, err := sup.get("ids")
		if err == nil && np != p && !np.exited() && sup.waitReady(ctx, np) == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("instance not restarted after spawn failures")
		}
		time.Sleep(200 * time.Millisecond)
	}
	// Ensure with the same spec revives a dead instance immediately.
	np, _ := sup.get("ids")
	np.cmd.Process.Kill()
	<-np.done
	if err := sup.Ensure(ctx, []InstanceSpec{spec}); err != nil {
		t.Fatal(err)
	}
	if cur, _ := sup.get("ids"); cur == np || cur.exited() {
		t.Fatal("Ensure did not revive the dead instance")
	}
	sup.Stop(ctx)
}

func TestRenderRejectsDottedOverlayAndKeepsRuntimeLast(t *testing.T) {
	for _, m := range []string{"plugins.0: /tmp/evil.so\n", "security:\n  lua.allow-rules: yes\n", "unix-command.filename: /tmp/x\n"} {
		if _, err := Render(renderInput(t, "", m)); err == nil {
			t.Errorf("overlay %q accepted", m)
		}
	}
	// Even a dotted key in the (trusted) user file cannot override the
	// runtime layer, because runtime keys are written last.
	in := renderInput(t, "", "")
	in.Base, _ = yamlmerge.Parse([]byte("unix-command.filename: /tmp/other.sock\ndefault_log_dir: /tmp/x\nvars: {}\n"))
	r, err := Render(in)
	if err != nil {
		t.Fatal(err)
	}
	eff, _ := yamlmerge.Parse(r.YAML)
	keys := yamlmerge.TopKeys(eff)
	idx := func(k string) int {
		for i, v := range keys {
			if v == k {
				return i
			}
		}
		return -1
	}
	if idx("unix-command") < idx("unix-command.filename") || idx("default-log-dir") < idx("default_log_dir") {
		t.Fatalf("runtime keys must come last: %v", keys)
	}
}
