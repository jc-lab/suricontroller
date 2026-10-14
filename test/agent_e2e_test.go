package test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"connectrpc.com/connect"

	"github.com/jc-lab/suricontroller/agent"
	"github.com/jc-lab/suricontroller/agent/config"
	"github.com/jc-lab/suricontroller/agent/engine"
	"github.com/jc-lab/suricontroller/agent/firewall"
	agentv1 "github.com/jc-lab/suricontroller/gen/suricontroller/agent/v1"
	apiv1 "github.com/jc-lab/suricontroller/gen/suricontroller/api/v1"
	"github.com/jc-lab/suricontroller/pkg/wire"
)

// stubEngine stands in for Suricata (which needs capture privileges).
type stubEngine struct {
	mu      sync.Mutex
	running map[string]engine.InstanceSpec
	reloads int
	signals int
}

func (s *stubEngine) Info(context.Context) (engine.Info, error) {
	return engine.Info{Version: "8.0.5", NFQ: true, AFPacket: true}, nil
}
func (s *stubEngine) Validate(_ context.Context, spec engine.InstanceSpec) (*engine.ValidationResult, error) {
	b, err := os.ReadFile(spec.ConfigPath)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(string(b), "%YAML 1.1") {
		return &engine.ValidationResult{OK: false, Output: "bad header"}, nil
	}
	return &engine.ValidationResult{OK: true}, nil
}
func (s *stubEngine) Ensure(_ context.Context, specs []engine.InstanceSpec) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.running = map[string]engine.InstanceSpec{}
	for _, sp := range specs {
		s.running[sp.Name] = sp
	}
	return nil
}
func (s *stubEngine) ReloadRules(context.Context, string) error {
	s.mu.Lock()
	s.reloads++
	s.mu.Unlock()
	return nil
}
func (s *stubEngine) Signal(string, os.Signal) error {
	s.mu.Lock()
	s.signals++
	s.mu.Unlock()
	return nil
}
func (s *stubEngine) Status(context.Context) []engine.InstanceStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []engine.InstanceStatus
	for name, sp := range s.running {
		out = append(out, engine.InstanceStatus{Name: name, Capture: sp.Capture, Interfaces: sp.Interfaces, Running: true, RulesLoaded: 2})
	}
	return out
}
func (s *stubEngine) Output() <-chan engine.LogLine { return make(chan engine.LogLine) }
func (s *stubEngine) Stop(context.Context) error    { return s.Ensure(context.Background(), nil) }

func TestAgentAgainstController(t *testing.T) {
	ctx := context.Background()
	e := startController(t)
	commitFiles(t, e, apiv1.Repo_REPO_RULES, "rules", map[string]string{"local/local.rules": localRules})
	commitFiles(t, e, apiv1.Repo_REPO_CONFIG, "config", map[string]string{"common/disable.conf": "1:1000002\n"})

	dir := t.TempDir()
	logDir := filepath.Join(dir, "log", "ids")
	cfgYAML := fmt.Sprintf(`
node_id: router-01
key_file: %[1]s/agent_ed25519
controller:
  url: %[2]s
  host_key: "%[3]s"
platform:
  profile: systemd-native
interfaces:
  - name: lo
  - name: eth-missing
ips:
  enabled: true
suricata:
  base_config: %[1]s/suricata.yaml
  local_rules_dir: %[1]s/rules.local
  instances:
    ids: { log_dir: %[4]s }
    ips: { log_dir: %[1]s/log/ips }
logs:
  start_position: beginning
state_dir: %[1]s/state
run_dir: %[1]s/run
`, dir, "ws"+strings.TrimPrefix(e.srv.URL, "http")+wire.AgentPath, e.ctl.HostPublicKey(), logDir)
	os.WriteFile(filepath.Join(dir, "suricata.yaml"), []byte(`%YAML 1.1
---
outputs:
  - eve-log:
      enabled: yes
      filename: eve.json
      types: [alert, dns]
`), 0o644)
	cfg, err := config.Parse([]byte(cfgYAML))
	if err != nil {
		t.Fatal(err)
	}
	key, _, err := agent.LoadKey(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.api.nodes.AddNode(ctx, connect.NewRequest(&apiv1.AddNodeRequest{PublicKey: key.Public(cfg.NodeID).String()})); err != nil {
		t.Fatal(err)
	}

	eng := &stubEngine{}
	a, err := agent.New(ctx, cfg, agent.Options{Engine: eng, Firewall: firewall.None{}})
	if err != nil {
		t.Fatal(err)
	}
	actx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		a.Run(actx)
	}()
	defer func() { cancel(); <-done }()

	getNode := func() *apiv1.Node {
		n, err := e.api.nodes.GetNode(ctx, connect.NewRequest(&apiv1.GetNodeRequest{Id: "router-01"}))
		if err != nil {
			t.Fatal(err)
		}
		return n.Msg.Node
	}
	// Connected and in sync with no instance running (all interfaces off).
	eventually(t, func() bool { n := getNode(); return n.Online && n.Deploy.InSync })
	n := getNode()
	if len(n.Interfaces) != 2 || n.Engine.GetVersion() != "8.0.5" || n.Platform.GetProfile() != "systemd-native" {
		t.Fatalf("node facts = %+v", n)
	}
	missing := false
	for _, w := range n.Warnings {
		missing = missing || w.Code == "interface_missing"
	}
	if !missing {
		t.Fatalf("expected interface_missing warning, got %v", n.Warnings)
	}

	// Enable IDS on lo: the agent renders, validates and starts the instance.
	if _, err := e.api.nodes.SetInterfaceModes(ctx, connect.NewRequest(&apiv1.SetInterfaceModesRequest{Id: "router-01",
		Modes: map[string]agentv1.InterfaceMode{"lo": agentv1.InterfaceMode_INTERFACE_MODE_IDS}})); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool {
		n := getNode()
		return n.Deploy.InSync && n.Deploy.LastStatus == agentv1.ApplyStatus_APPLY_STATUS_SUCCEEDED && n.Interfaces[0].AppliedMode == agentv1.InterfaceMode_INTERFACE_MODE_IDS
	})
	eng.mu.Lock()
	spec := eng.running["ids"]
	eng.mu.Unlock()
	effective, _ := os.ReadFile(spec.ConfigPath)
	if !strings.Contains(string(effective), "interface: lo") || !strings.Contains(string(effective), "default-log-dir: "+logDir) {
		t.Fatalf("effective config:\n%s", effective)
	}
	rules, _ := os.ReadFile(filepath.Join(dir, "state", "active", "rules", "suricata.rules"))
	if !strings.Contains(string(rules), "sid:1000001") || !strings.Contains(string(rules), "# alert tcp any any -> any 443") {
		t.Fatalf("active rules:\n%s", rules)
	}

	// Logs written by "Suricata" are collected according to the policy
	// (default: alert, anomaly, drop) and stored by the controller.
	os.MkdirAll(logDir, 0o755)
	os.WriteFile(filepath.Join(logDir, "eve.json"), []byte(`{"event_type":"alert","signature_id":1000001}`+"\n"+`{"event_type":"dns"}`+"\n"), 0o644)
	eventually(t, func() bool {
		s, err := e.api.logs.TailLog(ctx, connect.NewRequest(&apiv1.TailLogRequest{NodeId: "router-01", Type: agentv1.LogType_LOG_TYPE_EVE, Lines: 10}))
		if err != nil {
			return false
		}
		defer s.Close()
		return s.Receive() && len(s.Msg().Lines) == 1 && strings.Contains(s.Msg().Lines[0], "1000001")
	})
	eventually(t, func() bool {
		n := getNode()
		return len(n.LogSources) > 0 && n.LogSources[0].Path == filepath.Join(logDir, "eve.json")
	})

	// A new rules commit is applied with a rule reload (no restart).
	commitFiles(t, e, apiv1.Repo_REPO_RULES, "more", map[string]string{"local/more.rules": `alert ip any any -> any any (msg:"m"; sid:1000009; rev:1;)` + "\n"})
	eventually(t, func() bool {
		eng.mu.Lock()
		defer eng.mu.Unlock()
		return eng.reloads == 1
	})
	eventually(t, func() bool {
		n := getNode()
		return n.Deploy.InSync && n.Deploy.AppliedBundle.GetBundleId() == n.Deploy.DesiredBundle.GetBundleId()
	})

	// The agent reports its status periodically.
	eventually(t, func() bool { return len(getNode().Instances) == 1 })
}
