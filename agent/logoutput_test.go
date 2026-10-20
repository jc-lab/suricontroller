package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jc-lab/suricontroller/agent/collector"
	"github.com/jc-lab/suricontroller/agent/config"
	"github.com/jc-lab/suricontroller/agent/engine"
	"github.com/jc-lab/suricontroller/agent/firewall"
	agentv1 "github.com/jc-lab/suricontroller/gen/suricontroller/agent/v1"
	"github.com/jc-lab/suricontroller/pkg/sshkey"
)

type nopEngine struct{}

func (nopEngine) Info(context.Context) (engine.Info, error) {
	return engine.Info{Version: "8.0.5"}, nil
}
func (nopEngine) Validate(context.Context, engine.InstanceSpec) (*engine.ValidationResult, error) {
	return &engine.ValidationResult{OK: true}, nil
}
func (nopEngine) Ensure(context.Context, []engine.InstanceSpec) error { return nil }
func (nopEngine) ReloadRules(context.Context, string) error           { return nil }
func (nopEngine) Signal(string, os.Signal) error                      { return nil }
func (nopEngine) Status(context.Context) []engine.InstanceStatus      { return nil }
func (nopEngine) Output() <-chan engine.LogLine                       { return nil }
func (nopEngine) Stop(context.Context) error                          { return nil }

type nopFirewall struct{}

func (nopFirewall) Name() string                                       { return "none" }
func (nopFirewall) Apply(context.Context, firewall.Plan) error         { return nil }
func (nopFirewall) Check(context.Context, firewall.Plan) (bool, error) { return true, nil }
func (nopFirewall) Remove(context.Context) error                       { return nil }

type recordingOutput struct {
	got chan *collector.Collector
}

func (o *recordingOutput) ShipLogs(ctx context.Context, c *collector.Collector) error {
	c.SetPolicy(&agentv1.LogCollectionPolicy{Enabled: true, Types: []agentv1.LogType{agentv1.LogType_LOG_TYPE_AGENT}})
	o.got <- c
	<-ctx.Done()
	return nil
}

func TestLogOutputReceivesCollector(t *testing.T) {
	dir := t.TempDir()
	hk, _ := sshkey.Generate()
	cfg, err := config.Parse([]byte(fmt.Sprintf(`
node_id: router-01
key_file: %s
state_dir: %s
run_dir: %s
controller:
  url: ws://127.0.0.1:1/agent/v1/connect
  host_key: %q
platform:
  profile: systemd-native
  firewall: none
`, filepath.Join(dir, "key"), filepath.Join(dir, "state"), filepath.Join(dir, "run"), hk.Public("c").String())))
	if err != nil {
		t.Fatal(err)
	}
	out := &recordingOutput{got: make(chan *collector.Collector, 1)}
	tee := &LogTee{}
	a, err := New(context.Background(), cfg, Options{Engine: nopEngine{}, Firewall: nopFirewall{}, LogOutput: out, LogTee: tee})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	var c *collector.Collector
	select {
	case c = <-out.got:
	case <-time.After(10 * time.Second):
		t.Fatal("ShipLogs not called")
	}
	if c != a.Collector() {
		t.Fatal("ShipLogs got another collector")
	}
	fmt.Fprintln(tee, "hello from the agent")
	nctx, ncancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer ncancel()
	batches, err := c.Next(nctx, 10, 1<<20)
	if err != nil || len(batches) != 1 || batches[0].Type != agentv1.LogType_LOG_TYPE_AGENT {
		t.Fatalf("batches = %+v, err = %v", batches, err)
	}
}
