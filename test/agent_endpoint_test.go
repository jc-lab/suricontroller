package test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/jc-lab/suricontroller/agent"
	"github.com/jc-lab/suricontroller/agent/config"
	"github.com/jc-lab/suricontroller/agent/firewall"
	apiv1 "github.com/jc-lab/suricontroller/gen/suricontroller/api/v1"
	"github.com/jc-lab/suricontroller/pkg/sshkey"
	"github.com/jc-lab/suricontroller/pkg/wire"
)

// testSource is an EndpointSource the test switches.
type testSource struct {
	mu      sync.Mutex
	ep      *agent.Endpoint
	changed chan struct{}
}

func newTestSource() *testSource { return &testSource{changed: make(chan struct{})} }

func (s *testSource) set(ep agent.Endpoint) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ep = &ep
	close(s.changed)
	s.changed = make(chan struct{})
}

func (s *testSource) Endpoint(ctx context.Context) (agent.Endpoint, <-chan struct{}, error) {
	for {
		s.mu.Lock()
		ep, ch := s.ep, s.changed
		s.mu.Unlock()
		if ep != nil {
			return *ep, ch, nil
		}
		select {
		case <-ctx.Done():
			return agent.Endpoint{}, nil, ctx.Err()
		case <-ch:
		}
	}
}

func endpointOf(t *testing.T, e *controllerEnv) agent.Endpoint {
	k, err := sshkey.ParsePublicKey(e.ctl.HostPublicKey())
	if err != nil {
		t.Fatal(err)
	}
	return agent.Endpoint{URL: "ws" + strings.TrimPrefix(e.srv.URL, "http") + wire.AgentPath, HostKey: k}
}

// The agent waits for an endpoint, connects to it, and moves to another
// controller when the source changes.
func TestAgentEndpointSource(t *testing.T) {
	ctx := context.Background()
	e1, e2 := startController(t), startController(t)
	dir := t.TempDir()
	cfg, err := config.ParseWith([]byte(fmt.Sprintf(`
node_id: router-01
key_file: %[1]s/agent_ed25519
platform:
  profile: systemd-native
interfaces:
  - name: lo
state_dir: %[1]s/state
run_dir: %[1]s/run
`, dir)), config.ParseOptions{ExternalController: true})
	if err != nil {
		t.Fatal(err)
	}
	key, _, err := agent.LoadKey(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range []*controllerEnv{e1, e2} {
		if _, err := e.api.nodes.AddNode(ctx, connect.NewRequest(&apiv1.AddNodeRequest{PublicKey: key.Public(cfg.NodeID).String()})); err != nil {
			t.Fatal(err)
		}
	}
	online := func(e *controllerEnv) bool {
		n, err := e.api.nodes.GetNode(ctx, connect.NewRequest(&apiv1.GetNodeRequest{Id: "router-01"}))
		return err == nil && n.Msg.Node.Online
	}

	src := newTestSource()
	a, err := agent.New(ctx, cfg, agent.Options{Engine: &stubEngine{}, Firewall: firewall.None{}, Controller: src})
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

	// A wrong host key is refused; the corrected endpoint is used at once.
	wrong := endpointOf(t, e1)
	other, _ := sshkey.Generate()
	wrong.HostKey = other.Public("x")
	src.set(wrong)
	time.Sleep(300 * time.Millisecond)
	if online(e1) {
		t.Fatal("connected with a wrong controller host key")
	}
	src.set(endpointOf(t, e1))
	eventually(t, func() bool { return online(e1) })

	src.set(endpointOf(t, e2))
	eventually(t, func() bool { return online(e2) && !online(e1) })
}
