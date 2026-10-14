package test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/klauspost/compress/zstd"

	"github.com/jc-lab/suricontroller/agent/conn"
	"github.com/jc-lab/suricontroller/controller"
	"github.com/jc-lab/suricontroller/controller/auth"
	"github.com/jc-lab/suricontroller/controller/rules"
	agentv1 "github.com/jc-lab/suricontroller/gen/suricontroller/agent/v1"
	apiv1 "github.com/jc-lab/suricontroller/gen/suricontroller/api/v1"
	"github.com/jc-lab/suricontroller/gen/suricontroller/api/v1/apiv1connect"
	"github.com/jc-lab/suricontroller/pkg/bundle"
	"github.com/jc-lab/suricontroller/pkg/sshkey"
	"github.com/jc-lab/suricontroller/pkg/wire"
)

type apiClients struct {
	auth   apiv1connect.AuthServiceClient
	nodes  apiv1connect.NodeServiceClient
	repo   apiv1connect.RepoServiceClient
	deploy apiv1connect.DeployServiceClient
	logs   apiv1connect.LogServiceClient
	system apiv1connect.SystemServiceClient
}

type controllerEnv struct {
	ctl    *controller.Controller
	srv    *httptest.Server
	api    apiClients
	cancel context.CancelFunc
}

func startController(t *testing.T) *controllerEnv {
	t.Helper()
	admin, _ := auth.NewStaticAdmin("admin", "pw")
	sessions, _ := auth.NewCookieSession(auth.CookieSessionConfig{Login: admin, Secret: bytes.Repeat([]byte("s"), 32), Insecure: true})
	ctl, err := controller.New(controller.Options{
		DataDir: t.TempDir(),
		Auth:    sessions,
		// No network access in tests: only the local provider.
		RuleProviderTypes: []rules.TypeInfo{{Name: rules.TypeLocal}},
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle(wire.AgentPath, ctl.AgentHandler())
	mux.Handle("/api/", http.StripPrefix("/api", ctl.APIHandler()))
	srv := httptest.NewServer(mux)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		ctl.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
		srv.Close()
		ctl.Close()
	})

	jar, _ := cookiejar.New(nil)
	hc := &http.Client{Jar: jar}
	base := srv.URL + "/api"
	e := &controllerEnv{ctl: ctl, srv: srv, cancel: cancel, api: apiClients{
		auth:   apiv1connect.NewAuthServiceClient(hc, base),
		nodes:  apiv1connect.NewNodeServiceClient(hc, base),
		repo:   apiv1connect.NewRepoServiceClient(hc, base),
		deploy: apiv1connect.NewDeployServiceClient(hc, base),
		logs:   apiv1connect.NewLogServiceClient(hc, base),
		system: apiv1connect.NewSystemServiceClient(hc, base),
	}}
	if _, err := e.api.auth.Login(context.Background(), connect.NewRequest(&apiv1.LoginRequest{Username: "admin", Password: "pw"})); err != nil {
		t.Fatal(err)
	}
	return e
}

func commitFiles(t *testing.T, e *controllerEnv, repo apiv1.Repo, msg string, files map[string]string) string {
	t.Helper()
	req := &apiv1.WriteFilesRequest{Repo: repo, Message: msg}
	for p, c := range files {
		req.Changes = append(req.Changes, &apiv1.FileChange{Path: p, Content: []byte(c)})
	}
	resp, err := e.api.repo.WriteFiles(context.Background(), connect.NewRequest(req))
	if err != nil {
		t.Fatalf("commit %q: %v", msg, err)
	}
	return resp.Msg.Commit.Id
}

type fakeAgent struct {
	sess    *conn.Session
	desired chan *agentv1.DesiredState
}

func connectAgent(t *testing.T, e *controllerEnv, key *sshkey.PrivateKey, nodeID string) *fakeAgent {
	t.Helper()
	info, err := e.api.system.GetInfo(context.Background(), connect.NewRequest(&apiv1.GetInfoRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	hostKey, err := sshkey.ParsePublicKey(info.Msg.HostKey)
	if err != nil {
		t.Fatal(err)
	}
	a := &fakeAgent{desired: make(chan *agentv1.DesiredState, 16)}
	a.sess, err = conn.Dial(context.Background(), conn.Config{
		URL: "ws" + strings.TrimPrefix(e.srv.URL, "http") + wire.AgentPath, Key: key, ServerKey: hostKey, NodeID: nodeID,
	}, &agentv1.Hello{
		NodeId: nodeID, AgentVersion: "test",
		Interfaces: []*agentv1.InterfaceInfo{
			{Name: "eth0", IpsAllowed: true, Present: true, Up: true},
			{Name: "eth1", IpsAllowed: false, Present: true, Up: true},
		},
		LogSources: []*agentv1.LogSource{{Type: agentv1.LogType_LOG_TYPE_EVE, Instance: "ids", Path: "/var/log/suricata/ids/eve.json", EveTypes: []string{"alert"}}},
	}, func(ctx context.Context, env *agentv1.Envelope) (*agentv1.Envelope, error) {
		if d := env.GetDesiredState(); d != nil {
			a.desired <- d
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	go a.sess.Run(context.Background())
	t.Cleanup(a.sess.Close)
	return a
}

func (a *fakeAgent) next(t *testing.T) *agentv1.DesiredState {
	t.Helper()
	return waitFor(t, a.desired)
}

func (a *fakeAgent) fetch(t *testing.T, ref *agentv1.BundleRef, hostKey *sshkey.PublicKey) *bundle.Bundle {
	t.Helper()
	rc, _, err := a.sess.FetchBlob(context.Background(), ref.BundleId, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	b, err := bundle.Read(bytes.NewReader(data), ref.BundleId, hostKey.Key, bundle.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

const localRules = `alert tcp any any -> any 80 (msg:"rule one"; sid:1000001; rev:1;)
alert tcp any any -> any 443 (msg:"rule two"; sid:1000002; rev:1;)
`

func TestControllerEndToEnd(t *testing.T) {
	ctx := context.Background()
	e := startController(t)
	hostKey, _ := sshkey.ParsePublicKey(e.ctl.HostPublicKey())

	rulesC1 := commitFiles(t, e, apiv1.Repo_REPO_RULES, "add local rules", map[string]string{"local/local.rules": localRules})
	commitFiles(t, e, apiv1.Repo_REPO_CONFIG, "base config", map[string]string{
		"common/suricata.yaml": "vars:\n  address-groups:\n    HOME_NET: \"[10.0.0.0/8]\"\n",
		"common/disable.conf":  "1:1000002\n",
	})
	// Invalid edits are rejected.
	if _, err := e.api.repo.WriteFiles(ctx, connect.NewRequest(&apiv1.WriteFilesRequest{Repo: apiv1.Repo_REPO_CONFIG, Message: "bad",
		Changes: []*apiv1.FileChange{{Path: "common/suricata.yaml", Content: []byte("outputs: []\n")}}})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("forbidden overlay key: %v", err)
	}
	if _, err := e.api.repo.WriteFiles(ctx, connect.NewRequest(&apiv1.WriteFilesRequest{Repo: apiv1.Repo_REPO_CONFIG, Message: "bad",
		Changes: []*apiv1.FileChange{{Path: "common/disable.conf", Content: []byte("re:(unclosed\n")}}})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("invalid matcher: %v", err)
	}

	key, _ := sshkey.Generate()
	if _, err := e.api.nodes.AddNode(ctx, connect.NewRequest(&apiv1.AddNodeRequest{PublicKey: key.Public("router-01").String()})); err != nil {
		t.Fatal(err)
	}
	agent := connectAgent(t, e, key, "router-01")

	d1 := agent.next(t)
	if d1.Bundle == nil || d1.Bundle.RulesCommit != rulesC1 {
		t.Fatalf("desired = %v", d1)
	}
	if d1.InterfaceModes["eth0"] != agentv1.InterfaceMode_INTERFACE_MODE_OFF || len(d1.InterfaceModes) != 2 {
		t.Fatalf("interface modes = %v", d1.InterfaceModes)
	}
	if !d1.LogPolicy.GetEnabled() {
		t.Fatal("default log policy should be enabled")
	}
	b := agent.fetch(t, d1.Bundle, hostKey)
	rulesText := string(b.Files[bundle.PathRules])
	if !strings.Contains(rulesText, "sid:1000001") || !strings.Contains(rulesText, "# alert tcp any any -> any 443") {
		t.Fatalf("rendered rules:\n%s", rulesText)
	}
	if !strings.Contains(string(b.Files[bundle.PathControllerYAML]), "10.0.0.0/8") {
		t.Fatalf("controller yaml:\n%s", b.Files[bundle.PathControllerYAML])
	}

	// Interface modes: IPS only where the agent allows it.
	if _, err := e.api.nodes.SetInterfaceModes(ctx, connect.NewRequest(&apiv1.SetInterfaceModesRequest{Id: "router-01",
		Modes: map[string]agentv1.InterfaceMode{"eth1": agentv1.InterfaceMode_INTERFACE_MODE_IPS}})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("IPS on eth1 should be rejected: %v", err)
	}
	if _, err := e.api.nodes.SetInterfaceModes(ctx, connect.NewRequest(&apiv1.SetInterfaceModesRequest{Id: "router-01",
		Modes: map[string]agentv1.InterfaceMode{"eth0": agentv1.InterfaceMode_INTERFACE_MODE_IPS, "eth1": agentv1.InterfaceMode_INTERFACE_MODE_IDS}})); err != nil {
		t.Fatal(err)
	}
	d2 := agent.next(t)
	if d2.Generation != d1.Generation+1 || d2.InterfaceModes["eth0"] != agentv1.InterfaceMode_INTERFACE_MODE_IPS || d2.Bundle.BundleId != d1.Bundle.BundleId {
		t.Fatalf("d2 = %v", d2)
	}

	// Apply report -> in sync.
	if err := agent.sess.Notify(&agentv1.Envelope{Body: &agentv1.Envelope_ApplyReport{ApplyReport: &agentv1.ApplyReport{
		Generation: d2.Generation, Status: agentv1.ApplyStatus_APPLY_STATUS_SUCCEEDED, Stage: agentv1.ApplyStage_APPLY_STAGE_DONE,
		Applied: &agentv1.AppliedState{Generation: d2.Generation, Bundle: d2.Bundle, InterfaceModes: d2.InterfaceModes},
	}}}); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool {
		n, err := e.api.nodes.GetNode(ctx, connect.NewRequest(&apiv1.GetNodeRequest{Id: "router-01"}))
		return err == nil && n.Msg.Node.Online && n.Msg.Node.Deploy.InSync
	})
	hist, _ := e.api.nodes.ListApplyHistory(ctx, connect.NewRequest(&apiv1.ListApplyHistoryRequest{Id: "router-01"}))
	if len(hist.Msg.Entries) != 1 {
		t.Fatalf("history = %v", hist.Msg.Entries)
	}

	// New rules commit is deployed automatically...
	rulesC2 := commitFiles(t, e, apiv1.Repo_REPO_RULES, "more rules", map[string]string{"local/extra.rules": `alert udp any any -> any 53 (msg:"dns"; sid:1000003; rev:1;)` + "\n"})
	d3 := agent.next(t)
	if d3.Bundle.RulesCommit != rulesC2 {
		t.Fatalf("d3 = %v", d3)
	}
	// ...and pinning the previous commit rolls back.
	if _, err := e.api.deploy.SetPolicy(ctx, connect.NewRequest(&apiv1.SetPolicyRequest{Kind: apiv1.DeployKind_DEPLOY_KIND_RULES, Mode: apiv1.DeployMode_DEPLOY_MODE_PINNED, PinnedCommit: rulesC1[:10]})); err != nil {
		t.Fatal(err)
	}
	d4 := agent.next(t)
	if d4.Bundle.RulesCommit != rulesC1 || d4.Bundle.BundleId != d2.Bundle.BundleId {
		t.Fatalf("pinned: %v", d4)
	}
	// Paused: new commits are not deployed.
	if _, err := e.api.deploy.SetPolicy(ctx, connect.NewRequest(&apiv1.SetPolicyRequest{Kind: apiv1.DeployKind_DEPLOY_KIND_RULES, Mode: apiv1.DeployMode_DEPLOY_MODE_PAUSED})); err != nil {
		t.Fatal(err)
	}
	commitFiles(t, e, apiv1.Repo_REPO_RULES, "while paused", map[string]string{"local/paused.rules": `alert ip any any -> any any (msg:"p"; sid:1000004; rev:1;)` + "\n"})
	select {
	case d := <-agent.desired:
		t.Fatalf("unexpected desired while paused: %v", d)
	case <-time.After(700 * time.Millisecond):
	}
	pol, _ := e.api.deploy.GetPolicies(ctx, connect.NewRequest(&apiv1.GetPoliciesRequest{}))
	if pol.Msg.Rules.EffectiveCommit != rulesC1 || pol.Msg.Rules.HeadCommit == rulesC1 {
		t.Fatalf("policies = %v", pol.Msg.Rules)
	}

	// Preview renders any commit.
	pv, err := e.api.deploy.PreviewNode(ctx, connect.NewRequest(&apiv1.PreviewNodeRequest{NodeId: "router-01", RulesCommit: pol.Msg.Rules.HeadCommit}))
	if err != nil || pv.Msg.RuleStats.Total != 4 || pv.Msg.RuleStats.Enabled != 3 {
		t.Fatalf("preview = %v %v", pv, err)
	}

	// Logs shipped by the agent are stored per node.
	ls, err := agent.sess.OpenLogs()
	if err != nil {
		t.Fatal(err)
	}
	enc, _ := zstd.NewWriter(nil)
	ls.Send(&agentv1.LogBatch{Type: agentv1.LogType_LOG_TYPE_EVE, Instance: "ids", ZstdRecords: enc.EncodeAll([]byte(`{"event_type":"alert"}`+"\n"), nil), RecordCount: 1})
	eventually(t, func() bool {
		f, err := e.api.logs.ListLogFiles(ctx, connect.NewRequest(&apiv1.ListLogFilesRequest{NodeId: "router-01"}))
		return err == nil && len(f.Msg.Files) == 1
	})
	stream, err := e.api.logs.TailLog(ctx, connect.NewRequest(&apiv1.TailLogRequest{NodeId: "router-01", Type: agentv1.LogType_LOG_TYPE_EVE, Lines: 10}))
	if err != nil {
		t.Fatal(err)
	}
	if !stream.Receive() || len(stream.Msg().Lines) != 1 {
		t.Fatalf("tail: %v", stream.Err())
	}
	stream.Close()

	// Disabling a node disconnects it.
	disabled := false
	if _, err := e.api.nodes.UpdateNode(ctx, connect.NewRequest(&apiv1.UpdateNodeRequest{Id: "router-01", Enabled: &disabled})); err != nil {
		t.Fatal(err)
	}
	select {
	case <-agent.sess.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("disabled node still connected")
	}
}

func eventually(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestAPIRequestSizeLimit(t *testing.T) {
	e := startController(t)
	big := strings.Repeat("a", 1<<20)
	_, err := e.api.auth.Login(context.Background(), connect.NewRequest(&apiv1.LoginRequest{Username: big, Password: "x"}))
	if connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("oversized login: %v", err)
	}
}
