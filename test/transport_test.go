// Package test holds cross-component integration tests.
package test

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jc-lab/suricontroller/agent/conn"
	"github.com/jc-lab/suricontroller/controller/agentgw"
	"github.com/jc-lab/suricontroller/controller/store"
	agentv1 "github.com/jc-lab/suricontroller/gen/suricontroller/agent/v1"
	"github.com/jc-lab/suricontroller/pkg/noiseconn"
	"github.com/jc-lab/suricontroller/pkg/sshkey"
)

type memNodes struct {
	mu    sync.Mutex
	err   error
	nodes map[string]struct {
		id      string
		enabled bool
	}
}

func (m *memNodes) add(t *testing.T, k *sshkey.PrivateKey, id string, enabled bool) {
	x, err := k.Public(id).X25519()
	if err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.nodes == nil {
		m.nodes = map[string]struct {
			id      string
			enabled bool
		}{}
	}
	m.nodes[hex.EncodeToString(x)] = struct {
		id      string
		enabled bool
	}{id, enabled}
}

// fail makes lookups return err (a store outage) until called with nil.
func (m *memNodes) fail(err error) {
	m.mu.Lock()
	m.err = err
	m.mu.Unlock()
}

func (m *memNodes) setEnabled(key *sshkey.PrivateKey, enabled bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	x, _ := key.Public("").X25519()
	k := hex.EncodeToString(x)
	n := m.nodes[k]
	n.enabled = enabled
	m.nodes[k] = n
}

func (m *memNodes) LookupNodeByX25519(_ context.Context, key []byte) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return "", false, m.err
	}
	n, ok := m.nodes[hex.EncodeToString(key)]
	if !ok {
		return "", false, store.ErrNotFound
	}
	return n.id, n.enabled, nil
}

type recorder struct {
	connected chan *agentgw.Session
	status    chan *agentv1.StatusReport
	logs      chan *agentv1.LogBatch
	reports   chan *agentv1.ApplyReport
	disc      chan string
	blob      []byte
	desired   *agentv1.DesiredState
}

func newRecorder() *recorder {
	return &recorder{
		connected: make(chan *agentgw.Session, 8),
		status:    make(chan *agentv1.StatusReport, 8),
		logs:      make(chan *agentv1.LogBatch, 8),
		reports:   make(chan *agentv1.ApplyReport, 8),
		disc:      make(chan string, 8),
	}
}

func (r *recorder) OnConnect(ctx context.Context, s *agentgw.Session, hello *agentv1.Hello) error {
	if r.desired != nil {
		if err := s.SendDesired(r.desired); err != nil {
			return err
		}
	}
	r.connected <- s
	return nil
}
func (r *recorder) OnDisconnect(s *agentgw.Session)                          { r.disc <- s.NodeID }
func (r *recorder) OnStatus(s *agentgw.Session, st *agentv1.StatusReport)    { r.status <- st }
func (r *recorder) OnApplyReport(s *agentgw.Session, a *agentv1.ApplyReport) { r.reports <- a }
func (r *recorder) OnLogBatch(s *agentgw.Session, b *agentv1.LogBatch)       { r.logs <- b }
func (r *recorder) OpenBlob(ctx context.Context, nodeID, bundleID string) (io.ReadSeekCloser, int64, error) {
	if bundleID != "b1" {
		return nil, 0, errors.New("no such bundle")
	}
	return nopSeekCloser{bytes.NewReader(r.blob)}, int64(len(r.blob)), nil
}

type nopSeekCloser struct{ *bytes.Reader }

func (nopSeekCloser) Close() error { return nil }

type env struct {
	hostKey *sshkey.PrivateKey
	nodes   *memNodes
	rec     *recorder
	gw      *agentgw.Gateway
	url     string
	client  *http.Client
}

// newEnv starts the gateway behind a TLS-terminating reverse proxy, the way
// it is deployed behind cloudflared or a load balancer.
func newEnv(t *testing.T) *env { return newEnvWith(t, nil) }

func newEnvWith(t *testing.T, tweak func(*agentgw.Config)) *env {
	t.Helper()
	hk, _ := sshkey.Generate()
	static, err := noiseconn.KeyPair(hk.X25519())
	if err != nil {
		t.Fatal(err)
	}
	e := &env{hostKey: hk, nodes: &memNodes{}, rec: newRecorder()}
	cfg := agentgw.Config{StaticKey: static, Nodes: e.nodes, Handler: e.rec, ControllerVersion: "test"}
	if tweak != nil {
		tweak(&cfg)
	}
	e.gw = agentgw.New(cfg)
	backend := httptest.NewServer(e.gw)
	t.Cleanup(backend.Close)
	bu, _ := url.Parse(backend.URL)
	proxy := httptest.NewTLSServer(httputil.NewSingleHostReverseProxy(bu))
	t.Cleanup(proxy.Close)
	e.url = "wss" + strings.TrimPrefix(proxy.URL, "https") + "/agent/v1/connect"
	e.client = proxy.Client()
	return e
}

func (e *env) dial(t *testing.T, key *sshkey.PrivateKey, nodeID string, serverKey *sshkey.PublicKey, h func(*agentv1.Envelope)) (*conn.Session, error) {
	t.Helper()
	if serverKey == nil {
		serverKey = e.hostKey.Public("controller")
	}
	return conn.Dial(context.Background(), conn.Config{
		URL:          e.url,
		HTTPClient:   e.client,
		Key:          key,
		ServerKey:    serverKey,
		NodeID:       nodeID,
		AgentVersion: "test",
	}, &agentv1.Hello{NodeId: nodeID, AgentVersion: "test"}, func(ctx context.Context, env *agentv1.Envelope) (*agentv1.Envelope, error) {
		if h != nil {
			h(env)
		}
		return nil, nil
	})
}

func waitFor[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(10 * time.Second):
		t.Fatal("timeout")
		var zero T
		return zero
	}
}

func TestAgentSessionThroughTLSProxy(t *testing.T) {
	e := newEnv(t)
	nk, _ := sshkey.Generate()
	e.nodes.add(t, nk, "router-01", true)
	e.rec.desired = &agentv1.DesiredState{Generation: 7}
	e.rec.blob = bytes.Repeat([]byte("bundle-data-"), 50_000)

	desired := make(chan *agentv1.DesiredState, 1)
	s, err := e.dial(t, nk, "router-01", nil, func(env *agentv1.Envelope) {
		if d := env.GetDesiredState(); d != nil {
			desired <- d
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.HelloAck().ControllerVersion != "test" {
		t.Fatalf("hello ack = %v", s.HelloAck())
	}
	go s.Run(context.Background())

	sess := waitFor(t, e.rec.connected)
	if sess.NodeID != "router-01" || e.gw.Session("router-01") != sess {
		t.Fatal("session not registered")
	}
	if d := waitFor(t, desired); d.Generation != 7 {
		t.Fatalf("desired = %v", d)
	}

	// Status notification.
	if err := s.Notify(&agentv1.Envelope{Body: &agentv1.Envelope_Status{Status: &agentv1.StatusReport{TimeUnixMs: 99}}}); err != nil {
		t.Fatal(err)
	}
	if st := waitFor(t, e.rec.status); st.TimeUnixMs != 99 {
		t.Fatal("wrong status")
	}

	// Log stream.
	ls, err := s.OpenLogs()
	if err != nil {
		t.Fatal(err)
	}
	if err := ls.Send(&agentv1.LogBatch{Seq: 1, RecordCount: 3}); err != nil {
		t.Fatal(err)
	}
	if b := waitFor(t, e.rec.logs); b.Seq != 1 || b.RecordCount != 3 {
		t.Fatal("wrong log batch")
	}

	// Blob download, full and resumed.
	rc, size, err := s.FetchBlob(context.Background(), "b1", 0)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(rc)
	rc.Close()
	if err != nil || size != uint64(len(e.rec.blob)) || !bytes.Equal(got, e.rec.blob) {
		t.Fatalf("blob mismatch: err=%v size=%d len=%d", err, size, len(got))
	}
	rc, _, err = s.FetchBlob(context.Background(), "b1", 100)
	if err != nil {
		t.Fatal(err)
	}
	got, _ = io.ReadAll(rc)
	rc.Close()
	if !bytes.Equal(got, e.rec.blob[100:]) {
		t.Fatal("resumed blob mismatch")
	}
	if _, _, err := s.FetchBlob(context.Background(), "missing", 0); err == nil {
		t.Fatal("expected error for missing blob")
	}

	s.Close()
	if id := waitFor(t, e.rec.disc); id != "router-01" {
		t.Fatal("wrong disconnect")
	}
}

func TestUnknownKeyRejected(t *testing.T) {
	e := newEnv(t)
	nk, _ := sshkey.Generate()
	_, err := e.dial(t, nk, "stranger", nil, nil)
	var re *conn.RejectedError
	if !errors.As(err, &re) || re.Reason != agentv1.RejectReason_REJECT_REASON_UNKNOWN_KEY {
		t.Fatalf("err = %v", err)
	}
}

func TestDisabledAndMismatchRejected(t *testing.T) {
	e := newEnv(t)
	k1, _ := sshkey.Generate()
	k2, _ := sshkey.Generate()
	e.nodes.add(t, k1, "disabled-node", false)
	e.nodes.add(t, k2, "node-b", true)

	var re *conn.RejectedError
	if _, err := e.dial(t, k1, "disabled-node", nil, nil); !errors.As(err, &re) || re.Reason != agentv1.RejectReason_REJECT_REASON_DISABLED {
		t.Fatalf("disabled: err = %v", err)
	}
	if _, err := e.dial(t, k2, "node-c", nil, nil); !errors.As(err, &re) || re.Reason != agentv1.RejectReason_REJECT_REASON_NODE_ID_MISMATCH {
		t.Fatalf("mismatch: err = %v", err)
	}
}

func TestWrongPinnedControllerKey(t *testing.T) {
	e := newEnv(t)
	nk, _ := sshkey.Generate()
	e.nodes.add(t, nk, "router-01", true)
	other, _ := sshkey.Generate()
	if _, err := e.dial(t, nk, "router-01", other.Public("evil"), nil); err == nil {
		t.Fatal("expected handshake failure with wrong pinned key")
	}
}

func TestReconnectReplacesSession(t *testing.T) {
	e := newEnv(t)
	nk, _ := sshkey.Generate()
	e.nodes.add(t, nk, "router-01", true)

	s1, err := e.dial(t, nk, "router-01", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	go s1.Run(context.Background())
	first := waitFor(t, e.rec.connected)

	time.Sleep(5 * time.Millisecond) // handshake timestamps must increase
	s2, err := e.dial(t, nk, "router-01", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	go s2.Run(context.Background())
	second := waitFor(t, e.rec.connected)
	if first == second || e.gw.Session("router-01") != second {
		t.Fatal("new session should replace the old one")
	}
	select {
	case <-s1.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("old session not closed")
	}
	// The replaced session must not trigger a disconnect for the node.
	select {
	case id := <-e.rec.disc:
		t.Fatalf("unexpected disconnect of %s", id)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestClockSkewRejectionCarriesServerTime(t *testing.T) {
	hk, _ := sshkey.Generate()
	static, _ := noiseconn.KeyPair(hk.X25519())
	nodes := &memNodes{}
	nk, _ := sshkey.Generate()
	nodes.add(t, nk, "router-01", true)
	skew := 2 * time.Hour
	gw := agentgw.New(agentgw.Config{StaticKey: static, Nodes: nodes, Handler: newRecorder(), Now: func() time.Time { return time.Now().Add(skew) }})
	srv := httptest.NewServer(gw)
	defer srv.Close()
	dial := func(now func() time.Time) (*conn.Session, error) {
		return conn.Dial(context.Background(), conn.Config{
			URL: "ws" + strings.TrimPrefix(srv.URL, "http") + "/agent/v1/connect", Key: nk, ServerKey: hk.Public(""), NodeID: "router-01", Now: now,
		}, &agentv1.Hello{NodeId: "router-01"}, func(context.Context, *agentv1.Envelope) (*agentv1.Envelope, error) { return nil, nil })
	}
	_, err := dial(nil)
	var re *conn.RejectedError
	if !errors.As(err, &re) || re.Reason != agentv1.RejectReason_REJECT_REASON_CLOCK_SKEW {
		t.Fatalf("err = %v", err)
	}
	offset := time.Until(re.ServerTime)
	if offset < skew-time.Minute || offset > skew+time.Minute {
		t.Fatalf("server time offset = %v", offset)
	}
	s, err := dial(func() time.Time { return time.Now().Add(offset) })
	if err != nil {
		t.Fatalf("corrected clock: %v", err)
	}
	s.Close()
}

func TestRecheckClosesSessionOfDisabledNode(t *testing.T) {
	e := newEnvWith(t, func(c *agentgw.Config) { c.SessionRecheckInterval = 50 * time.Millisecond })
	nk, _ := sshkey.Generate()
	e.nodes.add(t, nk, "router-01", true)
	s, err := e.dial(t, nk, "router-01", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Run(context.Background())
	waitFor(t, e.rec.connected)

	// A store outage keeps the session.
	e.nodes.fail(errors.New("database down"))
	select {
	case <-s.Done():
		t.Fatal("session closed during a lookup outage")
	case <-time.After(300 * time.Millisecond):
	}
	e.nodes.fail(nil)

	e.nodes.setEnabled(nk, false)
	select {
	case <-s.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("session of a disabled node not closed")
	}
}

func TestLookupOutageRejectsAsUnavailable(t *testing.T) {
	e := newEnv(t)
	nk, _ := sshkey.Generate()
	e.nodes.add(t, nk, "router-01", true)
	e.nodes.fail(errors.New("database down"))
	var re *conn.RejectedError
	if _, err := e.dial(t, nk, "router-01", nil, nil); !errors.As(err, &re) || re.Reason != agentv1.RejectReason_REJECT_REASON_UNAVAILABLE {
		t.Fatalf("err = %v", err)
	}
}
