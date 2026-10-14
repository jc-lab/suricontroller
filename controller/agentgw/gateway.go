// Package agentgw is the controller endpoint agents connect to. It accepts
// WebSocket connections, runs the Noise IK handshake, authenticates the node
// by its static key and serves the yamux streams of the session.
package agentgw

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/flynn/noise"
	"github.com/hashicorp/yamux"
	"google.golang.org/protobuf/proto"

	agentv1 "github.com/jc-lab/suricontroller/gen/suricontroller/agent/v1"
	"github.com/jc-lab/suricontroller/pkg/noiseconn"
	"github.com/jc-lab/suricontroller/pkg/wire"
)

// NodeLookup resolves a node from the X25519 form of its static key.
type NodeLookup interface {
	LookupNodeByX25519(key []byte) (nodeID string, enabled bool, ok bool)
}

// Handler receives session events. Methods are called from per-session
// goroutines and must be safe for concurrent use. OnStatus and OnApplyReport
// run on the session's control loop and should return quickly.
type Handler interface {
	// OnConnect is called after the agent's Hello, before any other message
	// of the session is processed.
	OnConnect(ctx context.Context, s *Session, hello *agentv1.Hello) error
	OnDisconnect(s *Session)
	OnStatus(s *Session, st *agentv1.StatusReport)
	OnApplyReport(s *Session, r *agentv1.ApplyReport)
	OnLogBatch(s *Session, b *agentv1.LogBatch)
	// OpenBlob opens a bundle for download by the given node.
	OpenBlob(ctx context.Context, nodeID, bundleID string) (io.ReadSeekCloser, int64, error)
}

// Config configures a Gateway.
type Config struct {
	// StaticKey is the controller's Noise key (derived from the host key).
	StaticKey noise.DHKey
	Nodes     NodeLookup
	Handler   Handler
	Logger    *slog.Logger
	// ControllerVersion is reported to agents in HelloAck.
	ControllerVersion string
	// StatusInterval requested from agents (default 30s).
	StatusInterval time.Duration
	// Now is used for clock checks (tests).
	Now func() time.Time
	// TrustProxyHeaders uses CF-Connecting-IP / X-Forwarded-For as the
	// remote address shown in logs and the UI.
	TrustProxyHeaders bool
}

// Gateway implements http.Handler for the agent endpoint.
type Gateway struct {
	cfg Config
	log *slog.Logger

	mu       sync.Mutex
	sessions map[string]*Session
	lastTS   map[string]int64 // hex x25519 key -> last accepted handshake timestamp
}

// New creates a Gateway.
func New(cfg Config) *Gateway {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.StatusInterval <= 0 {
		cfg.StatusInterval = 30 * time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Gateway{
		cfg:      cfg,
		log:      cfg.Logger.With("component", "agentgw"),
		sessions: map[string]*Session{},
		lastTS:   map[string]int64{},
	}
}

// Session returns the current session of a node, or nil.
func (g *Gateway) Session(nodeID string) *Session {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.sessions[nodeID]
}

// Sessions returns all current sessions.
func (g *Gateway) Sessions() []*Session {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]*Session, 0, len(g.sessions))
	for _, s := range g.sessions {
		out = append(out, s)
	}
	return out
}

// Disconnect closes the session of a node, if any.
func (g *Gateway) Disconnect(nodeID string) {
	if s := g.Session(nodeID); s != nil {
		s.Close()
	}
}

// ServeHTTP accepts an agent WebSocket connection and serves it until it ends.
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{wire.Subprotocol}})
	if err != nil {
		g.log.Debug("websocket accept failed", "remote", r.RemoteAddr, "err", err)
		return
	}
	if ws.Subprotocol() != wire.Subprotocol {
		ws.Close(websocket.StatusPolicyViolation, "unsupported subprotocol")
		return
	}
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	nc := websocket.NetConn(ctx, ws, websocket.MessageBinary)
	defer nc.Close()

	remote := r.RemoteAddr
	if g.cfg.TrustProxyHeaders {
		remote = proxiedAddr(r)
	}
	var nodeID string
	var reject agentv1.RejectReason
	sc, _, err := noiseconn.Server(ctx, nc, noiseconn.ServerConfig{
		StaticKey: g.cfg.StaticKey,
		Accept: func(peer, payload []byte) ([]byte, bool) {
			nodeID, reject = g.authenticate(peer, payload)
			resp := &agentv1.HandshakeResponse{
				Accepted:         reject == agentv1.RejectReason_REJECT_REASON_UNSPECIFIED,
				Reason:           reject,
				ServerTimeUnixMs: g.cfg.Now().UnixMilli(),
			}
			b, _ := proto.Marshal(resp)
			return b, resp.Accepted
		},
	})
	if err != nil {
		if errors.Is(err, noiseconn.ErrRejected) {
			g.log.Warn("agent rejected", "remote", remote, "node", nodeID, "reason", reject.String())
		} else {
			g.log.Debug("handshake failed", "remote", remote, "err", err)
		}
		return
	}

	mux, err := yamux.Server(sc, wire.YamuxConfig())
	if err != nil {
		return
	}
	defer mux.Close()
	s := &Session{
		gw:          g,
		NodeID:      nodeID,
		RemoteAddr:  remote,
		ConnectedAt: g.cfg.Now(),
		mux:         mux,
		ctx:         ctx,
		cancel:      cancel,
	}
	if err := s.serve(); err != nil && ctx.Err() == nil {
		g.log.Info("session ended", "node", nodeID, "remote", remote, "err", err)
	}
}

func proxiedAddr(r *http.Request) string {
	if v := r.Header.Get("Cf-Connecting-Ip"); v != "" {
		return v
	}
	if v := r.Header.Values("X-Forwarded-For"); len(v) > 0 {
		parts := strings.Split(v[len(v)-1], ",")
		if last := strings.TrimSpace(parts[len(parts)-1]); last != "" {
			return last
		}
	}
	return r.RemoteAddr
}

// authenticate validates the handshake payload. It must not change any state
// other than the replay timestamp, because message 1 can be replayed.
func (g *Gateway) authenticate(peer, payload []byte) (string, agentv1.RejectReason) {
	init := &agentv1.HandshakeInit{}
	if err := proto.Unmarshal(payload, init); err != nil {
		return "", agentv1.RejectReason_REJECT_REASON_PROTOCOL
	}
	nodeID, enabled, ok := g.cfg.Nodes.LookupNodeByX25519(peer)
	if !ok {
		return init.NodeId, agentv1.RejectReason_REJECT_REASON_UNKNOWN_KEY
	}
	if !enabled {
		return nodeID, agentv1.RejectReason_REJECT_REASON_DISABLED
	}
	if init.NodeId != nodeID {
		return nodeID, agentv1.RejectReason_REJECT_REASON_NODE_ID_MISMATCH
	}
	now := g.cfg.Now()
	ts := time.UnixMilli(init.TimestampUnixMs)
	if d := now.Sub(ts); d > wire.MaxClockSkew || d < -wire.MaxClockSkew {
		return nodeID, agentv1.RejectReason_REJECT_REASON_CLOCK_SKEW
	}
	key := hex.EncodeToString(peer)
	g.mu.Lock()
	defer g.mu.Unlock()
	if init.TimestampUnixMs <= g.lastTS[key] {
		return nodeID, agentv1.RejectReason_REJECT_REASON_REPLAY
	}
	g.lastTS[key] = init.TimestampUnixMs
	return nodeID, agentv1.RejectReason_REJECT_REASON_UNSPECIFIED
}

// register makes s the current session of its node, closing the previous
// one. It is called only after the new session proved itself with a valid
// Hello, so replayed handshakes cannot evict a live session.
// It reports whether the replaced session had been announced through
// OnConnect, in which case the new session takes over that announcement.
func (g *Gateway) register(s *Session) bool {
	g.mu.Lock()
	old := g.sessions[s.NodeID]
	g.sessions[s.NodeID] = s
	g.mu.Unlock()
	if old == nil {
		return false
	}
	g.log.Info("replacing existing session", "node", s.NodeID, "old_remote", old.RemoteAddr)
	old.Close()
	return old.announced.Load()
}

func (g *Gateway) unregister(s *Session) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.sessions[s.NodeID] == s {
		delete(g.sessions, s.NodeID)
		return true
	}
	return false
}

// Session is one connected agent.
type Session struct {
	gw          *Gateway
	NodeID      string
	RemoteAddr  string
	ConnectedAt time.Time

	mux    *yamux.Session
	ctx    context.Context
	cancel context.CancelFunc

	// announced is set once OnConnect was (or, after a replacement, had
	// been) called for the node, so OnDisconnect stays balanced.
	announced atomic.Bool

	mu    sync.Mutex
	hello *agentv1.Hello
	peer  *wire.Peer
}

// Hello returns the agent's Hello message.
func (s *Session) Hello() *agentv1.Hello {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hello
}

// Context is cancelled when the session ends.
func (s *Session) Context() context.Context { return s.ctx }

// Close terminates the session.
func (s *Session) Close() {
	s.cancel()
	s.mux.Close()
}

// SendDesired pushes a desired state to the agent.
func (s *Session) SendDesired(ds *agentv1.DesiredState) error {
	s.mu.Lock()
	p := s.peer
	s.mu.Unlock()
	if p == nil {
		return errors.New("agentgw: session not ready")
	}
	return p.Notify(&agentv1.Envelope{Body: &agentv1.Envelope_DesiredState{DesiredState: ds}})
}

func (s *Session) serve() error {
	g := s.gw
	ctrl, hdr, err := acceptWithTimeout(s.mux, 30*time.Second)
	if err != nil {
		return err
	}
	if hdr.Type != agentv1.StreamType_STREAM_TYPE_CONTROL {
		return fmt.Errorf("first stream must be control, got %v", hdr.Type)
	}
	_ = ctrl.Conn().SetReadDeadline(time.Now().Add(30 * time.Second))
	first := &agentv1.Envelope{}
	if err := ctrl.Recv(first); err != nil {
		return fmt.Errorf("read hello: %w", err)
	}
	_ = ctrl.Conn().SetReadDeadline(time.Time{})
	hello := first.GetHello()
	if hello == nil || first.Id == 0 {
		return errors.New("first control message must be a Hello request")
	}
	if hello.NodeId != s.NodeID {
		return fmt.Errorf("hello node id %q does not match %q", hello.NodeId, s.NodeID)
	}
	s.mu.Lock()
	s.hello = hello
	s.mu.Unlock()

	if g.register(s) {
		s.announced.Store(true)
	}
	defer func() {
		if g.unregister(s) && s.announced.Load() {
			g.cfg.Handler.OnDisconnect(s)
		}
	}()

	if err := ctrl.Send(&agentv1.Envelope{ReplyTo: first.Id, Body: &agentv1.Envelope_HelloAck{HelloAck: &agentv1.HelloAck{
		ServerTimeUnixMs:      g.cfg.Now().UnixMilli(),
		ControllerVersion:     g.cfg.ControllerVersion,
		StatusIntervalSeconds: uint32(g.cfg.StatusInterval / time.Second),
	}}}); err != nil {
		return err
	}
	peer := wire.NewPeer(ctrl, s.handleControl)
	s.mu.Lock()
	s.peer = peer
	s.mu.Unlock()

	// OnConnect may push the desired state; it is written after HelloAck and
	// processed by the agent once its control loop starts.
	// Accept data streams before OnConnect: yamux closes the session if a
	// stream the agent opens is not accepted within StreamOpenTimeout.
	go s.acceptStreams()
	s.announced.Store(true)
	if err := g.cfg.Handler.OnConnect(s.ctx, s, hello); err != nil {
		return fmt.Errorf("connect handler: %w", err)
	}
	g.log.Info("agent connected", "node", s.NodeID, "remote", s.RemoteAddr, "agent_version", hello.AgentVersion)
	return peer.Run(s.ctx)
}

func acceptWithTimeout(mux *yamux.Session, d time.Duration) (*wire.MsgStream, *agentv1.StreamHeader, error) {
	type res struct {
		ms  *wire.MsgStream
		hdr *agentv1.StreamHeader
		err error
	}
	ch := make(chan res, 1)
	go func() {
		ms, hdr, err := wire.AcceptStream(mux, 0)
		ch <- res{ms, hdr, err}
	}()
	select {
	case r := <-ch:
		return r.ms, r.hdr, r.err
	case <-time.After(d):
		mux.Close()
		return nil, nil, errors.New("timeout waiting for control stream")
	}
}

func (s *Session) handleControl(_ context.Context, env *agentv1.Envelope) (*agentv1.Envelope, error) {
	switch b := env.Body.(type) {
	case *agentv1.Envelope_Status:
		s.gw.cfg.Handler.OnStatus(s, b.Status)
	case *agentv1.Envelope_ApplyReport:
		s.gw.cfg.Handler.OnApplyReport(s, b.ApplyReport)
	default:
		if env.Id != 0 {
			return nil, &wire.RemoteError{Code: "unsupported", Message: fmt.Sprintf("unsupported message %T", env.Body)}
		}
	}
	return nil, nil
}

func (s *Session) acceptStreams() {
	for {
		ms, hdr, err := wire.AcceptStream(s.mux, 0)
		if err != nil {
			return
		}
		switch hdr.Type {
		case agentv1.StreamType_STREAM_TYPE_LOGS:
			go s.serveLogs(ms)
		case agentv1.StreamType_STREAM_TYPE_BLOB:
			go s.serveBlob(ms, hdr.GetBlob())
		default:
			ms.Close()
		}
	}
}

func (s *Session) serveLogs(ms *wire.MsgStream) {
	defer ms.Close()
	for {
		b := &agentv1.LogBatch{}
		if err := ms.Recv(b); err != nil {
			return
		}
		s.gw.cfg.Handler.OnLogBatch(s, b)
	}
}

func (s *Session) serveBlob(ms *wire.MsgStream, req *agentv1.BlobRequest) {
	defer ms.Close()
	if req == nil {
		_ = ms.Send(&agentv1.BlobResponse{Error: "missing blob request"})
		return
	}
	rc, size, err := s.gw.cfg.Handler.OpenBlob(s.ctx, s.NodeID, req.BundleId)
	if err != nil {
		_ = ms.Send(&agentv1.BlobResponse{Error: err.Error()})
		return
	}
	defer rc.Close()
	if req.Offset > uint64(size) {
		_ = ms.Send(&agentv1.BlobResponse{Error: "offset beyond end of blob"})
		return
	}
	if _, err := rc.Seek(int64(req.Offset), io.SeekStart); err != nil {
		_ = ms.Send(&agentv1.BlobResponse{Error: err.Error()})
		return
	}
	if err := ms.Send(&agentv1.BlobResponse{Ok: true, Size: uint64(size)}); err != nil {
		return
	}
	if _, err := io.Copy(ms.Conn(), rc); err != nil {
		s.gw.log.Debug("blob transfer aborted", "node", s.NodeID, "bundle", req.BundleId, "err", err)
	}
}
