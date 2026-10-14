// Package conn establishes the agent's secure session with the controller:
// WebSocket dial, Noise IK handshake with the pinned controller key, yamux,
// and the Hello exchange on the control stream.
package conn

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"
	"google.golang.org/protobuf/proto"

	agentv1 "github.com/jc-lab/suricontroller/gen/suricontroller/agent/v1"
	"github.com/jc-lab/suricontroller/pkg/noiseconn"
	"github.com/jc-lab/suricontroller/pkg/sshkey"
	"github.com/jc-lab/suricontroller/pkg/wire"
)

// Config configures Dial.
type Config struct {
	// URL of the controller agent endpoint (ws:// or wss://).
	URL string
	// Headers added to the WebSocket upgrade request (e.g. Cloudflare Access
	// service token headers).
	Headers http.Header
	// HTTPClient used for the upgrade. Nil uses a client that honors the
	// HTTP(S)_PROXY environment variables.
	HTTPClient *http.Client
	Key        *sshkey.PrivateKey
	ServerKey  *sshkey.PublicKey
	NodeID     string
	// AgentVersion is sent in the handshake.
	AgentVersion string
	Now          func() time.Time
}

// RejectedError reports that the controller refused the agent. The
// rejection is authenticated (it arrives in Noise message 2), so ServerTime
// can be trusted to correct the local clock.
type RejectedError struct {
	Reason     agentv1.RejectReason
	Message    string
	ServerTime time.Time
}

func (e *RejectedError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("controller rejected agent: %s (%s)", e.Reason, e.Message)
	}
	return fmt.Sprintf("controller rejected agent: %s", e.Reason)
}

// Session is an established agent session.
type Session struct {
	ws       *websocket.Conn
	mux      *yamux.Session
	ctrl     *wire.MsgStream
	peer     *wire.Peer
	cancel   context.CancelFunc
	helloAck *agentv1.HelloAck
}

// Dial connects to the controller and performs the Hello exchange. The
// returned session's control loop is started with Run.
func Dial(ctx context.Context, cfg Config, hello *agentv1.Hello, h wire.Handler) (*Session, error) {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	serverX, err := cfg.ServerKey.X25519()
	if err != nil {
		return nil, err
	}
	static, err := noiseconn.KeyPair(cfg.Key.X25519())
	if err != nil {
		return nil, err
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Transport: &http.Transport{Proxy: http.ProxyFromEnvironment}}
	}
	dialCtx, dialCancel := context.WithTimeout(ctx, 30*time.Second)
	defer dialCancel()
	ws, _, err := websocket.Dial(dialCtx, cfg.URL, &websocket.DialOptions{
		HTTPClient:   client,
		HTTPHeader:   cfg.Headers,
		Subprotocols: []string{wire.Subprotocol},
	})
	if err != nil {
		return nil, fmt.Errorf("conn: websocket dial: %w", err)
	}
	if ws.Subprotocol() != wire.Subprotocol {
		ws.Close(websocket.StatusPolicyViolation, "unsupported subprotocol")
		return nil, errors.New("conn: controller did not accept subprotocol")
	}

	sessCtx, cancel := context.WithCancel(context.Background())
	s := &Session{ws: ws, cancel: cancel}
	ok := false
	defer func() {
		if !ok {
			s.Close()
		}
	}()
	nc := websocket.NetConn(sessCtx, ws, websocket.MessageBinary)

	payload, _ := proto.Marshal(&agentv1.HandshakeInit{
		NodeId:          cfg.NodeID,
		AgentVersion:    cfg.AgentVersion,
		TimestampUnixMs: cfg.Now().UnixMilli(),
	})
	resp := &agentv1.HandshakeResponse{}
	sc, _, err := noiseconn.Client(dialCtx, nc, noiseconn.ClientConfig{
		StaticKey:  static,
		PeerStatic: serverX,
		Payload:    payload,
		Accepted: func(p []byte) bool {
			return proto.Unmarshal(p, resp) == nil && resp.Accepted
		},
	})
	if err != nil {
		if errors.Is(err, noiseconn.ErrRejected) {
			return nil, &RejectedError{Reason: resp.Reason, Message: resp.Message, ServerTime: time.UnixMilli(resp.ServerTimeUnixMs)}
		}
		return nil, fmt.Errorf("conn: handshake: %w", err)
	}

	s.mux, err = yamux.Client(sc, wire.YamuxConfig())
	if err != nil {
		return nil, err
	}
	s.ctrl, err = wire.OpenStream(s.mux, &agentv1.StreamHeader{Type: agentv1.StreamType_STREAM_TYPE_CONTROL}, 0)
	if err != nil {
		return nil, err
	}
	if err := s.ctrl.Send(&agentv1.Envelope{Id: 1, Body: &agentv1.Envelope_Hello{Hello: hello}}); err != nil {
		return nil, err
	}
	_ = s.ctrl.Conn().SetReadDeadline(time.Now().Add(30 * time.Second))
	reply := &agentv1.Envelope{}
	if err := s.ctrl.Recv(reply); err != nil {
		return nil, fmt.Errorf("conn: read hello reply: %w", err)
	}
	_ = s.ctrl.Conn().SetReadDeadline(time.Time{})
	if e := reply.GetError(); e != nil {
		return nil, &wire.RemoteError{Code: e.Code, Message: e.Message}
	}
	if reply.ReplyTo != 1 || reply.GetHelloAck() == nil {
		return nil, errors.New("conn: unexpected hello reply")
	}
	s.helloAck = reply.GetHelloAck()
	s.peer = wire.NewPeer(s.ctrl, h)
	ok = true
	return s, nil
}

// HelloAck returns the controller's reply to Hello.
func (s *Session) HelloAck() *agentv1.HelloAck { return s.helloAck }

// Run processes control messages until the session ends.
func (s *Session) Run(ctx context.Context) error {
	defer s.Close()
	return s.peer.Run(ctx)
}

// Done is closed when the control loop stops.
func (s *Session) Done() <-chan struct{} { return s.peer.Done() }

// Notify sends a control notification.
func (s *Session) Notify(env *agentv1.Envelope) error { return s.peer.Notify(env) }

// OpenLogs opens a log stream.
func (s *Session) OpenLogs() (*wire.MsgStream, error) {
	return wire.OpenStream(s.mux, &agentv1.StreamHeader{Type: agentv1.StreamType_STREAM_TYPE_LOGS}, 0)
}

// FetchBlob starts downloading a bundle from offset. It returns a reader for
// the remaining bytes and the total size of the blob.
func (s *Session) FetchBlob(ctx context.Context, bundleID string, offset uint64) (io.ReadCloser, uint64, error) {
	ms, err := wire.OpenStream(s.mux, &agentv1.StreamHeader{
		Type: agentv1.StreamType_STREAM_TYPE_BLOB,
		Blob: &agentv1.BlobRequest{BundleId: bundleID, Offset: offset},
	}, 0)
	if err != nil {
		return nil, 0, err
	}
	stop := context.AfterFunc(ctx, func() { ms.Close() })
	resp := &agentv1.BlobResponse{}
	if err := ms.Recv(resp); err != nil {
		stop()
		ms.Close()
		return nil, 0, err
	}
	if !resp.Ok {
		stop()
		ms.Close()
		return nil, 0, fmt.Errorf("conn: blob %s: %s", bundleID, resp.Error)
	}
	return &blobReader{r: ms.Reader(), ms: ms, stop: stop}, resp.Size, nil
}

type blobReader struct {
	r    io.Reader
	ms   *wire.MsgStream
	stop func() bool
}

func (b *blobReader) Read(p []byte) (int, error) { return b.r.Read(p) }

func (b *blobReader) Close() error {
	b.stop()
	return b.ms.Close()
}

// Close terminates the session.
func (s *Session) Close() {
	s.cancel()
	if s.mux != nil {
		s.mux.Close()
	}
	_ = s.ws.CloseNow()
}
