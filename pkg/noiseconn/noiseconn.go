// Package noiseconn implements a Noise_IK_25519_ChaChaPoly_BLAKE2s secure
// channel over a stream connection (in practice a WebSocket adapted with
// websocket.NetConn).
//
// Every Noise message is framed with a 2-byte big-endian length prefix, so the
// channel does not depend on the message boundaries of the underlying
// transport. The resulting *Conn implements net.Conn.
package noiseconn

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/flynn/noise"
	"golang.org/x/crypto/curve25519"
)

// Prologue binds the handshake to this protocol and version. Other
// protocols built on this package set their own prologue in the config.
const Prologue = "suricontroller/agent/1"

const (
	maxMessageSize = 65535
	tagSize        = 16
	maxPlaintext   = maxMessageSize - tagSize
)

// DefaultHandshakeTimeout bounds the whole handshake.
const DefaultHandshakeTimeout = 15 * time.Second

var cipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)

// ErrRejected is returned by Client when the responder declined the
// handshake. The responder's payload is still returned.
var ErrRejected = errors.New("noiseconn: handshake rejected by peer")

// KeyPair builds a Noise DH key pair from an X25519 private scalar.
func KeyPair(x25519Private []byte) (noise.DHKey, error) {
	pub, err := curve25519.X25519(x25519Private, curve25519.Basepoint)
	if err != nil {
		return noise.DHKey{}, err
	}
	priv := make([]byte, len(x25519Private))
	copy(priv, x25519Private)
	return noise.DHKey{Private: priv, Public: pub}, nil
}

// ClientConfig configures the initiator side.
type ClientConfig struct {
	StaticKey noise.DHKey
	// PeerStatic is the pinned X25519 public key of the responder.
	PeerStatic []byte
	// Payload is sent (encrypted) in handshake message 1.
	Payload []byte
	// Accepted inspects the responder's payload and reports whether the
	// handshake was accepted. If nil, every response is accepted.
	Accepted func(payload []byte) bool
	Timeout  time.Duration
	// Prologue overrides the default Prologue. Both peers must use the same.
	Prologue string
}

// ServerConfig configures the responder side.
type ServerConfig struct {
	StaticKey noise.DHKey
	// Accept is called with the initiator's static key and payload. It
	// returns the payload for message 2 and whether to accept the peer. A
	// rejected peer still receives message 2 so it can learn the reason.
	Accept  func(peerStatic, payload []byte) (response []byte, accept bool)
	Timeout time.Duration
	// Prologue overrides the default Prologue. Both peers must use the same.
	Prologue string
}

func prologue(p string) []byte {
	if p == "" {
		p = Prologue
	}
	return []byte(p)
}

// Client performs the initiator side of the handshake.
func Client(ctx context.Context, c net.Conn, cfg ClientConfig) (*Conn, []byte, error) {
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cipherSuite,
		Random:        rand.Reader,
		Pattern:       noise.HandshakeIK,
		Initiator:     true,
		Prologue:      prologue(cfg.Prologue),
		StaticKeypair: cfg.StaticKey,
		PeerStatic:    cfg.PeerStatic,
	})
	if err != nil {
		return nil, nil, err
	}
	stop := handshakeDeadline(ctx, c, cfg.Timeout)
	defer stop()

	msg1, _, _, err := hs.WriteMessage(nil, cfg.Payload)
	if err != nil {
		return nil, nil, err
	}
	if err := writeFrame(c, msg1); err != nil {
		return nil, nil, fmt.Errorf("noiseconn: send handshake: %w", err)
	}
	msg2, err := readFrame(c, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("noiseconn: read handshake: %w", err)
	}
	payload, send, recv, err := hs.ReadMessage(nil, msg2)
	if err != nil {
		return nil, nil, fmt.Errorf("noiseconn: handshake: %w", err)
	}
	if cfg.Accepted != nil && !cfg.Accepted(payload) {
		return nil, payload, ErrRejected
	}
	return newConn(c, send, recv, cfg.PeerStatic), payload, nil
}

// Server performs the responder side of the handshake. It returns the
// initiator's payload alongside the connection.
func Server(ctx context.Context, c net.Conn, cfg ServerConfig) (*Conn, []byte, error) {
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cipherSuite,
		Random:        rand.Reader,
		Pattern:       noise.HandshakeIK,
		Initiator:     false,
		Prologue:      prologue(cfg.Prologue),
		StaticKeypair: cfg.StaticKey,
	})
	if err != nil {
		return nil, nil, err
	}
	stop := handshakeDeadline(ctx, c, cfg.Timeout)
	defer stop()

	msg1, err := readFrame(c, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("noiseconn: read handshake: %w", err)
	}
	payload, _, _, err := hs.ReadMessage(nil, msg1)
	if err != nil {
		return nil, nil, fmt.Errorf("noiseconn: handshake: %w", err)
	}
	peer := append([]byte(nil), hs.PeerStatic()...)
	resp, accept := cfg.Accept(peer, payload)
	// For the responder, the first cipher state encrypts initiator->responder
	// traffic and the second responder->initiator traffic.
	msg2, recv, send, err := hs.WriteMessage(nil, resp)
	if err != nil {
		return nil, payload, err
	}
	if err := writeFrame(c, msg2); err != nil {
		return nil, payload, fmt.Errorf("noiseconn: send handshake: %w", err)
	}
	if !accept {
		return nil, payload, ErrRejected
	}
	return newConn(c, send, recv, peer), payload, nil
}

// handshakeDeadline applies a deadline to c for the handshake and also
// aborts it when ctx is cancelled. The returned func clears the deadline.
func handshakeDeadline(ctx context.Context, c net.Conn, timeout time.Duration) func() {
	if timeout <= 0 {
		timeout = DefaultHandshakeTimeout
	}
	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = c.SetDeadline(deadline)
	stopWatch := context.AfterFunc(ctx, func() { _ = c.SetDeadline(time.Unix(1, 0)) })
	return func() {
		stopWatch()
		_ = c.SetDeadline(time.Time{})
	}
}

func writeFrame(w io.Writer, msg []byte) error {
	if len(msg) > maxMessageSize {
		return fmt.Errorf("noiseconn: message too large (%d)", len(msg))
	}
	buf := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(buf, uint16(len(msg)))
	copy(buf[2:], msg)
	_, err := w.Write(buf)
	return err
}

func readFrame(r io.Reader, buf []byte) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if cap(buf) < n {
		buf = make([]byte, n)
	}
	buf = buf[:n]
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// Conn is an established secure channel. It is safe for one concurrent
// reader and one concurrent writer.
type Conn struct {
	c          net.Conn
	peerStatic []byte

	rmu     sync.Mutex
	recv    *noise.CipherState
	frame   []byte
	pending []byte // decrypted bytes not yet returned by Read

	wmu  sync.Mutex
	send *noise.CipherState
	wbuf []byte
}

func newConn(c net.Conn, send, recv *noise.CipherState, peer []byte) *Conn {
	return &Conn{c: c, send: send, recv: recv, peerStatic: peer}
}

// PeerStatic returns the peer's X25519 static public key.
func (c *Conn) PeerStatic() []byte { return c.peerStatic }

// Read implements net.Conn.
func (c *Conn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for len(c.pending) == 0 {
		frame, err := readFrame(c.c, c.frame)
		if err != nil {
			return 0, err
		}
		c.frame = frame
		// Decrypt in place; the frame buffer is only reused once pending
		// has been fully consumed.
		pt, err := c.recv.Decrypt(frame[:0], nil, frame)
		if err != nil {
			return 0, fmt.Errorf("noiseconn: decrypt: %w", err)
		}
		c.pending = pt
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

// Write implements net.Conn. Large writes are split into multiple Noise
// messages.
func (c *Conn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	written := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxPlaintext {
			chunk = chunk[:maxPlaintext]
		}
		need := 2 + len(chunk) + tagSize
		if cap(c.wbuf) < need {
			c.wbuf = make([]byte, 0, 2+maxMessageSize)
		}
		buf := c.wbuf[:2]
		binary.BigEndian.PutUint16(buf, uint16(len(chunk)+tagSize))
		buf, err := c.send.Encrypt(buf, nil, chunk)
		if err != nil {
			return written, err
		}
		if _, err := c.c.Write(buf); err != nil {
			return written, err
		}
		written += len(chunk)
		p = p[len(chunk):]
	}
	return written, nil
}

// Close implements net.Conn.
func (c *Conn) Close() error { return c.c.Close() }

// LocalAddr implements net.Conn.
func (c *Conn) LocalAddr() net.Addr { return c.c.LocalAddr() }

// RemoteAddr implements net.Conn.
func (c *Conn) RemoteAddr() net.Addr { return c.c.RemoteAddr() }

// SetDeadline implements net.Conn.
func (c *Conn) SetDeadline(t time.Time) error { return c.c.SetDeadline(t) }

// SetReadDeadline implements net.Conn.
func (c *Conn) SetReadDeadline(t time.Time) error { return c.c.SetReadDeadline(t) }

// SetWriteDeadline implements net.Conn.
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.c.SetWriteDeadline(t) }
