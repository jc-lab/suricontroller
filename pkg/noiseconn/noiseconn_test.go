package noiseconn

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/flynn/noise"
)

func genKey(t *testing.T) noise.DHKey {
	t.Helper()
	k, err := cipherSuite.GenerateKeypair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

type result struct {
	conn    *Conn
	payload []byte
	err     error
}

func handshake(t *testing.T, client ClientConfig, server ServerConfig) (cr, sr result) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	done := make(chan result, 1)
	go func() {
		c, p, err := Server(context.Background(), b, server)
		if err != nil {
			b.Close()
		}
		done <- result{c, p, err}
	}()
	c, p, err := Client(context.Background(), a, client)
	cr = result{c, p, err}
	sr = <-done
	return
}

func TestHandshakeAndTransport(t *testing.T) {
	ck, sk := genKey(t), genKey(t)
	var seenPeer []byte
	cr, sr := handshake(t,
		ClientConfig{StaticKey: ck, PeerStatic: sk.Public, Payload: []byte("hello")},
		ServerConfig{StaticKey: sk, Accept: func(peer, payload []byte) ([]byte, bool) {
			seenPeer = peer
			if string(payload) != "hello" {
				t.Errorf("payload = %q", payload)
			}
			return []byte("welcome"), true
		}},
	)
	if cr.err != nil || sr.err != nil {
		t.Fatalf("client err=%v server err=%v", cr.err, sr.err)
	}
	if !bytes.Equal(seenPeer, ck.Public) {
		t.Fatal("server saw wrong client static key")
	}
	if string(cr.payload) != "welcome" {
		t.Fatalf("response payload = %q", cr.payload)
	}

	// Large message spanning several Noise frames, in both directions.
	big := make([]byte, 300_000)
	rand.Read(big)
	errc := make(chan error, 1)
	go func() {
		_, err := cr.conn.Write(big)
		errc <- err
	}()
	got := make([]byte, len(big))
	if _, err := io.ReadFull(sr.conn, got); err != nil {
		t.Fatal(err)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, big) {
		t.Fatal("data mismatch client->server")
	}
	go func() {
		_, err := sr.conn.Write([]byte("pong"))
		errc <- err
	}()
	buf := make([]byte, 4)
	if _, err := io.ReadFull(cr.conn, buf); err != nil || string(buf) != "pong" {
		t.Fatalf("server->client: %q %v", buf, err)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}

func TestWrongPinnedServerKey(t *testing.T) {
	ck, sk, other := genKey(t), genKey(t), genKey(t)
	cr, sr := handshake(t,
		ClientConfig{StaticKey: ck, PeerStatic: other.Public, Payload: []byte("x")},
		ServerConfig{StaticKey: sk, Accept: func(_, _ []byte) ([]byte, bool) {
			t.Error("server must not accept a handshake for another static key")
			return nil, true
		}},
	)
	if sr.err == nil {
		t.Fatal("server should fail to decrypt message 1")
	}
	if cr.err == nil {
		t.Fatal("client should fail")
	}
}

func TestRejected(t *testing.T) {
	ck, sk := genKey(t), genKey(t)
	cr, sr := handshake(t,
		ClientConfig{StaticKey: ck, PeerStatic: sk.Public, Accepted: func(p []byte) bool { return string(p) == "ok" }},
		ServerConfig{StaticKey: sk, Accept: func(_, _ []byte) ([]byte, bool) { return []byte("unknown key"), false }},
	)
	if !errors.Is(sr.err, ErrRejected) {
		t.Fatalf("server err = %v", sr.err)
	}
	if !errors.Is(cr.err, ErrRejected) || string(cr.payload) != "unknown key" {
		t.Fatalf("client err=%v payload=%q", cr.err, cr.payload)
	}
}

func TestTamperedFrameFails(t *testing.T) {
	ck, sk := genKey(t), genKey(t)
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	mitmA, mitmB := net.Pipe()
	defer mitmA.Close()
	defer mitmB.Close()

	// Relay a <-> b, flipping one bit in the first post-handshake frame
	// sent by the client.
	go relay(mitmA, a, 1) // client -> server: frame 0 is message 1
	go relay(a, mitmA, -1)

	done := make(chan result, 1)
	go func() {
		c, p, err := Server(context.Background(), mitmB, ServerConfig{StaticKey: sk, Accept: func(_, _ []byte) ([]byte, bool) { return nil, true }})
		done <- result{c, p, err}
	}()
	cc, _, err := Client(context.Background(), b, ClientConfig{StaticKey: ck, PeerStatic: sk.Public})
	if err != nil {
		t.Fatal(err)
	}
	sr := <-done
	if sr.err != nil {
		t.Fatal(sr.err)
	}
	go cc.Write([]byte("secret data"))
	buf := make([]byte, 16)
	if _, err := sr.conn.Read(buf); err == nil {
		t.Fatal("expected decrypt failure on tampered frame")
	}
}

// relay copies frames from src to dst. When tamperFrame >= 0, the frame with
// that index (0-based, counting handshake frames) gets a bit flipped.
func relay(dst, src net.Conn, tamperFrame int) {
	for i := 0; ; i++ {
		f, err := readFrame(src, nil)
		if err != nil {
			dst.Close()
			return
		}
		if i == tamperFrame {
			f[len(f)-1] ^= 1
		}
		if err := writeFrame(dst, f); err != nil {
			return
		}
	}
}

func TestPrologueMismatchFails(t *testing.T) {
	ck, sk := genKey(t), genKey(t)
	cr, sr := handshake(t,
		ClientConfig{StaticKey: ck, PeerStatic: sk.Public, Prologue: "other/1"},
		ServerConfig{StaticKey: sk, Accept: func(_, _ []byte) ([]byte, bool) { return nil, true }},
	)
	if sr.err == nil && cr.err == nil {
		t.Fatal("handshake with different prologues succeeded")
	}
	cr, sr = handshake(t,
		ClientConfig{StaticKey: ck, PeerStatic: sk.Public, Prologue: "other/1"},
		ServerConfig{StaticKey: sk, Prologue: "other/1", Accept: func(_, _ []byte) ([]byte, bool) { return nil, true }},
	)
	if cr.err != nil || sr.err != nil {
		t.Fatalf("handshake with matching custom prologue: client=%v server=%v", cr.err, sr.err)
	}
}
