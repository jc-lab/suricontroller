//go:build linux

package suritap

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"
)

// mockd locates the Rust suritap-mockd binary (cargo build -p suritap):
// $SURITAP_MOCKD or tap/target/{release,debug}/suritap-mockd.
func mockd(t *testing.T) string {
	if p := os.Getenv("SURITAP_MOCKD"); p != "" {
		return p
	}
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(file), "..", "..")
	for _, p := range []string{"tap/target/release/suritap-mockd", "tap/target/debug/suritap-mockd"} {
		if _, err := os.Stat(filepath.Join(root, p)); err == nil {
			return filepath.Join(root, p)
		}
	}
	t.Skip("suritap-mockd not built (cargo build -p suritap in tap/) and SURITAP_MOCKD unset")
	return ""
}

func startMockd(t *testing.T, workers string) string {
	dir, _ := startMockdCmd(t, workers)
	return dir
}

func startMockdCmd(t *testing.T, workers string, extra ...string) (string, *exec.Cmd) {
	bin := mockd(t)
	// Keep the socket path short (sun_path is 108 bytes).
	dir, err := os.MkdirTemp("", "stap")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, append([]string{"--dir", dir, "--workers", workers, "--max-segment", "4096"}, extra...)...)
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGCONT) // in case a test stopped it
		_ = cmd.Process.Signal(syscall.SIGTERM)
		_ = cmd.Wait()
		os.RemoveAll(dir)
	})
	for range 100 {
		if _, err := os.Stat(SocketPath(dir, 0)); err == nil {
			return dir, cmd
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("mockd did not start")
	return "", nil
}

// Payload that cannot be queued in time (server stalled, ring full) is
// reported as a gap before the next payload of that direction, and the
// connection keeps working.
func TestUnsentPayloadBecomesGap(t *testing.T) {
	dir, cmd := startMockdCmd(t, "1")
	c, err := Dial(dir, Options{C2SSize: 64 << 10, S2CSize: 64 << 10})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	conn, err := c.Open(OpenParams{Src: netip.MustParseAddrPort("198.51.100.1:40000"), Dst: netip.MustParseAddrPort("10.0.0.1:443")})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if v, err := conn.Inspect(ctx, ToServer, []byte("GET / HTTP/1.1\r\n")); err != nil || v.Action != Pass {
		t.Fatalf("before: %+v %v", v, err)
	}
	gaps := func() uint64 {
		conn.gapMu.Lock()
		defer conn.gapMu.Unlock()
		return conn.gaps[ToServer]
	}
	// The data does not fit while the server is stopped; the (small) GAP
	// record for it is queued right away.
	_ = cmd.Process.Signal(syscall.SIGSTOP)
	short, cancelShort := context.WithTimeout(context.Background(), 50*time.Millisecond)
	err = conn.Send(short, ToServer, bytes.Repeat([]byte("x"), 256<<10))
	cancelShort()
	_ = cmd.Process.Signal(syscall.SIGCONT)
	if !errors.Is(err, context.DeadlineExceeded) || gaps() != 0 {
		t.Fatalf("send to a stalled server: %v, pending gap %d", err, gaps())
	}
	// A gap that could not be queued goes out before the next payload.
	conn.gapMu.Lock()
	conn.gaps[ToServer] = 1000
	conn.gapMu.Unlock()
	if v, err := conn.Inspect(ctx, ToServer, []byte("after")); err != nil || v.Action != Pass {
		t.Fatalf("after: %+v %v", v, err)
	}
	if gaps() != 0 {
		t.Fatalf("pending gap not reported: %d", gaps())
	}
}

func TestInteropWithRustServer(t *testing.T) {
	dir := startMockd(t, "2")
	c, err := Dial(dir, Options{Name: "go-test", C2SSize: 64 << 10, S2CSize: 64 << 10})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.Workers() != 2 {
		t.Fatalf("workers = %d", c.Workers())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := c.Ping(ctx, 1); err != nil {
		t.Fatal(err)
	}

	workers := map[int]bool{}
	for i := range 16 {
		src := netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, 100, byte(i + 1)}), uint16(40000+i))
		if i%2 == 1 {
			src = netip.MustParseAddrPort("[2001:db8:9::1]:40001")
		}
		dst := netip.MustParseAddrPort("10.0.0.1:443")
		if src.Addr().Is6() {
			dst = netip.MustParseAddrPort("[2001:db8:1::1]:443")
		}
		conn, err := c.Open(OpenParams{Src: src, Dst: dst, Meta: []Meta{{MetaSNI, "go.example"}}})
		if err != nil {
			t.Fatal(err)
		}
		workers[conn.Worker()] = true
		v, err := conn.Inspect(ctx, ToServer, []byte("GET / HTTP/1.1\r\n\r\n"))
		if err != nil || v.Action != Pass || v.CID != conn.CID() {
			t.Fatalf("benign: %+v %v", v, err)
		}
		// Larger than a record and than the ring: splitting and back pressure.
		big := bytes.Repeat([]byte("x"), 300_000)
		if v, err := conn.Inspect(ctx, ToClient, big); err != nil || v.Action != Pass {
			t.Fatalf("big: %+v %v", v, err)
		}
		v, err = conn.Inspect(ctx, ToServer, []byte("GET /SURITAP-TEST-DROP HTTP/1.1\r\n\r\n"))
		if err != nil || !v.Dropped() || v.Reason != ReasonRule || len(v.Alerts) != 1 {
			t.Fatalf("drop: %+v %v", v, err)
		}
		if err := conn.Close(false); err != nil {
			t.Fatal(err)
		}
	}
	if len(workers) != 2 {
		t.Fatalf("connections were not spread over workers: %v", workers)
	}

	// Concurrent requests on one session.
	conn, err := c.Open(OpenParams{Src: netip.MustParseAddrPort("198.51.100.200:1"), Dst: netip.MustParseAddrPort("10.0.0.1:443")})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 300 {
				if v, err := conn.Inspect(ctx, ToServer, []byte("ping")); err != nil || v.Action != Pass {
					t.Errorf("concurrent: %+v %v", v, err)
					return
				}
			}
		}()
	}
	wg.Wait()

	// Close while the ring is full: the CLOSE is queued, then flushed.
	conn.s.mu.Lock()
	var h [dataFixed]byte
	dataHeader(&h, 0, ToServer, 0) // unknown cid, no verdict wanted: no reply
	for conn.s.tx.push(kData, 0, h[:], make([]byte, 8000)) {
	}
	conn.s.tx.publish()
	conn.s.mu.Unlock()
	victim := &Conn{s: conn.s, cid: 424242} // same (full) session
	if err := victim.Close(false); err != nil {
		t.Fatal(err)
	}
	if !victim.s.pendingCloses() {
		t.Log("ring drained before the check; queueing path not observed")
	}
	deadline := time.Now().Add(2 * time.Second)
	for victim.s.pendingCloses() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if victim.s.pendingCloses() {
		t.Fatal("queued CLOSE was not flushed")
	}

	unknown := &Conn{s: conn.s, cid: 1}
	if v, err := unknown.Inspect(ctx, ToServer, []byte("x")); err != nil || v.Action != Error || v.Reason != ReasonUnknownFlow {
		t.Fatalf("unknown flow: %+v %v", v, err)
	}
}

func TestServerGoneFailsFast(t *testing.T) {
	bin := mockd(t)
	dir, _ := os.MkdirTemp("", "stap")
	defer os.RemoveAll(dir)
	cmd := exec.Command(bin, "--dir", dir)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	for range 100 {
		if _, err := os.Stat(SocketPath(dir, 0)); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	c, err := Dial(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	conn, err := c.Open(OpenParams{Src: netip.MustParseAddrPort("1.2.3.4:5"), Dst: netip.MustParseAddrPort("10.0.0.1:443")})
	if err != nil {
		t.Fatal(err)
	}
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	_, err = conn.Inspect(ctx, ToServer, []byte("x"))
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("err = %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("did not fail fast")
	}
}

// The endpoint policy of the plugin reaches the client and follows file
// changes; endpoints it does not list are unknown.
func TestEndpointPolicy(t *testing.T) {
	pf := filepath.Join(t.TempDir(), "policy")
	if err := os.WriteFile(pf, []byte("websecure prevent\napi detect\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dir, _ := startMockdCmd(t, "2", "--policy-file", pf)
	c, err := Dial(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	waitMode := func(ep string, want EndpointMode) {
		t.Helper()
		for range 300 {
			if m, ok := c.EndpointMode(ep); ok && m == want {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		m, ok := c.EndpointMode(ep)
		t.Fatalf("%s: mode %v (%v), want %v", ep, m, ok, want)
	}
	waitMode("websecure", ModePrevent)
	waitMode("api", ModeDetect)
	if _, ok := c.EndpointMode("other"); ok {
		t.Fatal("unlisted endpoint has a mode")
	}
	if err := os.WriteFile(pf, []byte("websecure off\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	waitMode("websecure", ModeOff)
	if _, ok := c.EndpointMode("api"); ok {
		t.Fatal("removed endpoint still has a mode")
	}
}
