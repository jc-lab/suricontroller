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
	bin := mockd(t)
	// Keep the socket path short (sun_path is 108 bytes).
	dir, err := os.MkdirTemp("", "stap")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "--dir", dir, "--workers", workers, "--max-segment", "4096")
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		_ = cmd.Wait()
		os.RemoveAll(dir)
	})
	for range 100 {
		if _, err := os.Stat(SocketPath(dir, 0)); err == nil {
			return dir
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("mockd did not start")
	return ""
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
