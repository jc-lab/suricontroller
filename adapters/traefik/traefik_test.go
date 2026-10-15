//go:build linux

package suritaptraefik

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/jc-lab/suricontroller/pkg/suritap"
)

const marker = "SURITAP-TEST-DROP" // suritap-mockd drops packets containing it

func startMockd(t *testing.T) string {
	t.Helper()
	bin := os.Getenv("SURITAP_MOCKD")
	if bin == "" {
		_, file, _, _ := runtime.Caller(0)
		root := filepath.Join(filepath.Dir(file), "..", "..")
		for _, p := range []string{"tap/target/release/suritap-mockd", "tap/target/debug/suritap-mockd"} {
			if _, err := os.Stat(filepath.Join(root, p)); err == nil {
				bin = filepath.Join(root, p)
				break
			}
		}
	}
	if bin == "" {
		t.Skip("suritap-mockd not built (cargo build -p suritap in tap/)")
	}
	dir, err := os.MkdirTemp("", "stap")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "--dir", dir, "--workers", "2", "--max-segment", "4096")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		_ = cmd.Wait()
		os.RemoveAll(dir)
	})
	for range 100 {
		if _, err := os.Stat(suritap.SocketPath(dir, 1)); err == nil {
			return dir
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("mockd did not start")
	return ""
}

type backend struct {
	calls atomic.Int32
	reply string
}

func (b *backend) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b.calls.Add(1)
	if _, err := io.Copy(io.Discard, r.Body); err != nil {
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	w.Header().Set("Set-Cookie", "session=secret")
	_, _ = io.WriteString(w, b.reply)
}

func newServer(t *testing.T, h http.Handler) *httptest.Server {
	srv := httptest.NewUnstartedServer(h)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func do(t *testing.T, c *http.Client, method, url string, body io.Reader) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(method, url, body)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func middleware(t *testing.T, entryPoint string, cfg Config, next http.Handler) http.Handler {
	h, err := Middleware(WithEntryPoint(context.Background(), entryPoint), &cfg, next)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = Lookup(entryPoint).Close() })
	return h
}

func newTap(t *testing.T, cfg Config) *Tap {
	tap, err := New("tcp", &cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tap.Close() })
	return tap
}

// The patch build runs the plugin's HTTP logic over shared memory.
func TestMiddlewareSharedMemory(t *testing.T) {
	dir := startMockd(t)
	b := &backend{reply: "hello"}
	srv := newServer(t, middleware(t, "shm-websecure", Config{SocketDir: dir, MaxRequestBody: 64 << 10, Timeout: "2s"}, b))
	c := srv.Client()
	if resp, body := do(t, c, "GET", srv.URL+"/index.html", nil); resp.StatusCode != 200 || body != "hello" || resp.ProtoMajor != 2 {
		t.Fatalf("benign: %d %q %s", resp.StatusCode, body, resp.Proto)
	}
	if resp, _ := do(t, c, "GET", srv.URL+"/"+marker, nil); resp.StatusCode != 403 || resp.Header.Get("X-Suritap-Cid") == "" {
		t.Fatalf("attack: %d", resp.StatusCode)
	}
	big := bytes.Repeat([]byte("x"), 512<<10)
	copy(big[300<<10:], marker)
	if resp, _ := do(t, c, "POST", srv.URL+"/upload", bytes.NewReader(big)); resp.StatusCode != 403 {
		t.Fatalf("streamed body attack: %d", resp.StatusCode)
	}
	if b.calls.Load() != 2 {
		t.Fatalf("backend calls %d", b.calls.Load())
	}
	if Lookup("shm-websecure").client == nil {
		t.Fatal("shared-memory client not used")
	}
}

func TestFailPolicy(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "none")
	b := &backend{reply: "ok"}
	open := newServer(t, middleware(t, "fail-open", Config{SocketDir: missing}, b))
	if resp, _ := do(t, open.Client(), "GET", open.URL+"/", nil); resp.StatusCode != 200 {
		t.Fatalf("fail open: %d", resp.StatusCode)
	}
	closed := newServer(t, middleware(t, "fail-closed", Config{SocketDir: missing, FailPolicy: "closed"}, b))
	if resp, _ := do(t, closed.Client(), "GET", closed.URL+"/", nil); resp.StatusCode != 503 {
		t.Fatalf("fail closed: %d", resp.StatusCode)
	}
	if _, err := New("x", &Config{Mode: "bogus"}); err == nil {
		t.Fatal("invalid mode accepted")
	}
}

func TestTCPStream(t *testing.T) {
	dir := startMockd(t)
	tap := newTap(t, Config{SocketDir: dir, Timeout: "2s"})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan []byte, 1)
	errc := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		wc := tap.WrapConn("pg", c.(*net.TCPConn))
		defer wc.Close()
		buf := make([]byte, 64)
		n, err := wc.Read(buf)
		if err != nil {
			errc <- err
			return
		}
		got <- append([]byte(nil), buf[:n]...)
		if _, err := wc.Write([]byte("pong")); err != nil {
			errc <- err
			return
		}
		_, err = wc.Read(buf)
		errc <- err
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Write([]byte("ping"))
	if b := <-got; string(b) != "ping" {
		t.Fatalf("read %q", b)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "pong" {
		t.Fatalf("write path: %q %v", buf, err)
	}
	_, _ = c.Write([]byte("evil " + marker))
	if err := <-errc; !errors.Is(err, errBlocked) {
		t.Fatalf("second read: %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(buf); err == nil {
		t.Fatal("connection still open after a drop")
	}
}
