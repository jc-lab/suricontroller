// Package yaegi runs the Traefik plugin (adapters/traefik-plugin) under the
// same interpreter and call path as Traefik's plugin loader, against
// suritap-mockd, to catch constructs Yaegi cannot run.
package yaegi

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/traefik/yaegi/interp"
	"github.com/traefik/yaegi/stdlib"
)

const module = "github.com/jc-lab/suricontroller/adapters/traefik-plugin"

func repoRoot() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "..")
}

// gopath lays the plugin out like Traefik's plugins-local directory.
func gopath(t *testing.T) string {
	root := t.TempDir()
	dst := filepath.Join(root, "src", module)
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(repoRoot(), "adapters", "traefik-plugin")
	entries, _ := os.ReadDir(src)
	for _, e := range entries {
		n := e.Name()
		if strings.HasSuffix(n, "_test.go") || (!strings.HasSuffix(n, ".go") && n != "go.mod" && n != ".traefik.yml") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(src, n))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, n), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func startMockd(t *testing.T, extra ...string) (string, *exec.Cmd) {
	bin := os.Getenv("SURITAP_MOCKD")
	if bin == "" {
		for _, p := range []string{"tap/target/release/suritap-mockd", "tap/target/debug/suritap-mockd"} {
			if _, err := os.Stat(filepath.Join(repoRoot(), p)); err == nil {
				bin = filepath.Join(repoRoot(), p)
				break
			}
		}
	}
	if bin == "" {
		t.Skip("suritap-mockd not built")
	}
	dir, _ := os.MkdirTemp("", "stap")
	t.Cleanup(func() { os.RemoveAll(dir) })
	cmd := exec.Command(bin, append([]string{"--dir", dir, "--workers", "2"}, extra...)...)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	for range 100 {
		if _, err := os.Stat(filepath.Join(dir, "worker-1.stream.sock")); err == nil {
			return dir, cmd
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("mockd did not start")
	return "", nil
}

// syncBuffer collects the interpreter's output.
type syncBuffer struct {
	mu    sync.Mutex
	b     bytes.Buffer
	flush func()
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

// String returns the output so far; with final it first waits until the
// interpreter's output is drained (no output after that is kept).
func (s *syncBuffer) String(final ...bool) string {
	if len(final) > 0 && final[0] && s.flush != nil {
		s.flush()
		s.flush = nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// newPlugin builds the middleware like Traefik does: CreateConfig, set the
// fields by reflection, call New by reflection.
func newPlugin(t *testing.T, next http.Handler, fields map[string]any, out *syncBuffer) http.Handler {
	// Yaegi substitutes os.Stdout/os.Stderr only with *os.File streams.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.MultiWriter(out, os.Stdout), r)
		close(done)
	}()
	var once sync.Once
	out.flush = func() { once.Do(func() { _ = w.Close(); <-done; _ = r.Close() }) }
	t.Cleanup(out.flush)
	i := interp.New(interp.Options{GoPath: gopath(t), Stdout: w, Stderr: w})
	if err := i.Use(stdlib.Symbols); err != nil {
		t.Fatal(err)
	}
	if _, err := i.Eval(`import "` + module + `"`); err != nil {
		t.Fatal(err)
	}
	cfg, err := i.Eval(`suritap.CreateConfig()`)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range fields {
		cfg.Elem().FieldByName(k).Set(reflect.ValueOf(v))
	}
	fn, err := i.Eval(`suritap.New`)
	if err != nil {
		t.Fatal(err)
	}
	res := fn.Call([]reflect.Value{reflect.ValueOf(context.Background()), reflect.ValueOf(next), cfg, reflect.ValueOf("tap")})
	if e := res[1].Interface(); e != nil {
		t.Fatal(e)
	}
	return res[0].Interface().(http.Handler)
}

func get(t *testing.T, h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "https://app.example"+path, strings.NewReader(body))
	req.RemoteAddr = "203.0.113.7:40000"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestPluginUnderYaegi(t *testing.T) {
	dir, mockd := startMockd(t)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = io.WriteString(w, "ok")
	})
	out := &syncBuffer{}
	h := newPlugin(t, next, map[string]any{"SocketDir": dir, "Timeout": "2s", "Response": "prevent"}, out)
	defer func() {
		// Interpreter crashes are recovered by the plugin but must not happen.
		if s := out.String(true); strings.Contains(s, "panic") || strings.Contains(s, "crashed") {
			t.Errorf("interpreter output:\n%s", s)
		}
	}()
	if w := get(t, h, "GET", "/", ""); w.Code != 200 || w.Body.String() != "ok" {
		t.Fatalf("benign: %d %q", w.Code, w.Body.String())
	}
	if w := get(t, h, "GET", "/SURITAP-TEST-DROP", ""); w.Code != 403 || w.Header().Get("X-Suritap-Cid") == "" {
		t.Fatalf("attack: %d", w.Code)
	}
	if w := get(t, h, "POST", "/upload", strings.Repeat("a", 200000)+"SURITAP-TEST-DROP"); w.Code != 403 {
		t.Fatalf("streamed body attack: %d", w.Code)
	}
	for range 50 {
		if w := get(t, h, "GET", "/x", ""); w.Code != 200 {
			t.Fatalf("loop: %d", w.Code)
		}
	}
	// Suricata goes away: the session must fail cleanly (fail open).
	_ = mockd.Process.Signal(syscall.SIGKILL)
	_ = mockd.Wait()
	time.Sleep(100 * time.Millisecond)
	for range 3 {
		if w := get(t, h, "GET", "/after", ""); w.Code != 200 {
			t.Fatalf("after Suricata stopped: %d", w.Code)
		}
	}
	if s := out.String(true); !strings.Contains(s, "blocked request") || !strings.Contains(s, "cannot reach Suricata") {
		t.Errorf("plugin log lines not captured:\n%s", s)
	}
}
