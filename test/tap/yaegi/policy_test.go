package yaegi

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestEndpointPolicyUnderYaegi checks the policy path (POLICY records read
// by the session goroutine, background session opening) in the
// interpreter: detect never blocks, off skips inspection.
func TestEndpointPolicyUnderYaegi(t *testing.T) {
	pf := filepath.Join(t.TempDir(), "policy")
	if err := os.WriteFile(pf, []byte("tap detect\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dir, _ := startMockd(t, "--policy-file", pf)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	out := &syncBuffer{}
	h := newPlugin(t, next, map[string]any{"SocketDir": dir, "Timeout": "2s"}, out)
	wait := func(want int, what string) {
		t.Helper()
		for i := 0; i < 300; i++ {
			if get(t, h, "GET", "/"+marker, "").Code == want {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("%s: never %d", what, want)
	}
	wait(200, "detect endpoint")
	if err := os.WriteFile(pf, []byte("tap prevent\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	wait(403, "prevent endpoint")
	if err := os.WriteFile(pf, []byte("tap off\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	wait(200, "off endpoint")
	if s := out.String(true); strings.Contains(s, "panic") || strings.Contains(s, "crashed") {
		t.Errorf("interpreter output:\n%s", s)
	}
}
