package yaegi

import (
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// silentServer accepts socket-transport sessions (one worker) and never
// answers with a verdict.
func silentServer(t *testing.T) string {
	dir, _ := os.MkdirTemp("", "stap")
	t.Cleanup(func() { os.RemoveAll(dir) })
	l, err := net.Listen("unix", filepath.Join(dir, "worker-0.stream.sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				hello := make([]byte, 64)
				if _, err := io.ReadFull(c, hello); err != nil {
					return
				}
				w := make([]byte, 64)
				binary.LittleEndian.PutUint32(w[0:], 0x50415453)
				binary.LittleEndian.PutUint16(w[4:], 1)
				binary.LittleEndian.PutUint16(w[10:], 1)     // workers
				binary.LittleEndian.PutUint32(w[12:], 65536) // max payload
				if _, err := c.Write(w); err != nil {
					return
				}
				_, _ = io.Copy(io.Discard, c)
			}()
		}
	}()
	return dir
}

// TestVerdictTimeoutUnderYaegi checks that waiting for a verdict is bounded
// by the timeout under the interpreter (context.AfterFunc, no select) for
// concurrent requests.
func TestVerdictTimeoutUnderYaegi(t *testing.T) {
	dir := silentServer(t)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") })
	out := &syncBuffer{}
	h := newPlugin(t, next, map[string]any{"SocketDir": dir, "Timeout": "50ms", "FailPolicy": "closed"}, out)
	var wg sync.WaitGroup
	start := time.Now()
	for c := 0; c < 16; c++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 5; i++ {
				t0 := time.Now()
				w := get(t, h, "GET", "/hello", "")
				if d := time.Since(t0); w.Code != http.StatusServiceUnavailable || d < 40*time.Millisecond || d > time.Second {
					t.Errorf("status %d after %v", w.Code, d)
				}
			}
		}()
	}
	wg.Wait()
	if el := time.Since(start); el > 3*time.Second {
		t.Errorf("80 timed-out requests took %v", el)
	}
	if s := out.String(true); !containsAll(s, "no verdict", "context deadline exceeded") {
		t.Errorf("timeouts not logged:\n%s", firstLines(s, 5))
	}
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}
