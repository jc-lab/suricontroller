package yaegi

import (
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestPluginLoadUnderYaegi drives the interpreted middleware concurrently
// and reports latency; SURITAP_LOAD_DIR may point at a running Suricata.
func TestPluginLoadUnderYaegi(t *testing.T) {
	dir := os.Getenv("SURITAP_LOAD_DIR")
	if dir == "" {
		dir, _ = startMockd(t)
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") })
	out := &syncBuffer{}
	h := newPlugin(t, next, map[string]any{"SocketDir": dir, "Timeout": "1s"}, out)
	var mu sync.Mutex
	var lat []time.Duration
	var wg sync.WaitGroup
	start := time.Now()
	for c := 0; c < 16; c++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 300; i++ {
				t0 := time.Now()
				w := get(t, h, "GET", "/hello", "")
				d := time.Since(t0)
				if w.Code != 200 {
					t.Errorf("status %d", w.Code)
				}
				mu.Lock()
				lat = append(lat, d)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	el := time.Since(start)
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	t.Logf("%d req in %v (%.0f/s) p50=%v p99=%v p999=%v max=%v", len(lat), el, float64(len(lat))/el.Seconds(),
		lat[len(lat)/2], lat[len(lat)*99/100], lat[len(lat)*999/1000], lat[len(lat)-1])
	s := out.String(true)
	if n := strings.Count(s, "no verdict"); n > 0 {
		t.Errorf("%d verdicts timed out:\n%s", n, firstLines(s, 5))
	}
}

func firstLines(s string, n int) string {
	lines := strings.SplitN(s, "\n", n+1)
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}
