package yaegi

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

const marker = "SURITAP-TEST-DROP" // suritap-mockd drops packets containing it

// TestStreamingUnderYaegi runs the paths that cross goroutines the way
// Traefik does: the reverse proxy's transport reads large request bodies
// (inspectBody, reqState) while the handler goroutine writes the response,
// and flushed responses in prevent mode.
func TestStreamingUnderYaegi(t *testing.T) {
	dir, _ := startMockd(t)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/events" {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "data: first\n\n")
			w.(http.Flusher).Flush()
			time.Sleep(300 * time.Millisecond)
			_, _ = io.WriteString(w, "data: last\n\n")
			return
		}
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer backend.Close()
	u, _ := url.Parse(backend.URL)
	proxy := httputil.NewSingleHostReverseProxy(u)
	proxy.FlushInterval = -1
	out := &syncBuffer{}
	h := newPlugin(t, proxy, map[string]any{"SocketDir": dir, "Timeout": "2s", "Response": "prevent", "MaxRequestBody": int64(64 << 10)}, out)
	front := httptest.NewServer(h)
	defer front.Close()

	benign := bytes.Repeat([]byte("a"), 300<<10)
	// The mock matches the marker per packet, so repeat it: whatever the
	// read sizes, some chunk holds a whole copy.
	evil := append(bytes.Repeat([]byte("a"), 200<<10), bytes.Repeat([]byte(marker), 6000)...)
	var wg sync.WaitGroup
	for c := 0; c < 8; c++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 5; i++ {
				resp, err := http.Post(front.URL+"/upload", "application/octet-stream", bytes.NewReader(benign))
				if err != nil {
					t.Error(err)
					return
				}
				b, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if resp.StatusCode != 200 || string(b) != "ok" {
					t.Errorf("benign streamed body: %d %q", resp.StatusCode, b)
				}
				resp, err = http.Post(front.URL+"/upload", "application/octet-stream", bytes.NewReader(evil))
				if err != nil {
					t.Error(err)
					return
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.StatusCode != 403 {
					t.Errorf("attack in streamed body: %d", resp.StatusCode)
				}
			}
		}()
	}
	wg.Wait()

	resp, err := http.Get(front.URL + "/events")
	if err != nil {
		t.Fatal(err)
	}
	first := make([]byte, len("data: first\n\n"))
	t0 := time.Now()
	if _, err := io.ReadFull(resp.Body, first); err != nil || time.Since(t0) > 200*time.Millisecond {
		t.Errorf("flushed event: %q %v after %v", first, err, time.Since(t0))
	}
	rest, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(rest) != "data: last\n\n" {
		t.Errorf("rest of the event stream: %q", rest)
	}
	if s := out.String(true); strings.Contains(s, "panic") || strings.Contains(s, "crashed") {
		t.Errorf("interpreter output:\n%s", s)
	}
}
