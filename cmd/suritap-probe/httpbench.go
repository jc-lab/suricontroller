//go:build linux

package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

// runHTTPBench measures request latency through a proxy (e.g. Traefik with
// and without suritap).
func runHTTPBench(args []string) int {
	fs := flag.NewFlagSet("httpbench", flag.ExitOnError)
	url := fs.String("url", "", "URL to request")
	connect := fs.String("connect", "", "dial this host:port instead of the URL host (like curl --resolve)")
	conns := fs.Int("c", 16, "concurrent clients")
	n := fs.Int("n", 20000, "total requests")
	h1 := fs.Bool("http1", false, "force HTTP/1.1 (default: HTTP/2 over TLS)")
	_ = fs.Parse(args)
	if *url == "" {
		fmt.Fprintln(os.Stderr, "-url is required")
		return 2
	}
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // benchmark against test certificates
		ForceAttemptHTTP2:   !*h1,
		MaxIdleConnsPerHost: *conns,
	}
	if *h1 {
		tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}
	if *connect != "" {
		d := &net.Dialer{}
		tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return d.DialContext(ctx, network, *connect)
		}
	}
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	jobs := make(chan struct{}, *n)
	for range *n {
		jobs <- struct{}{}
	}
	close(jobs)
	var mu sync.Mutex
	lat := make(hist, 0, *n)
	codes := map[int]int{}
	var errs int
	var wg sync.WaitGroup
	start := time.Now()
	for range *conns {
		wg.Add(1)
		go func() {
			defer wg.Done()
			local := make(hist, 0, *n / *conns + 1)
			for range jobs {
				t := time.Now()
				resp, err := client.Get(*url)
				if err != nil {
					mu.Lock()
					errs++
					mu.Unlock()
					continue
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				local = append(local, time.Since(t))
				mu.Lock()
				codes[resp.StatusCode]++
				mu.Unlock()
			}
			mu.Lock()
			lat = append(lat, local...)
			mu.Unlock()
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)
	if len(lat) == 0 {
		fmt.Fprintln(os.Stderr, "no successful requests")
		return 1
	}
	fmt.Printf("%d requests, %d clients, %v: %.0f req/s, status %v, errors %d\n", len(lat), *conns, elapsed.Round(time.Millisecond),
		float64(len(lat))/elapsed.Seconds(), codes, errs)
	fmt.Printf("latency: %s\n", lat)
	return 0
}
