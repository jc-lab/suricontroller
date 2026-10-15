//go:build linux

package main

import (
	"context"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jc-lab/suricontroller/pkg/suritap"
)

func netipPort(a netip.AddrPort, port uint16) netip.AddrPort {
	return netip.AddrPortFrom(a.Addr(), port)
}

type hist []time.Duration

func (h hist) pct(p float64) time.Duration {
	if len(h) == 0 {
		return 0
	}
	return h[min(len(h)-1, int(float64(len(h))*p))]
}

func (h hist) String() string {
	slices.Sort(h)
	return fmt.Sprintf("p50=%v p90=%v p99=%v p99.9=%v max=%v", h.pct(0.5), h.pct(0.9), h.pct(0.99), h.pct(0.999), h[len(h)-1])
}

func runBench(args []string) int {
	fs := flag.NewFlagSet("bench", flag.ExitOnError)
	conns := fs.Int("conns", 16, "concurrent connections (one goroutine each)")
	reqs := fs.Int("requests", 2000, "request/response pairs per connection")
	size := fs.Int("size", 512, "approximate request size in bytes")
	respSize := fs.Int("response", 1024, "response body size (sent without waiting for a verdict)")
	pings := fs.Int("pings", 5000, "transport-only round trips (0 to skip)")
	trace := fs.Int("trace", 0, "print the latency of the first N requests of connection 0")
	c, done := dial(fs, args)
	defer done()
	ctx := context.Background()

	if *pings > 0 {
		h := make(hist, 0, *pings)
		for i := range *pings {
			d, err := c.Ping(ctx, i%c.Workers())
			if err != nil {
				fmt.Fprintln(os.Stderr, "ping:", err)
				return 1
			}
			h = append(h, d)
		}
		fmt.Printf("transport round trip (PING, no engine): %s\n", h)
	}

	pad := strings.Repeat("a", max(0, *size-120))
	resp := httpResp([]byte(strings.Repeat("r", *respSize)))
	var mu sync.Mutex
	all := make(hist, 0, *conns**reqs)
	var drops, errs int
	var wg sync.WaitGroup
	start := time.Now()
	for ci := range *conns {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := open(c, false)
			if err != nil {
				mu.Lock()
				errs++
				mu.Unlock()
				return
			}
			defer conn.Close(false)
			local := make(hist, 0, *reqs)
			d, e := 0, 0
			for i := range *reqs {
				req := httpReq("GET", fmt.Sprintf("/api/v1/items/%d", i), "X-Pad: "+pad+"\r\n", nil)
				t := time.Now()
				v, err := conn.Inspect(ctx, suritap.ToServer, req)
				local = append(local, time.Since(t))
				if err != nil {
					e++
					continue
				}
				if v.Action != suritap.Pass {
					d++
				}
				if err := conn.Send(ctx, suritap.ToClient, resp); err != nil {
					e++
				}
			}
			if ci == 0 && *trace > 0 {
				for i, d := range local[:min(*trace, len(local))] {
					fmt.Printf("req %d: %v\n", i, d)
				}
			}
			mu.Lock()
			all = append(all, local...)
			drops += d
			errs += e
			mu.Unlock()
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)
	if len(all) == 0 {
		fmt.Fprintln(os.Stderr, "no requests completed")
		return 1
	}
	fmt.Printf("requests: %d over %d connections in %v (%.0f req/s, %d workers)\n", len(all), *conns, elapsed.Round(time.Millisecond),
		float64(len(all))/elapsed.Seconds(), c.Workers())
	fmt.Printf("request verdict latency: %s\n", all)
	fmt.Printf("non-pass verdicts: %d, errors: %d\n", drops, errs)
	if errs > 0 {
		return 1
	}
	return 0
}
