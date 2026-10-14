//go:build linux

// Command suritap-probe exercises a Suricata instance running the suritap
// capture plugin: functional checks (check), a connection holder for crash
// tests (hold) and a latency/throughput benchmark (bench).
package main

import (
	"context"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/jc-lab/suricontroller/pkg/suritap"
)

func usage() {
	fmt.Fprintf(os.Stderr, `usage: suritap-probe <command> [flags]

commands:
  check   run functional scenarios (expects test/tap/tap.rules)
  bench   measure verdict latency and throughput
  hold    open connections and wait (for crash-cleanup tests)
  backend HTTP and TCP echo upstreams for proxy tests
  httpbench  HTTP latency/throughput through a proxy
`)
	os.Exit(2)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cmd, args := os.Args[1], os.Args[2:]
	switch cmd {
	case "check":
		os.Exit(runCheck(args))
	case "bench":
		os.Exit(runBench(args))
	case "hold":
		os.Exit(runHold(args))
	case "backend":
		os.Exit(runBackend(args))
	case "httpbench":
		os.Exit(runHTTPBench(args))
	default:
		usage()
	}
}

var srcPort atomic.Uint32

func init() { srcPort.Store(20000) }

// addrs returns a fresh client address and the listener address.
func addrs(v6 bool) (netip.AddrPort, netip.AddrPort) {
	port := uint16(20000 + srcPort.Add(1)%40000)
	if v6 {
		return netip.AddrPortFrom(netip.MustParseAddr("2001:db8:9::7"), port), netip.MustParseAddrPort("[2001:db8:1::10]:443")
	}
	return netip.AddrPortFrom(netip.MustParseAddr("203.0.113.7"), port), netip.MustParseAddrPort("10.0.0.10:443")
}

func dial(fs *flag.FlagSet, args []string) (*suritap.Client, func()) {
	dir := fs.String("dir", "/run/suritap", "suritap socket directory")
	name := fs.String("name", "suritap-probe", "client name reported to Suricata")
	spin := fs.Duration("spin", 0, "verdict reader busy-poll before sleeping")
	_ = fs.Parse(args)
	c, err := suritap.Dial(*dir, suritap.Options{Name: *name, Spin: *spin})
	if err != nil {
		fmt.Fprintln(os.Stderr, "dial:", err)
		os.Exit(1)
	}
	return c, func() { _ = c.Close() }
}

func runHold(args []string) int {
	fs := flag.NewFlagSet("hold", flag.ExitOnError)
	n := fs.Int("conns", 10, "connections to open")
	c, done := dial(fs, args)
	defer done()
	ctx := context.Background()
	for range *n {
		src, dst := addrs(false)
		conn, err := c.Open(suritap.OpenParams{Src: src, Dst: dst, Meta: []suritap.Meta{{Tag: suritap.MetaProxy, Value: "hold"}}})
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if _, err := conn.Inspect(ctx, suritap.ToServer, []byte("GET /hold HTTP/1.1\r\nHost: h\r\n\r\n")); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	}
	fmt.Println("holding", *n, "connections")
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	select {
	case <-sig:
	case <-time.After(10 * time.Minute):
	}
	return 0
}
