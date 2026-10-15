//go:build linux

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/jc-lab/suricontroller/pkg/suritap"
)

// runInspect sends one payload on one connection, the way a proxy adapter
// would, and prints the endpoint's mode from the plugin's policy and the
// verdict as JSON (for diagnostics and the docker integration test).
func runInspect(args []string) int {
	fs := flag.NewFlagSet("inspect", flag.ExitOnError)
	endpoint := fs.String("endpoint", "", "endpoint name sent in OPEN (meta tag endpoint)")
	data := fs.String("data", "GET / HTTP/1.1\r\nHost: probe.example\r\n\r\n", "payload (client to server)")
	src := fs.String("src", "198.51.100.7:40000", "client address")
	dst := fs.String("dst", "10.0.0.10:443", "listener address")
	wait := fs.Duration("policy-wait", 3*time.Second, "how long to wait for the endpoint policy")
	timeout := fs.Duration("timeout", 2*time.Second, "verdict timeout")
	c, done := dial(fs, args)
	defer done()

	out := map[string]any{"endpoint": *endpoint}
	deadline := time.Now().Add(*wait)
	for *endpoint != "" {
		if m, ok := c.EndpointMode(*endpoint); ok {
			out["mode"] = m.String()
			break
		}
		if time.Now().After(deadline) {
			out["mode"] = "unlisted"
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if p := c.Policy(); p != nil {
		out["policy_version"] = p.Version
	}
	s, err := netip.ParseAddrPort(*src)
	if err != nil {
		fmt.Fprintln(os.Stderr, "src:", err)
		return 2
	}
	d, err := netip.ParseAddrPort(*dst)
	if err != nil {
		fmt.Fprintln(os.Stderr, "dst:", err)
		return 2
	}
	meta := []suritap.Meta{{Tag: suritap.MetaProxy, Value: "suritap-probe"}}
	if *endpoint != "" {
		meta = append(meta, suritap.Meta{Tag: suritap.MetaEndpoint, Value: *endpoint})
	}
	conn, err := c.Open(suritap.OpenParams{Src: s, Dst: d, Meta: meta})
	if err != nil {
		fmt.Fprintln(os.Stderr, "open:", err)
		return 1
	}
	defer conn.Close(false)
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	v, err := conn.Inspect(ctx, suritap.ToServer, []byte(*data))
	if err != nil {
		fmt.Fprintln(os.Stderr, "inspect:", err)
		return 1
	}
	out["cid"] = conn.CID()
	out["action"] = v.Action.String()
	out["reason"] = v.Reason.String()
	var sids []uint32
	for _, a := range v.Alerts {
		sids = append(sids, a.SID)
	}
	out["sids"] = sids
	_ = json.NewEncoder(os.Stdout).Encode(out)
	return 0
}
