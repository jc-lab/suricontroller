// Package suritap is the Go client of the suritap transport: it streams
// plaintext from a TLS-terminating proxy to the Suricata suritap capture
// plugin and returns per-request verdicts.
//
// The client opens one session per Suricata worker. A session is a sealed
// memfd shared with Suricata that holds two single-producer/single-consumer
// rings (requests and verdicts) and two eventfds used only to wake a
// sleeping peer; the UNIX socket carries the handshake and liveness. The
// wire format is specified in docs/suritap.md and implemented on the
// server side by the Rust crate in tap/suritap.
//
//	c, _ := suritap.Dial("/run/suritap", suritap.Options{Name: "traefik"})
//	conn, _ := c.Open(suritap.OpenParams{Src: clientAddr, Dst: listenerAddr})
//	v, err := conn.Inspect(ctx, suritap.ToServer, requestBytes)
//	if err == nil && v.Action == suritap.Drop { /* block */ }
//	conn.Close(false)
//
// The package is Linux only.
package suritap
