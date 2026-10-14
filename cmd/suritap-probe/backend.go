//go:build linux

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
)

// runBackend serves the upstreams of the proxy tests: an HTTP server that
// counts requests per path (GET /__stats) and a TCP echo server.
func runBackend(args []string) int {
	fs := flag.NewFlagSet("backend", flag.ExitOnError)
	httpAddr := fs.String("http", "127.0.0.1:18080", "HTTP listen address")
	tcpAddr := fs.String("tcp", "127.0.0.1:18081", "TCP echo listen address")
	_ = fs.Parse(args)

	var mu sync.Mutex
	hits := map[string]int{}
	mux := http.NewServeMux()
	mux.HandleFunc("/__stats", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		_ = json.NewEncoder(w).Encode(hits)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		n, err := io.Copy(io.Discard, r.Body)
		mu.Lock()
		hits[r.URL.Path]++
		mu.Unlock()
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		switch r.URL.Path {
		case "/leak":
			_, _ = io.WriteString(w, "account=1 SECRET-LEAK token=abc\n")
		default:
			fmt.Fprintf(w, "hello from backend (%s %s, %d body bytes)\n", r.Method, r.URL.Path, n)
		}
	})
	go func() {
		if err := http.ListenAndServe(*httpAddr, mux); err != nil { //nolint:gosec // test backend
			fmt.Fprintln(os.Stderr, "http:", err)
			os.Exit(1)
		}
	}()
	ln, err := net.Listen("tcp", *tcpAddr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "tcp:", err)
		return 1
	}
	fmt.Println("backend ready")
	for {
		c, err := ln.Accept()
		if err != nil {
			return 1
		}
		go func() {
			defer c.Close()
			_, _ = io.Copy(c, c)
		}()
	}
}
