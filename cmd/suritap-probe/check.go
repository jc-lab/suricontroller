//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"net/netip"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/jc-lab/suricontroller/pkg/suritap"
)

type scenario struct {
	name string
	run  func(ctx context.Context, c *suritap.Client) (string, error)
}

// Groups select scenarios: "default" runs against tap.rules, the others
// need a special engine configuration or rule set (see test/tap/run.sh).
var groups = map[string][]scenario{
	"default": {
		{"http-benign-ipv4", benign(false)},
		{"http-benign-ipv6", benign(true)},
		{"http-uri-drop-ipv4", uriDrop(false)},
		{"http-uri-drop-ipv6", uriDrop(true)},
		{"alert-only-passes-with-alert", alertOnly},
		{"reject-maps-to-drop", rejectRule},
		{"body-small-drop", bodySmall},
		{"body-streamed-timing", bodyStreamed},
		{"body-marker-in-last-chunk", bodyLastChunk},
		{"body-deep-marker", bodyDeep},
		{"body-large-records", bodyLargeRecords},
		{"response-body-drop", responseDrop},
		{"raw-stream-drop", rawStream},
		{"pgsql-query-drop", pgsqlDrop},
		{"http2-prior-knowledge-drop", http2Drop},
		{"flow-stays-dropped", flowStaysDropped},
		{"gap-then-data", gapThenData},
		{"bypass-after-depth", bypassAfterDepth},
		{"keepalive-many-requests", keepAlive},
		{"tuple-reuse-after-drop", reuseAfterDrop},
		{"tuple-reuse-after-bypass", reuseAfterBypass},
	},
	"reload-before": {{"reloaded-rule-absent", reloaded(false)}},
	"reload-after":  {{"reloaded-rule-active", reloaded(true)}},
	"exception":     {{"exception-policy-drop", exceptionPolicy}},
}

func runCheck(args []string) int {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	group := fs.String("group", "default", "scenario group: default, reload-before, reload-after, exception")
	only := fs.String("only", "", "run only scenarios whose name contains this")
	c, done := dial(fs, args)
	defer done()
	list, ok := groups[*group]
	if !ok {
		fmt.Fprintln(os.Stderr, "unknown group", *group)
		return 2
	}
	failed := 0
	for _, s := range list {
		if *only != "" && !strings.Contains(s.name, *only) {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		detail, err := s.run(ctx, c)
		cancel()
		if err != nil {
			failed++
			fmt.Printf("FAIL %-32s %v\n", s.name, err)
		} else {
			fmt.Printf("PASS %-32s %s\n", s.name, detail)
		}
	}
	if failed > 0 {
		fmt.Printf("%d scenario(s) failed\n", failed)
		return 1
	}
	return 0
}

func open(c *suritap.Client, v6 bool, meta ...suritap.Meta) (*suritap.Conn, error) {
	src, dst := addrs(v6)
	return c.Open(suritap.OpenParams{Src: src, Dst: dst, Meta: append(meta, suritap.Meta{Tag: suritap.MetaSNI, Value: "probe.example"})})
}

// openAt opens a connection from a fixed client port (to reuse a 5-tuple).
func openAt(c *suritap.Client, port uint16) (*suritap.Conn, error) {
	_, dst := addrs(false)
	src := netip.AddrPortFrom(netip.MustParseAddr("203.0.113.99"), port)
	return c.Open(suritap.OpenParams{Src: src, Dst: dst})
}

func describe(v suritap.Verdict) string {
	var sids []string
	for _, a := range v.Alerts {
		sids = append(sids, fmt.Sprintf("%d(act=%#x)", a.SID, a.Action))
	}
	s := fmt.Sprintf("action=%s reason=%s", v.Action, v.Reason)
	if v.DropReason != 0 {
		s += fmt.Sprintf(" drop_reason=%d", v.DropReason)
	}
	if len(sids) > 0 {
		s += " alerts=" + strings.Join(sids, ",")
	}
	return s
}

func expect(v suritap.Verdict, action suritap.Action, sid uint32) error {
	if v.Action != action {
		return fmt.Errorf("want %s, got %s", action, describe(v))
	}
	if sid == 0 {
		return nil
	}
	for _, a := range v.Alerts {
		if a.SID == sid {
			return nil
		}
	}
	return fmt.Errorf("sid %d missing: %s", sid, describe(v))
}

func httpReq(method, path, extra string, body []byte) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\nHost: probe.example\r\nUser-Agent: suritap-probe\r\n%s", method, path, extra)
	if body != nil {
		fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
	}
	b.WriteString("\r\n")
	b.Write(body)
	return b.Bytes()
}

func httpResp(body []byte) []byte {
	return append([]byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n", len(body))), body...)
}

func benign(v6 bool) func(context.Context, *suritap.Client) (string, error) {
	return func(ctx context.Context, c *suritap.Client) (string, error) {
		conn, err := open(c, v6)
		if err != nil {
			return "", err
		}
		defer conn.Close(false)
		v, err := conn.Inspect(ctx, suritap.ToServer, httpReq("GET", "/index.html", "", nil))
		if err != nil {
			return "", err
		}
		if err := expect(v, suritap.Pass, 0); err != nil {
			return "", err
		}
		r, err := conn.Inspect(ctx, suritap.ToClient, httpResp([]byte("hello")))
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("request %s, response %s, worker %d", describe(v), describe(r), conn.Worker()), expect(r, suritap.Pass, 0)
	}
}

func uriDrop(v6 bool) func(context.Context, *suritap.Client) (string, error) {
	return func(ctx context.Context, c *suritap.Client) (string, error) {
		conn, err := open(c, v6)
		if err != nil {
			return "", err
		}
		defer conn.Close(true)
		v, err := conn.Inspect(ctx, suritap.ToServer, httpReq("GET", "/cgi-bin/../../etc/passwd", "", nil))
		if err != nil {
			return "", err
		}
		return describe(v), errors.Join(expect(v, suritap.Drop, 9000001), wantReason(v, suritap.ReasonRule))
	}
}

func wantReason(v suritap.Verdict, r suritap.Reason) error {
	if v.Reason != r {
		return fmt.Errorf("reason %s, want %s", v.Reason, r)
	}
	return nil
}

func alertOnly(ctx context.Context, c *suritap.Client) (string, error) {
	conn, err := open(c, false)
	if err != nil {
		return "", err
	}
	defer conn.Close(false)
	v, err := conn.Inspect(ctx, suritap.ToServer, httpReq("GET", "/alert-only", "", nil))
	if err != nil {
		return "", err
	}
	return describe(v), expect(v, suritap.Pass, 9000004)
}

func rejectRule(ctx context.Context, c *suritap.Client) (string, error) {
	conn, err := open(c, false)
	if err != nil {
		return "", err
	}
	defer conn.Close(true)
	req := []byte("GET / HTTP/1.1\r\nHost: probe.example\r\nUser-Agent: reject-me\r\n\r\n")
	v, err := conn.Inspect(ctx, suritap.ToServer, req)
	if err != nil {
		return "", err
	}
	if err := expect(v, suritap.Drop, 9000003); err != nil {
		return "", err
	}
	for _, a := range v.Alerts {
		if a.SID == 9000003 && a.Action&0x1c == 0 {
			return "", fmt.Errorf("alert action %#x lacks the reject bit", a.Action)
		}
	}
	return describe(v), nil
}

func bodySmall(ctx context.Context, c *suritap.Client) (string, error) {
	conn, err := open(c, false)
	if err != nil {
		return "", err
	}
	defer conn.Close(true)
	v, err := conn.Inspect(ctx, suritap.ToServer, httpReq("POST", "/upload", "Content-Type: text/plain\r\n", []byte("hello EVIL-BODY-MARKER world")))
	if err != nil {
		return "", err
	}
	return describe(v), expect(v, suritap.Drop, 9000002)
}

// bodyStreamed sends a 96 KiB body in 4 KiB chunks with the marker in the
// first chunk and reports after how many body bytes the verdict turns
// into a drop (governed by request-body-minimal-inspect-size).
func bodyStreamed(ctx context.Context, c *suritap.Client) (string, error) {
	conn, err := open(c, false)
	if err != nil {
		return "", err
	}
	defer conn.Close(true)
	const total, chunk = 96 << 10, 4 << 10
	hdr := fmt.Sprintf("POST /upload HTTP/1.1\r\nHost: probe.example\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\n\r\n", total)
	v, err := conn.Inspect(ctx, suritap.ToServer, []byte(hdr))
	if err != nil {
		return "", err
	}
	if v.Action != suritap.Pass {
		return "", fmt.Errorf("headers: %s", describe(v))
	}
	body := bytes.Repeat([]byte("a"), total)
	copy(body[100:], "EVIL-BODY-MARKER")
	for off := 0; off < total; off += chunk {
		v, err := conn.Inspect(ctx, suritap.ToServer, body[off:off+chunk])
		if err != nil {
			return "", err
		}
		if v.Action == suritap.Drop {
			return fmt.Sprintf("marker at body offset 100 dropped after %d of %d body bytes (%s)", off+chunk, total, describe(v)),
				expect(v, suritap.Drop, 9000002)
		}
	}
	return "", errors.New("never dropped")
}

func bodyLastChunk(ctx context.Context, c *suritap.Client) (string, error) {
	conn, err := open(c, false)
	if err != nil {
		return "", err
	}
	defer conn.Close(true)
	const total, chunk = 20 << 10, 4 << 10
	body := bytes.Repeat([]byte("b"), total)
	copy(body[total-40:], "EVIL-BODY-MARKER")
	hdr := fmt.Sprintf("POST /upload HTTP/1.1\r\nHost: probe.example\r\nContent-Length: %d\r\n\r\n", total)
	if _, err := conn.Inspect(ctx, suritap.ToServer, []byte(hdr)); err != nil {
		return "", err
	}
	for off := 0; off < total; off += chunk {
		v, err := conn.Inspect(ctx, suritap.ToServer, body[off:off+chunk])
		if err != nil {
			return "", err
		}
		if v.Action == suritap.Drop && off+chunk < total {
			return "", fmt.Errorf("dropped early at %d", off+chunk)
		}
		if off+chunk == total {
			return fmt.Sprintf("dropped when the request completed (%s)", describe(v)), expect(v, suritap.Drop, 9000002)
		}
	}
	return "", errors.New("unreachable")
}

// bodyDeep puts the marker 300 KiB into a 600 KiB upload: inspection must
// keep up with the body (the engine needs timely ACKs for that).
func bodyDeep(ctx context.Context, c *suritap.Client) (string, error) {
	conn, err := open(c, false)
	if err != nil {
		return "", err
	}
	defer conn.Close(true)
	const total, chunk, at = 600 << 10, 16 << 10, 300 << 10
	body := bytes.Repeat([]byte("d"), total)
	copy(body[at:], "EVIL-BODY-MARKER")
	hdr := fmt.Sprintf("POST /upload HTTP/1.1\r\nHost: probe.example\r\nContent-Length: %d\r\n\r\n", total)
	if _, err := conn.Inspect(ctx, suritap.ToServer, []byte(hdr)); err != nil {
		return "", err
	}
	for off := 0; off < total; off += chunk {
		v, err := conn.Inspect(ctx, suritap.ToServer, body[off:off+chunk])
		if err != nil {
			return "", err
		}
		if v.Action == suritap.Drop {
			if off+chunk-at > chunk {
				return "", fmt.Errorf("dropped late: %d bytes after the marker", off+chunk-at)
			}
			return fmt.Sprintf("marker at 300 KiB dropped in the chunk that carried it (%s)", describe(v)), expect(v, suritap.Drop, 9000002)
		}
	}
	return "", errors.New("never dropped")
}

// bodyLargeRecords sends the whole body in one Inspect, i.e. in records of
// the largest size the transport allows (each split into several
// segments by the engine): ACKs must still come every ack-threshold bytes,
// or Suricata prunes the uninspected body (§7.5).
func bodyLargeRecords(ctx context.Context, c *suritap.Client) (string, error) {
	conn, err := open(c, false)
	if err != nil {
		return "", err
	}
	defer conn.Close(true)
	const total, at = 600 << 10, 300 << 10
	body := bytes.Repeat([]byte("d"), total)
	copy(body[at:], "EVIL-BODY-MARKER")
	req := append([]byte(fmt.Sprintf("POST /upload HTTP/1.1\r\nHost: probe.example\r\nContent-Length: %d\r\n\r\n", total)), body...)
	v, err := conn.Inspect(ctx, suritap.ToServer, req)
	if err != nil {
		return "", err
	}
	return "marker at 300 KiB of a body sent in one Inspect: " + describe(v), expect(v, suritap.Drop, 9000002)
}

func responseDrop(ctx context.Context, c *suritap.Client) (string, error) {
	conn, err := open(c, false)
	if err != nil {
		return "", err
	}
	defer conn.Close(true)
	if v, err := conn.Inspect(ctx, suritap.ToServer, httpReq("GET", "/report", "", nil)); err != nil || v.Action != suritap.Pass {
		return "", fmt.Errorf("request: %s %v", describe(v), err)
	}
	v, err := conn.Inspect(ctx, suritap.ToClient, httpResp([]byte("account=1 SECRET-LEAK token=abc")))
	if err != nil {
		return "", err
	}
	return describe(v), expect(v, suritap.Drop, 9000006)
}

func rawStream(ctx context.Context, c *suritap.Client) (string, error) {
	conn, err := open(c, false)
	if err != nil {
		return "", err
	}
	defer conn.Close(true)
	v, err := conn.Inspect(ctx, suritap.ToServer, []byte("\x01\x02binary-proto RAW-STREAM-EVIL \x00\x00"))
	if err != nil {
		return "", err
	}
	return describe(v), expect(v, suritap.Drop, 9000007)
}

func pgMsg(typ byte, payload []byte) []byte {
	b := []byte{typ, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(b[1:], uint32(4+len(payload)))
	return append(b, payload...)
}

func pgsqlDrop(ctx context.Context, c *suritap.Client) (string, error) {
	src, dst := addrs(false)
	conn, err := c.Open(suritap.OpenParams{Src: src, Dst: netipPort(dst, 5432), Meta: []suritap.Meta{{Tag: suritap.MetaProto, Value: "pgsql"}}})
	if err != nil {
		return "", err
	}
	defer conn.Close(true)
	params := []byte("user\x00app\x00database\x00shop\x00\x00")
	startup := make([]byte, 8, 8+len(params))
	binary.BigEndian.PutUint32(startup, uint32(8+len(params)))
	binary.BigEndian.PutUint32(startup[4:], 196608) // protocol 3.0
	startup = append(startup, params...)
	if v, err := conn.Inspect(ctx, suritap.ToServer, startup); err != nil || v.Action != suritap.Pass {
		return "", fmt.Errorf("startup: %s %v", describe(v), err)
	}
	var srv []byte
	srv = append(srv, pgMsg('R', []byte{0, 0, 0, 0})...)                   // AuthenticationOk
	srv = append(srv, pgMsg('S', []byte("server_version\x0017.0\x00"))...) // ParameterStatus
	srv = append(srv, pgMsg('K', []byte{0, 0, 0, 1, 0, 0, 0, 2})...)       // BackendKeyData
	srv = append(srv, pgMsg('Z', []byte{'I'})...)                          // ReadyForQuery
	if v, err := conn.Inspect(ctx, suritap.ToClient, srv); err != nil || v.Action != suritap.Pass {
		return "", fmt.Errorf("server hello: %s %v", describe(v), err)
	}
	if v, err := conn.Inspect(ctx, suritap.ToServer, pgMsg('Q', []byte("SELECT 1\x00"))); err != nil || v.Action != suritap.Pass {
		return "", fmt.Errorf("benign query: %s %v", describe(v), err)
	}
	var resp []byte
	resp = append(resp, pgMsg('T', []byte{0, 1, '?', 'c', 'o', 'l', 'u', 'm', 'n', '?', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 23, 0, 4, 255, 255, 255, 255, 0, 0})...)
	resp = append(resp, pgMsg('D', []byte{0, 1, 0, 0, 0, 1, '1'})...)
	resp = append(resp, pgMsg('C', []byte("SELECT 1\x00"))...)
	resp = append(resp, pgMsg('Z', []byte{'I'})...)
	if _, err := conn.Inspect(ctx, suritap.ToClient, resp); err != nil {
		return "", err
	}
	v, err := conn.Inspect(ctx, suritap.ToServer, pgMsg('Q', []byte("COPY pwn FROM PROGRAM 'id'\x00")))
	if err != nil {
		return "", err
	}
	return describe(v), expect(v, suritap.Drop, 9000005)
}

func http2Drop(ctx context.Context, c *suritap.Client) (string, error) {
	conn, err := open(c, false, suritap.Meta{Tag: suritap.MetaALPN, Value: "h2"})
	if err != nil {
		return "", err
	}
	defer conn.Close(true)
	frames := func(f func(fr *http2.Framer) error) ([]byte, error) {
		var buf bytes.Buffer
		if err := f(http2.NewFramer(&buf, nil)); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	}
	header := func(path string, stream uint32) func(fr *http2.Framer) error {
		return func(fr *http2.Framer) error {
			var hb bytes.Buffer
			enc := hpack.NewEncoder(&hb)
			for _, kv := range [][2]string{{":method", "GET"}, {":scheme", "https"}, {":authority", "probe.example"}, {":path", path}, {"user-agent", "suritap-probe"}} {
				if err := enc.WriteField(hpack.HeaderField{Name: kv[0], Value: kv[1]}); err != nil {
					return err
				}
			}
			return fr.WriteHeaders(http2.HeadersFrameParam{StreamID: stream, BlockFragment: hb.Bytes(), EndStream: true, EndHeaders: true})
		}
	}
	preface, err := frames(func(fr *http2.Framer) error { return fr.WriteSettings() })
	if err != nil {
		return "", err
	}
	first, err := frames(header("/ok", 1))
	if err != nil {
		return "", err
	}
	v, err := conn.Inspect(ctx, suritap.ToServer, append(append([]byte(http2.ClientPreface), preface...), first...))
	if err != nil || v.Action != suritap.Pass {
		return "", fmt.Errorf("preface: %s %v", describe(v), err)
	}
	srv, err := frames(func(fr *http2.Framer) error {
		if err := fr.WriteSettings(); err != nil {
			return err
		}
		return fr.WriteSettingsAck()
	})
	if err != nil {
		return "", err
	}
	if _, err := conn.Inspect(ctx, suritap.ToClient, srv); err != nil {
		return "", err
	}
	bad, err := frames(header("/h2-evil", 3))
	if err != nil {
		return "", err
	}
	v, err = conn.Inspect(ctx, suritap.ToServer, bad)
	if err != nil {
		return "", err
	}
	return describe(v), expect(v, suritap.Drop, 9000008)
}

func flowStaysDropped(ctx context.Context, c *suritap.Client) (string, error) {
	conn, err := open(c, false)
	if err != nil {
		return "", err
	}
	defer conn.Close(true)
	v, err := conn.Inspect(ctx, suritap.ToServer, httpReq("GET", "/etc/passwd", "", nil))
	if err != nil || v.Action != suritap.Drop {
		return "", fmt.Errorf("first: %s %v", describe(v), err)
	}
	v, err = conn.Inspect(ctx, suritap.ToServer, httpReq("GET", "/harmless", "", nil))
	if err != nil {
		return "", err
	}
	return describe(v), errors.Join(expect(v, suritap.Drop, 0), wantReason(v, suritap.ReasonFlow))
}

func gapThenData(ctx context.Context, c *suritap.Client) (string, error) {
	conn, err := open(c, false)
	if err != nil {
		return "", err
	}
	defer conn.Close(false)
	if _, err := conn.Inspect(ctx, suritap.ToServer, httpReq("GET", "/a", "", nil)); err != nil {
		return "", err
	}
	if err := conn.Gap(ctx, suritap.ToServer, 5000); err != nil {
		return "", err
	}
	v, err := conn.Inspect(ctx, suritap.ToServer, httpReq("GET", "/b", "", nil))
	if err != nil {
		return "", err
	}
	if v.Action == suritap.Error {
		return "", fmt.Errorf("engine error after gap: %s", describe(v))
	}
	return "after a 5000-byte gap: " + describe(v), nil
}

func bypassAfterDepth(ctx context.Context, c *suritap.Client) (string, error) {
	conn, err := open(c, false)
	if err != nil {
		return "", err
	}
	defer conn.Close(false)
	if _, err := conn.Inspect(ctx, suritap.ToServer, httpReq("GET", "/big", "", nil)); err != nil {
		return "", err
	}
	const size = 3 << 20
	hdr := []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", size))
	if err := conn.Send(ctx, suritap.ToClient, hdr); err != nil {
		return "", err
	}
	chunk := bytes.Repeat([]byte("z"), 64<<10)
	for sent := 0; sent < size; sent += len(chunk) {
		if conn.Bypassed() {
			return fmt.Sprintf("BYPASS received after %d response bytes", sent), nil
		}
		if _, err := conn.Inspect(ctx, suritap.ToClient, chunk); err != nil {
			return "", err
		}
	}
	if conn.Bypassed() {
		return "BYPASS received at the end of the response", nil
	}
	return "", errors.New("no BYPASS (needs stream.bypass: yes and reassembly depth < response size)")
}

func keepAlive(ctx context.Context, c *suritap.Client) (string, error) {
	conn, err := open(c, false)
	if err != nil {
		return "", err
	}
	defer conn.Close(false)
	for i := range 200 {
		v, err := conn.Inspect(ctx, suritap.ToServer, httpReq("GET", fmt.Sprintf("/item/%d", i), "", nil))
		if err != nil {
			return "", err
		}
		if v.Action != suritap.Pass {
			return "", fmt.Errorf("request %d: %s", i, describe(v))
		}
		if _, err := conn.Inspect(ctx, suritap.ToClient, httpResp([]byte("ok"))); err != nil {
			return "", err
		}
	}
	v, err := conn.Inspect(ctx, suritap.ToServer, httpReq("GET", "/etc/passwd", "", nil))
	if err != nil {
		return "", err
	}
	return "200 request/response pairs passed, 201st " + describe(v), expect(v, suritap.Drop, 9000001)
}

func reloaded(active bool) func(context.Context, *suritap.Client) (string, error) {
	return func(ctx context.Context, c *suritap.Client) (string, error) {
		conn, err := open(c, false)
		if err != nil {
			return "", err
		}
		defer conn.Close(true)
		v, err := conn.Inspect(ctx, suritap.ToServer, httpReq("GET", "/reloaded-rule", "", nil))
		if err != nil {
			return "", err
		}
		if active {
			return describe(v), expect(v, suritap.Drop, 9000010)
		}
		return describe(v), expect(v, suritap.Pass, 0)
	}
}

// exceptionPolicy sends a malformed PostgreSQL message after a valid
// startup; the parser error triggers app-layer.error-policy (drop-flow in
// the exception test configuration).
func exceptionPolicy(ctx context.Context, c *suritap.Client) (string, error) {
	src, dst := addrs(false)
	conn, err := c.Open(suritap.OpenParams{Src: src, Dst: netipPort(dst, 5432)})
	if err != nil {
		return "", err
	}
	defer conn.Close(true)
	params := []byte("user\x00app\x00database\x00shop\x00\x00")
	startup := make([]byte, 8, 8+len(params))
	binary.BigEndian.PutUint32(startup, uint32(8+len(params)))
	binary.BigEndian.PutUint32(startup[4:], 196608)
	startup = append(startup, params...)
	if v, err := conn.Inspect(ctx, suritap.ToServer, startup); err != nil || v.Action != suritap.Pass {
		return "", fmt.Errorf("startup: %s %v", describe(v), err)
	}
	if v, err := conn.Inspect(ctx, suritap.ToClient, append(pgMsg('R', []byte{0, 0, 0, 0}), pgMsg('Z', []byte{'I'})...)); err != nil || v.Action != suritap.Pass {
		return "", fmt.Errorf("server hello: %s %v", describe(v), err)
	}
	// 'Q' with a length below the 4-byte minimum.
	v, err := conn.Inspect(ctx, suritap.ToServer, []byte{'Q', 0, 0, 0, 1, 'x', 'x', 'x'})
	if err != nil {
		return "", err
	}
	return describe(v), errors.Join(expect(v, suritap.Drop, 0), wantReason(v, suritap.ReasonPolicy))
}

// reuseAfterDrop: a dropped flow never sees its RST and lingers in the
// engine; a new connection with the same 5-tuple must still get a clean
// flow (per-connection discriminator).
func reuseAfterDrop(ctx context.Context, c *suritap.Client) (string, error) {
	port := uint16(10000 + srcPort.Add(1)%5000)
	a, err := openAt(c, port)
	if err != nil {
		return "", err
	}
	v, err := a.Inspect(ctx, suritap.ToServer, httpReq("GET", "/etc/passwd", "", nil))
	if err != nil || v.Action != suritap.Drop {
		return "", fmt.Errorf("first connection: %s %v", describe(v), err)
	}
	_ = a.Close(true)
	b, err := openAt(c, port)
	if err != nil {
		return "", err
	}
	defer b.Close(false)
	v, err = b.Inspect(ctx, suritap.ToServer, httpReq("GET", "/index.html", "", nil))
	if err != nil {
		return "", err
	}
	return "second connection on the same 5-tuple: " + describe(v), expect(v, suritap.Pass, 0)
}

// reuseAfterBypass: a bypassed flow also lingers; reusing its 5-tuple must
// not skip inspection of the new connection.
func reuseAfterBypass(ctx context.Context, c *suritap.Client) (string, error) {
	port := uint16(15000 + srcPort.Add(1)%5000)
	a, err := openAt(c, port)
	if err != nil {
		return "", err
	}
	if _, err := a.Inspect(ctx, suritap.ToServer, httpReq("GET", "/big", "", nil)); err != nil {
		return "", err
	}
	const size = 2 << 20
	if err := a.Send(ctx, suritap.ToClient, []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", size))); err != nil {
		return "", err
	}
	chunk := bytes.Repeat([]byte("z"), 64<<10)
	for sent := 0; sent < size && !a.Bypassed(); sent += len(chunk) {
		if _, err := a.Inspect(ctx, suritap.ToClient, chunk); err != nil {
			return "", err
		}
	}
	if !a.Bypassed() {
		return "", errors.New("first connection was not bypassed")
	}
	_ = a.Close(false)
	b, err := openAt(c, port)
	if err != nil {
		return "", err
	}
	defer b.Close(true)
	v, err := b.Inspect(ctx, suritap.ToServer, httpReq("GET", "/etc/passwd", "", nil))
	if err != nil {
		return "", err
	}
	return "attack on the reused 5-tuple: " + describe(v), expect(v, suritap.Drop, 9000001)
}
