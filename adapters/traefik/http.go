//go:build linux

package suritaptraefik

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/jc-lab/suricontroller/pkg/suritap"
)

// Middleware wraps the entry point HTTP handler (Traefik patch hook). The
// entry point name comes from the context (WithEntryPoint).
func Middleware(ctx context.Context, cfg *Config, next http.Handler) (http.Handler, error) {
	if cfg == nil {
		return next, nil
	}
	t, err := ForEntryPoint(EntryPointFrom(ctx), cfg)
	if err != nil {
		return nil, err
	}
	return t.HTTP(next), nil
}

var errBlocked = errors.New("suritap: blocked")

// HTTP returns an http.Handler that inspects each request (and, depending
// on the configuration, its response) before calling next.
func (t *Tap) HTTP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.serveHTTP(w, r, next)
	})
}

func (t *Tap) serveHTTP(w http.ResponseWriter, r *http.Request, next http.Handler) {
	t.Stats.Requests.Add(1)
	conn, err := t.open(parseAddr(r.RemoteAddr), localAddr(r), requestMeta(r))
	if err != nil {
		t.Stats.Unavailable.Add(1)
		if t.s.failClosed && t.s.mode == modePrevent {
			http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
			return
		}
		next.ServeHTTP(w, r)
		return
	}
	defer conn.Close(false)

	upgrade := r.Header.Get("Upgrade") != "" && headerHasToken(r.Header, "Connection", "upgrade")
	st := &reqState{}
	blocked, v := t.inspectRequest(r, conn, st)
	if blocked {
		logBlock(t.entryPoint, conn.CID(), "request", v)
		writeBlocked(w, conn.CID())
		return
	}
	if upgrade || t.s.response == modeOff {
		// Upgraded connections (websocket) are only inspected up to the
		// handshake; the response writer is passed through untouched.
		next.ServeHTTP(w, r)
		return
	}
	rw := &respWriter{ResponseWriter: w, t: t, conn: conn, r: r, st: st, ctx: r.Context()}
	next.ServeHTTP(rw, r)
	rw.finish()
}

// reqState is shared by the request body reader and the response writer.
type reqState struct {
	blocked atomic.Bool // set when a streamed request body was blocked
}

func localAddr(r *http.Request) (ap netip.AddrPort) {
	if a, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		return addrOf(a)
	}
	return ap
}

func requestMeta(r *http.Request) []suritap.Meta {
	meta := []suritap.Meta{{Tag: suritap.MetaProto, Value: r.Proto}}
	if r.TLS != nil {
		if r.TLS.ServerName != "" {
			meta = append(meta, suritap.Meta{Tag: suritap.MetaSNI, Value: r.TLS.ServerName})
		}
		if r.TLS.NegotiatedProtocol != "" {
			meta = append(meta, suritap.Meta{Tag: suritap.MetaALPN, Value: r.TLS.NegotiatedProtocol})
		}
	}
	if id := r.Header.Get("X-Request-Id"); id != "" && len(id) <= 128 {
		meta = append(meta, suritap.Meta{Tag: suritap.MetaRequestID, Value: id})
	}
	return meta
}

func headerHasToken(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, f := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(f), token) {
				return true
			}
		}
	}
	return false
}

// writeBlocked answers 403. Headers already set for the response (by the
// upstream, e.g. Set-Cookie) are discarded.
func writeBlocked(w http.ResponseWriter, cid uint64) {
	h := w.Header()
	clear(h)
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Suritap-Cid", strconv.FormatUint(cid, 10))
	w.WriteHeader(http.StatusForbidden)
	_, _ = io.WriteString(w, "Forbidden\n")
}

// inspectRequest sends the request head and body. Bodies up to maxBody are
// buffered and inspected before the request goes upstream; larger ones are
// inspected chunk by chunk as the upstream reads them.
func (t *Tap) inspectRequest(r *http.Request, conn *suritap.Conn, st *reqState) (bool, *suritap.Verdict) {
	hasBody := r.Body != nil && r.Body != http.NoBody && r.ContentLength != 0
	if !hasBody {
		return t.verdict(r.Context(), conn, t.s.mode, suritap.ToServer, requestHead(r, 0))
	}
	var prefix []byte
	if r.ContentLength < 0 || r.ContentLength <= t.s.maxBody {
		data, err := io.ReadAll(io.LimitReader(r.Body, t.s.maxBody+1))
		if err != nil {
			// Truncated client upload: let the upstream see the same
			// failure, after inspecting what arrived.
			r.Body = &errReader{data: data, err: err}
			blocked, v := t.verdict(r.Context(), conn, t.s.mode, suritap.ToServer, append(requestHead(r, int64(len(data))), data...))
			return blocked, v
		}
		if int64(len(data)) <= t.s.maxBody {
			// Complete body: forward it with an explicit length.
			r.Body = io.NopCloser(bytes.NewReader(data))
			r.ContentLength = int64(len(data))
			r.TransferEncoding = nil
			return t.verdict(r.Context(), conn, t.s.mode, suritap.ToServer, append(requestHead(r, r.ContentLength), data...))
		}
		prefix = data
	}
	// Streaming.
	chunked := r.ContentLength < 0
	head := requestHead(r, r.ContentLength)
	if chunked {
		head = append(head, chunk(prefix)...)
	} else {
		head = append(head, prefix...)
	}
	if blocked, v := t.verdict(r.Context(), conn, t.s.mode, suritap.ToServer, head); blocked {
		return true, v
	}
	r.Body = &inspectBody{t: t, conn: conn, ctx: r.Context(), st: st, prefix: bytes.NewReader(prefix), body: r.Body, chunked: chunked}
	return false, nil
}

type errReader struct {
	data []byte
	err  error
}

func (e *errReader) Read(p []byte) (int, error) {
	if len(e.data) > 0 {
		n := copy(p, e.data)
		e.data = e.data[n:]
		return n, nil
	}
	return 0, e.err
}

func (e *errReader) Close() error { return nil }

// inspectBody inspects a large request body while the upstream reads it.
// A drop verdict aborts the upstream request.
type inspectBody struct {
	t       *Tap
	conn    *suritap.Conn
	ctx     context.Context
	st      *reqState
	prefix  *bytes.Reader // already inspected
	body    io.ReadCloser
	chunked bool
	done    bool
}

func (b *inspectBody) Read(p []byte) (int, error) {
	if b.st.blocked.Load() {
		return 0, errBlocked
	}
	if b.prefix.Len() > 0 {
		return b.prefix.Read(p)
	}
	n, err := b.body.Read(p)
	if n > 0 {
		data := p[:n]
		if b.chunked {
			data = chunk(data)
		}
		if blocked, v := b.t.verdict(b.ctx, b.conn, b.t.s.mode, suritap.ToServer, data); blocked {
			b.st.blocked.Store(true)
			logBlock(b.t.entryPoint, b.conn.CID(), "request body", v)
			return 0, errBlocked
		}
	}
	if err == io.EOF && b.chunked && !b.done {
		b.done = true
		if blocked, v := b.t.verdict(b.ctx, b.conn, b.t.s.mode, suritap.ToServer, []byte("0\r\n\r\n")); blocked {
			b.st.blocked.Store(true)
			logBlock(b.t.entryPoint, b.conn.CID(), "request body", v)
			return n, errBlocked
		}
	}
	return n, err
}

func (b *inspectBody) Close() error { return b.body.Close() }

// respWriter forwards the response and inspects it. Detect mode streams it
// to Suricata without waiting. Prevent mode buffers responses up to
// maxResponseBuffer and inspects them complete (a blocked response becomes
// a 403); larger responses are inspected while streaming and the
// connection is aborted when later bytes are dropped.
type respWriter struct {
	http.ResponseWriter
	t    *Tap
	conn *suritap.Conn
	r    *http.Request
	st   *reqState
	ctx  context.Context

	status    int  // status set by the handler
	committed bool // status sent to the client
	sentHead  bool // status line sent to Suricata
	chunked   bool
	noBody    bool
	endSent   bool // terminating chunk sent to Suricata
	aborted   bool
	buf       []byte // prevent mode: body held back until inspected
}

func (w *respWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *respWriter) WriteHeader(code int) {
	if w.committed || w.aborted {
		return
	}
	if code >= 100 && code < 200 && code != http.StatusSwitchingProtocols {
		w.ResponseWriter.WriteHeader(code) // informational, not inspected
		return
	}
	if w.st.blocked.Load() {
		// The request body was blocked while streaming: answer 403
		// instead of the upstream error.
		w.aborted = true
		writeBlocked(w.ResponseWriter, w.conn.CID())
		return
	}
	if w.status == 0 {
		w.status = code
	}
	if w.t.s.response != modePrevent {
		w.commit(nil, false)
	}
}

// head returns the serialized status line and headers (once).
func (w *respWriter) head() []byte {
	if w.sentHead {
		return nil
	}
	w.sentHead = true
	if w.status == 0 {
		w.status = http.StatusOK
	}
	h := w.Header()
	w.noBody = w.r.Method == http.MethodHead || w.status == http.StatusNoContent || w.status == http.StatusNotModified
	length := int64(-1)
	if cl := h.Get("Content-Length"); cl != "" {
		if n, err := strconv.ParseInt(cl, 10, 64); err == nil {
			length = n
		}
	}
	if w.noBody {
		length = 0
	}
	w.chunked = length < 0
	return responseHead(w.status, h, length)
}

// commit inspects (prevent) or sends (detect) the head and body (plus the
// end of a chunked message when final), then writes the status to the
// client. Returns false when blocked.
func (w *respWriter) commit(body []byte, final bool) bool {
	data := w.head()
	if !w.noBody {
		data = append(data, w.frame(body)...)
		if final && w.chunked {
			data = append(data, "0\r\n\r\n"...)
			w.endSent = true
		}
	}
	if blocked, v := w.t.verdict(w.ctx, w.conn, w.t.s.response, suritap.ToClient, data); blocked {
		logBlock(w.t.entryPoint, w.conn.CID(), "response", v)
		w.aborted = true
		writeBlocked(w.ResponseWriter, w.conn.CID())
		return false
	}
	w.committed = true
	w.ResponseWriter.WriteHeader(w.status)
	return true
}

func (w *respWriter) frame(p []byte) []byte {
	if w.chunked {
		return chunk(p)
	}
	return p
}

func (w *respWriter) Write(p []byte) (int, error) {
	if w.aborted {
		return 0, errBlocked
	}
	if w.st.blocked.Load() && !w.committed {
		w.WriteHeader(http.StatusForbidden)
		return 0, errBlocked
	}
	if !w.committed {
		if w.status == 0 {
			w.status = http.StatusOK
		}
		if w.t.s.response != modePrevent {
			if !w.commit(p, false) {
				return 0, errBlocked
			}
			return w.ResponseWriter.Write(p)
		}
		if int64(len(w.buf)+len(p)) <= w.t.s.maxRespBuf {
			w.buf = append(w.buf, p...)
			return len(p), nil
		}
		data := append(w.buf, p...)
		w.buf = nil
		if !w.commit(data, false) {
			return 0, errBlocked
		}
		if _, err := w.ResponseWriter.Write(data); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	if len(p) > 0 && !w.noBody {
		if blocked, v := w.t.verdict(w.ctx, w.conn, w.t.s.response, suritap.ToClient, w.frame(p)); blocked {
			logBlock(w.t.entryPoint, w.conn.CID(), "response", v)
			w.aborted = true
			// Headers are gone already: abort the connection.
			panic(http.ErrAbortHandler)
		}
	}
	return w.ResponseWriter.Write(p)
}

func (w *respWriter) Flush() {
	if w.aborted {
		return
	}
	if !w.committed && w.t.s.response == modePrevent {
		// Hold the headers until the body is inspected, so that a
		// blocked response can still become a 403.
		return
	}
	if !w.committed {
		if w.status == 0 {
			w.status = http.StatusOK
		}
		if !w.commit(nil, false) {
			return
		}
	}
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}

func (w *respWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return http.NewResponseController(w.ResponseWriter).Hijack()
}

// finish completes the response after the handler returned.
func (w *respWriter) finish() {
	if w.aborted {
		return
	}
	if !w.committed {
		if w.status == 0 {
			w.status = http.StatusOK
		}
		if w.commit(w.buf, true) && len(w.buf) > 0 {
			_, _ = w.ResponseWriter.Write(w.buf)
		}
		return
	}
	if w.chunked && !w.noBody && !w.endSent {
		if blocked, v := w.t.verdict(w.ctx, w.conn, w.t.s.response, suritap.ToClient, []byte("0\r\n\r\n")); blocked {
			logBlock(w.t.entryPoint, w.conn.CID(), "response end", v)
			// The body is out already; abort so the client sees a
			// truncated response instead of a complete one.
			panic(http.ErrAbortHandler)
		}
	}
}

// requestHead serializes the request line and headers as HTTP/1.1.
// length: >0 Content-Length, 0 no body, <0 chunked.
func requestHead(r *http.Request, length int64) []byte {
	var b bytes.Buffer
	uri := r.RequestURI
	if uri == "" || r.ProtoMajor >= 2 && !strings.HasPrefix(uri, "/") && uri != "*" {
		uri = r.URL.RequestURI()
	}
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", r.Method, uri)
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	if host != "" {
		fmt.Fprintf(&b, "Host: %s\r\n", host)
	}
	writeHeaders(&b, r.Header, "Host")
	writeFraming(&b, length)
	b.WriteString("\r\n")
	return b.Bytes()
}

func responseHead(status int, h http.Header, length int64) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", status, http.StatusText(status))
	writeHeaders(&b, h, "")
	if length != 0 || h.Get("Content-Length") != "" {
		writeFraming(&b, length)
	}
	b.WriteString("\r\n")
	return b.Bytes()
}

func writeHeaders(b *bytes.Buffer, h http.Header, skip string) {
	keys := make([]string, 0, len(h))
	for k := range h {
		switch http.CanonicalHeaderKey(k) {
		case "Content-Length", "Transfer-Encoding", "Trailer":
			continue
		}
		if skip != "" && http.CanonicalHeaderKey(k) == skip {
			continue
		}
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		for _, v := range h[k] {
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteString("\r\n")
		}
	}
}

func writeFraming(b *bytes.Buffer, length int64) {
	switch {
	case length > 0:
		fmt.Fprintf(b, "Content-Length: %d\r\n", length)
	case length < 0:
		b.WriteString("Transfer-Encoding: chunked\r\n")
	}
}

func chunk(p []byte) []byte {
	if len(p) == 0 {
		return nil
	}
	out := make([]byte, 0, len(p)+16)
	out = strconv.AppendInt(out, int64(len(p)), 16)
	out = append(out, '\r', '\n')
	out = append(out, p...)
	return append(out, '\r', '\n')
}
