package snortconv

import (
	"fmt"
	"regexp"
	"strings"
)

// suricataBuf maps buffers to the Suricata 8 sticky buffer keyword.
var suricataBuf = map[buf]string{
	bufPkt:         "pkt_data",
	bufFile:        "file.data",
	bufURI:         "http.uri",
	bufRawURI:      "http.uri.raw",
	bufHeader:      "http.header",
	bufRawHeader:   "http.header.raw",
	bufCookie:      "http.cookie",
	bufRawCookie:   "http.cookie", // Suricata does not normalize cookies
	bufClientBody:  "http.request_body",
	bufMethod:      "http.method",
	bufStatCode:    "http.stat_code",
	bufStatMsg:     "http.stat_msg",
	bufVersion:     "http.protocol",
	bufUserAgent:   "http.user_agent",
	bufHost:        "http.host.raw",
	bufRawRequest:  "http.request_line",
	bufRawStatus:   "http.response_line",
	bufBase64:      "base64_data",
	bufDCEStub:     "dce_stub_data",
	bufSIPMethod:   "sip.method",
	bufSIPStatCode: "sip.stat_code",
	// Suricata has no buffer holding only the SIP headers or body: the
	// payload holds both (and the start line).
	bufSIPHeader: "pkt_data",
	bufSIPBody:   "pkt_data",
}

// suricataActions maps Snort actions to Suricata actions.
var suricataActions = map[string]string{
	"alert": "alert", "pass": "pass", "drop": "drop", "reject": "reject",
	"sdrop": "drop", "block": "drop",
}

// suricataProtos maps Snort header protocols and Snort 3 service names to
// Suricata header protocols.
var suricataProtos = map[string]string{
	"tcp": "tcp", "udp": "udp", "icmp": "icmp", "ip": "ip",
	"http": "http", "ssl": "tls", "tls": "tls", "dns": "dns", "smtp": "smtp",
	"ftp": "ftp", "ftp-data": "ftp-data", "imap": "imap", "pop3": "pop3",
	"ssh": "ssh", "smb": "smb", "netbios-ssn": "smb", "dcerpc": "dcerpc",
	"sip": "sip", "telnet": "telnet", "tftp": "tftp", "snmp": "snmp",
	"kerberos": "krb5", "krb5": "krb5", "ntp": "ntp", "dhcp": "dhcp",
	"rdp": "rdp", "nfs": "nfs", "ldap": "ldap", "mqtt": "mqtt",
	"modbus": "modbus", "dnp3": "dnp3", "enip": "enip", "http2": "http2",
	"postgresql": "pgsql", "vnc": "rfb", "ike": "ike", "bittorrent": "bittorrent-dht",
}

// packetKeywords are options Suricata evaluates per packet; it refuses
// rules that combine them with app-layer inspection.
var packetKeywords = map[string]bool{
	"dsize": true, "flags": true, "ttl": true, "tos": true, "id": true,
	"seq": true, "ack": true, "window": true, "fragbits": true,
	"fragoffset": true, "ipopts": true, "itype": true, "icode": true,
	"icmp_id": true, "icmp_seq": true, "sameip": true,
}

// appLayerKeywords are non-buffer options that make a rule app-layer.
var appLayerKeywords = map[string]bool{
	"dce_iface": true, "dce_opnum": true, "ssl_state": true,
	"ssl_version": true, "urilen": true, "ftpbounce": true,
}

// assignBuffers resolves the buffer of every payload op and whether the
// source engine starts it at the beginning of that buffer.
//
// Snort 3 inspects the buffer selected by the last sticky buffer option
// and resets the cursor whenever one is given. Snort 2 inspects the buffer
// named by a content modifier or pcre flag, or else the current
// file_data/pkt_data/base64_data buffer; byte_* and isdataat with
// "relative" follow the cursor into the buffer of the previous match (as
// snort2lua does). Moving to another buffer resets the cursor in both.
func (c *conv) assignBuffers() {
	sticky, last := bufPkt, buf("")
	pending, rawSticky := true, false
	for _, it := range c.items {
		if it.sticky != "" {
			sticky, pending, rawSticky = canonical(it.sticky), true, it.sticky == bufRaw
			continue
		}
		o := it.op
		if o == nil {
			continue
		}
		if o.synthetic {
			o.Buf, o.reset = o.explicit, true
			continue
		}
		switch {
		case o.explicit != "":
			o.Buf = canonical(o.explicit)
		case c.d == Snort2 && payloadKinds[o.Kind] && o.relative() && !pending && last != "":
			o.Buf = last
		default:
			o.Buf = sticky
		}
		if o.explicit == bufRaw || rawSticky && o.explicit == "" {
			c.note(CodeRawPayload, "Snort raw (unnormalized) payload mapped to the Suricata payload, which Suricata does not normalize")
		}
		o.reset = pending || o.Buf != last
		pending, last = false, o.Buf
	}
}

func canonical(b buf) buf {
	if b == bufRaw {
		return bufPkt
	}
	return b
}

// prepare rewrites payload ops for Suricata: options that start a buffer in
// Snort become absolute, bufferlen becomes bsize or isdataat, and Snort 2
// fast_pattern:only becomes a case-insensitive fast pattern.
func (c *conv) prepare() {
	var out []item
	for _, it := range c.items {
		o := it.op
		if o == nil {
			if it.sticky == "" {
				out = append(out, it)
			}
			continue
		}
		if o.reset && o.relative() && !o.synthetic {
			c.absolutize(o)
		}
		if o.Kind == "content" && o.C.FPOnly {
			// Snort 2 inserts fast patterns case-insensitively and does not
			// re-check a fast_pattern:only content, so it never was case
			// sensitive (snort2lua converts it to "fast_pattern,nocase").
			o.C.FPOnly, o.C.Nocase = false, true
			c.note(CodeFastPatternOnly, "fast_pattern:only converted to nocase + fast_pattern")
		}
		if o.Kind == "content" && o.C.Within != "" {
			if w, ok := atoi(o.C.Within); ok && w < contentLen(o.C.Str) {
				c.fail(CodeNeverMatches, "within:%d is shorter than content %q", w, o.C.Str)
			}
		}
		if o.Kind == "content" && o.C.Depth != "" {
			if d, ok := atoi(o.C.Depth); ok && d < contentLen(o.C.Str) {
				c.fail(CodeNeverMatches, "depth:%d is shorter than content %q", d, o.C.Str)
			}
		}
		if o.Kind == "bsize" {
			out = append(out, c.bufferlen(o)...)
			continue
		}
		out = append(out, item{op: o})
	}
	c.items = out
}

// absolutize rewrites a relative option that the source engine evaluates at
// the start of its buffer. Suricata keeps one cursor per buffer, so the
// relative form would continue after earlier matches in that buffer.
func (c *conv) absolutize(o *op) {
	switch o.Kind {
	case "pcre":
		o.PcreFlags = strings.ReplaceAll(o.PcreFlags, "R", "")
	case "content":
		cc := o.C
		dist, within := cc.Distance, cc.Within
		if dist == "" {
			dist = "0"
		}
		d, dok := atoi(dist)
		w, wok := atoi(within)
		switch {
		case dok && within == "":
			if d > 0 {
				cc.Offset = fmt.Sprint(d)
			}
		case dok && wok:
			// Snort and Suricata search [cursor+distance, cursor+distance+within).
			start, end := max(d, 0), d+w
			if end-start < contentLen(cc.Str) {
				c.fail(CodeNeverMatches, "content %q cannot fit at the start of its buffer (distance:%d, within:%d)", cc.Str, d, w)
				return
			}
			if start > 0 {
				cc.Offset = fmt.Sprint(start)
			}
			cc.Depth = fmt.Sprint(end - start)
		case dist == "0" && within != "":
			cc.Depth = within
		case within == "":
			cc.Offset = dist
		default:
			c.approx(CodeRelativeReset, "relative content %q with variable distance and within kept relative", cc.Str)
			return
		}
		cc.Distance, cc.Within = "", ""
	default:
		o.Args = dropArg(o.Args, "relative")
	}
	c.note(CodeRelativeReset, "relative option at the start of a buffer made absolute")
}

// bufferlen converts Snort 3 "bufferlen:<range>[,relative]". A relative
// bufferlen checks the bytes left after the cursor, which isdataat checks
// in Suricata; an absolute one is bsize (dsize on the packet).
func (c *conv) bufferlen(o *op) []item {
	rel := hasArg(o.Args, "relative")
	args := dropArg(o.Args, "relative")
	if len(args) != 1 {
		c.fail(CodeSyntax, "invalid bufferlen %q", strings.Join(o.Args, ","))
		return nil
	}
	if o.synthetic {
		return []item{{op: o}}
	}
	expr, ok := normRange(args[0], false)
	if !ok {
		c.fail(CodeSyntax, "invalid bufferlen %q", args[0])
		return nil
	}
	if !rel || o.reset {
		if o.Buf == bufPkt {
			return []item{{opt: &rawOpt{Name: "dsize", Value: expr, HasValue: true}}}
		}
		o.Args = []string{expr}
		return []item{{op: o}}
	}
	isdataat := func(v string) item {
		return item{op: &op{Kind: "isdataat", Buf: o.Buf, Args: []string{v, "relative"}}}
	}
	// "left > n" is "isdataat:n,relative"; "left < n" is "isdataat:!n-1,relative".
	if m := reExclRange.FindStringSubmatch(expr); m != nil {
		lo, _ := atoi(m[1])
		hi, _ := atoi(m[2])
		return []item{isdataat(fmt.Sprint(lo)), isdataat(fmt.Sprintf("!%d", hi-1))}
	}
	m := reNormCompare.FindStringSubmatch(expr)
	n, _ := atoi(m[2])
	switch m[1] {
	case ">":
		return []item{isdataat(fmt.Sprint(n))}
	case "<":
		if n == 0 {
			c.fail(CodeNeverMatches, "bufferlen:<0 never matches")
			return nil
		}
		return []item{isdataat(fmt.Sprintf("!%d", n-1))}
	case "":
		if n == 0 {
			return []item{isdataat("!0")}
		}
		return []item{isdataat(fmt.Sprint(n - 1)), isdataat(fmt.Sprintf("!%d", n))}
	}
	c.fail(CodeUnsupported, "bufferlen %q,relative has no Suricata equivalent", args[0])
	return nil
}

// emit renders the Suricata rule.
func (c *conv) emit() string {
	c.assignBuffers()
	c.prepare()

	// Map buffers.
	for _, it := range c.items {
		if o := it.op; o != nil {
			if _, ok := suricataBuf[o.Buf]; !ok {
				c.fail(CodeUnsupported, "Snort buffer %s has no Suricata equivalent", o.Buf)
			}
			if o.Buf == bufSIPHeader || o.Buf == bufSIPBody {
				c.approx(CodeApproxBuffer, "%s inspected in the whole SIP payload (Suricata has no %s buffer)", o.Buf, o.Buf)
			}
		}
	}

	ops := c.orderOps()
	c.fastPatterns(ops)
	c.checkPacketAppLayer(ops)
	c.checkDirection(ops)

	hdr := c.header()
	var opts []string
	block := false
	for _, it := range c.items {
		if it.op != nil {
			if !block {
				opts = append(opts, renderOps(ops)...)
				block = true
			}
			continue
		}
		opts = append(opts, it.opt.String())
	}
	if c.r.Action == "sdrop" {
		opts = append(opts, "noalert")
	}
	return hdr + " (" + strings.Join(opts, "; ") + ";)"
}

// orderOps groups payload ops by Suricata buffer, in order of first use,
// keeping their order within a buffer. Suricata appends to a buffer that is
// selected again, so grouping does not change the meaning, avoids its
// "duplicate instance" warnings and keeps multi-instance buffers in one
// instance, as Snort means. Grouping is skipped when it would move the use
// of a byte_extract/byte_math variable before its definition.
func (c *conv) orderOps() []*op {
	var orig []*op
	order := map[string]int{}
	for _, it := range c.items {
		if it.op != nil {
			orig = append(orig, it.op)
			if _, ok := order[suricataBuf[it.op.Buf]]; !ok {
				order[suricataBuf[it.op.Buf]] = len(order)
			}
		}
	}
	grouped := make([]*op, 0, len(orig))
	for i := 0; i < len(order); i++ {
		for _, o := range orig {
			if order[suricataBuf[o.Buf]] == i {
				grouped = append(grouped, o)
			}
		}
	}
	if varsDefinedBeforeUse(grouped) {
		return grouped
	}
	return orig
}

var (
	reIdent       = regexp.MustCompile(`^[A-Za-z_]\w*$`)
	reExclRange   = regexp.MustCompile(`^(\d+)<>(\d+)$`)
	reNormCompare = regexp.MustCompile(`^([<>!]?)(\d+)$`)
)

func varsDefinedBeforeUse(ops []*op) bool {
	defined := map[string]bool{}
	all := map[string]bool{}
	for _, o := range ops {
		if n := varDef(o); n != "" {
			all[n] = true
		}
	}
	for _, o := range ops {
		var uses []string
		if o.Kind == "content" {
			uses = []string{o.C.Offset, o.C.Depth, o.C.Distance, o.C.Within}
		} else {
			uses = o.Args
		}
		for _, u := range uses {
			if all[u] && !defined[u] {
				return false
			}
		}
		if n := varDef(o); n != "" {
			defined[n] = true
		}
	}
	return true
}

func varDef(o *op) string {
	switch o.Kind {
	case "byte_extract":
		if len(o.Args) > 2 && reIdent.MatchString(o.Args[2]) {
			return o.Args[2]
		}
	case "byte_math":
		for _, a := range o.Args {
			if f := strings.Fields(a); len(f) == 2 && f[0] == "result" {
				return f[1]
			}
		}
	}
	return ""
}

// fastPatterns enforces Suricata's fast_pattern rules: one per rule, and
// not on a negated relative content. fast_pattern only affects performance.
func (c *conv) fastPatterns(ops []*op) {
	seen := false
	for _, o := range ops {
		if o.Kind != "content" || !o.C.FastPattern {
			continue
		}
		cc := o.C
		switch {
		case seen:
			c.note(CodeFastPattern, "extra fast_pattern removed (Suricata allows one per rule)")
		case cc.Neg && (cc.relative() || cc.Offset != "" || cc.Depth != ""):
			c.note(CodeFastPattern, "fast_pattern removed from a negated content with position modifiers")
		case o.Buf == bufBase64:
			c.note(CodeFastPattern, "fast_pattern removed from base64_data content")
		default:
			seen = true
			continue
		}
		cc.FastPattern, cc.FPOffset, cc.FPLength = false, "", ""
	}
}

// checkPacketAppLayer reports rules that combine per-packet options with
// app-layer inspection, which Suricata refuses.
func (c *conv) checkPacketAppLayer(ops []*op) {
	app := false
	if p := c.suricataProto(); p != "" && p != "tcp" && p != "udp" && p != "icmp" && p != "ip" {
		app = true
	}
	for _, o := range ops {
		if o.Buf != bufPkt && o.Buf != bufBase64 && o.Buf != bufSIPHeader && o.Buf != bufSIPBody {
			app = true
		}
	}
	var pkt []string
	for _, it := range c.items {
		if it.opt == nil {
			continue
		}
		if appLayerKeywords[it.opt.Name] {
			app = true
		}
		if packetKeywords[it.opt.Name] {
			pkt = append(pkt, it.opt.Name)
		}
	}
	if app && len(pkt) > 0 {
		c.fail(CodePacketAppLayer, "Suricata cannot combine per-packet options (%s) with app-layer inspection", strings.Join(pkt, ", "))
	}
}

// Buffers that exist only in requests (toServer) or only in responses.
var (
	toServerBufs = map[buf]bool{
		bufURI: true, bufRawURI: true, bufMethod: true, bufClientBody: true,
		bufUserAgent: true, bufHost: true, bufRawRequest: true, bufSIPMethod: true,
	}
	toClientBufs = map[buf]bool{
		bufStatCode: true, bufStatMsg: true, bufRawStatus: true, bufSIPStatCode: true,
	}
)

// checkDirection reports rules Suricata refuses because of their direction:
// request and response buffers together (Snort evaluates them on the
// response, Suricata needs a "=>" transactional rule with different
// semantics), a buffer against the flow direction, and the raw header
// buffer without a flow direction.
func (c *conv) checkDirection(ops []*op) {
	var toServer, toClient bool
	for _, it := range c.items {
		if it.opt != nil && it.opt.Name == "flow" {
			for _, f := range splitArgs(it.opt.Value) {
				switch f {
				case "to_server", "from_client":
					toServer = true
				case "to_client", "from_server":
					toClient = true
				}
			}
		}
	}
	var req, resp, rawHeader bool
	for _, o := range ops {
		req = req || toServerBufs[o.Buf]
		resp = resp || toClientBufs[o.Buf]
		rawHeader = rawHeader || o.Buf == bufRawHeader
	}
	switch {
	case req && resp:
		c.fail(CodeDirection, "request and response buffers in one rule")
	case req && toClient, resp && toServer:
		c.fail(CodeDirection, "buffer used against the flow direction")
	case rawHeader && !toServer && !toClient && !req && !resp:
		c.fail(CodeDirection, "Suricata needs a flow direction to inspect raw HTTP headers")
	}
}

func (c *conv) suricataProto() string {
	return suricataProtos[strings.ToLower(c.r.Proto)]
}

func (c *conv) header() string {
	r := c.r
	action, ok := suricataActions[r.Action]
	if !ok {
		c.fail(CodeAction, "action %q has no Suricata equivalent", r.Action)
	}
	proto := c.suricataProto()
	if proto == "" {
		c.fail(CodeProto, "protocol %q has no Suricata equivalent", r.Proto)
	}
	if r.Src == "" {
		return action + " " + proto + " any any -> any any"
	}
	src, sp, dir, dst, dp := r.Src, r.SrcPort, r.Dir, r.Dst, r.DstPort
	if dir == "<-" {
		src, sp, dst, dp, dir = dst, dp, src, sp, "->"
	}
	return strings.Join([]string{action, proto, src, sp, dir, dst, dp}, " ")
}

func renderOps(ops []*op) []string {
	var out []string
	cur := suricataBuf[bufPkt]
	for _, o := range ops {
		if b := suricataBuf[o.Buf]; b != cur {
			out = append(out, b)
			cur = b
		}
		out = append(out, o.render()...)
	}
	return out
}

func (o *op) render() []string {
	switch o.Kind {
	case "content":
		cc := o.C
		neg := ""
		if cc.Neg {
			neg = "!"
		}
		out := []string{"content:" + neg + `"` + cc.Str + `"`}
		if cc.Nocase {
			out = append(out, "nocase")
		}
		if cc.StartsWith {
			out = append(out, "startswith")
		}
		for _, m := range []struct{ k, v string }{{"offset", cc.Offset}, {"depth", cc.Depth}, {"distance", cc.Distance}, {"within", cc.Within}} {
			if m.v != "" {
				out = append(out, m.k+":"+m.v)
			}
		}
		if cc.EndsWith {
			out = append(out, "endswith")
		}
		if cc.FastPattern {
			if cc.FPOffset != "" {
				out = append(out, "fast_pattern:"+cc.FPOffset+","+cc.FPLength)
			} else {
				out = append(out, "fast_pattern")
			}
		}
		return out
	case "pcre":
		neg := ""
		if o.PcreNeg {
			neg = "!"
		}
		return []string{"pcre:" + neg + `"/` + o.PcreRe + "/" + o.PcreFlags + `"`}
	}
	return []string{o.Kind + ":" + strings.Join(o.Args, ",")}
}
