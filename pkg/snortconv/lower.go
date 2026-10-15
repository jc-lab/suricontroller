package snortconv

import (
	"fmt"
	"regexp"
	"strings"
)

// snort2Modifiers maps Snort 2 HTTP content modifiers to their buffer.
var snort2Modifiers = map[string]buf{
	"http_uri":         bufURI,
	"http_raw_uri":     bufRawURI,
	"http_header":      bufHeader,
	"http_raw_header":  bufRawHeader,
	"http_cookie":      bufCookie,
	"http_raw_cookie":  bufRawCookie,
	"http_client_body": bufClientBody,
	"http_method":      bufMethod,
	"http_stat_code":   bufStatCode,
	"http_stat_msg":    bufStatMsg,
}

// snort2PcreFlags maps Snort 2 pcre buffer flags to their buffer.
var snort2PcreFlags = map[rune]buf{
	'U': bufURI,
	'I': bufRawURI,
	'H': bufHeader,
	'D': bufRawHeader,
	'C': bufCookie,
	'K': bufRawCookie,
	'P': bufClientBody,
	'M': bufMethod,
	'S': bufStatCode,
	'Y': bufStatMsg,
	'B': bufRaw,
}

// snort3Sticky maps Snort 3 sticky buffer options to their buffer. Options
// that select a buffer Suricata has no equivalent for are in
// snort3Unsupported instead.
var snort3Sticky = map[string]buf{
	"pkt_data":         bufPkt,
	"raw_data":         bufRaw,
	"file_data":        bufFile,
	"http_uri":         bufURI,
	"http_raw_uri":     bufRawURI,
	"http_header":      bufHeader,
	"http_raw_header":  bufRawHeader,
	"http_cookie":      bufCookie,
	"http_raw_cookie":  bufRawCookie,
	"http_client_body": bufClientBody,
	"http_raw_body":    bufRawBody,
	"http_method":      bufMethod,
	"http_stat_code":   bufStatCode,
	"http_stat_msg":    bufStatMsg,
	"http_version":     bufVersion,
	"http_raw_request": bufRawRequest,
	"http_raw_status":  bufRawStatus,
	"base64_data":      bufBase64,
	"dce_stub_data":    bufDCEStub,
	"sip_header":       bufSIPHeader,
	"sip_body":         bufSIPBody,
}

var snort3Unsupported = map[string]string{
	"http_param":         "selects one URI/body parameter value; Suricata has no per-parameter buffer",
	"http_true_ip":       "Suricata has no true client IP buffer",
	"http_trailer":       "Suricata has no HTTP trailer buffer",
	"http_raw_trailer":   "Suricata has no HTTP trailer buffer",
	"js_data":            "Suricata has no normalized JavaScript buffer",
	"vba_data":           "Suricata has no VBA macro buffer",
	"script_data":        "Suricata has no script buffer",
	"ber_data":           "Suricata has no BER/ASN.1 navigation keyword",
	"ber_skip":           "Suricata has no BER/ASN.1 navigation keyword",
	"sd_pattern":         "Suricata has no sensitive data pattern keyword",
	"cvs":                "Suricata has no CVS keyword",
	"gtp_type":           "Suricata has no GTP keywords",
	"gtp_info":           "Suricata has no GTP keywords",
	"gtp_version":        "Suricata has no GTP keywords",
	"so":                 "shared object rules cannot be converted",
	"soid":               "shared object rules cannot be converted",
	"replace":            "content replacement is not converted",
	"react":              "active responses are not converted",
	"resp":               "active responses are not converted",
	"session":            "session logging is not converted",
	"logto":              "per-rule log files are not supported by Suricata",
	"file_type":          "Suricata has no file type identification keyword",
	"file_meta":          "Suricata has no file type identification keyword",
	"mms_data":           "Suricata has no MMS keywords",
	"s7commplus_content": "Suricata has no S7CommPlus keywords",
}

// payloadKinds are the non-content options that inspect a buffer.
var payloadKinds = map[string]bool{
	"byte_test": true, "byte_jump": true, "byte_extract": true,
	"byte_math": true, "isdataat": true, "base64_decode": true,
}

// lowerSnort2 interprets the options of a Snort 2.9 rule.
func (c *conv) lowerSnort2() {
	var last *op // most recent content, target of content modifiers
	lastContent := func(name string) *content {
		if last == nil {
			c.fail(CodeSyntax, "%s without a preceding content", name)
			return &content{}
		}
		return last.C
	}
	for _, o := range c.r.Options {
		name, v := o.Name, o.Value
		if b, ok := snort2Modifiers[name]; ok {
			lastContent(name)
			if last != nil {
				last.explicit = b
			}
			continue
		}
		switch name {
		case "content", "uricontent":
			cc, err := parseContentValue(v, false)
			if err != nil {
				c.fail(CodeSyntax, "%s: %v", name, err)
				continue
			}
			last = &op{Kind: "content", C: cc}
			if name == "uricontent" {
				last.explicit = bufURI
			}
			c.items = append(c.items, item{op: last})
		case "nocase":
			lastContent(name).Nocase = true
		case "replace":
			if last != nil {
				c.replace(last.C, v)
			} else {
				c.replace(nil, v)
			}
		case "rawbytes":
			lastContent(name)
			if last != nil {
				last.explicit = bufRaw
			}
		case "depth":
			lastContent(name).Depth = v
		case "offset":
			lastContent(name).Offset = v
		case "distance":
			lastContent(name).Distance = v
		case "within":
			lastContent(name).Within = v
		case "fast_pattern":
			cc := lastContent(name)
			switch {
			case !o.HasValue || v == "":
				cc.FastPattern = true
			case v == "only":
				cc.FastPattern, cc.FPOnly = true, true
			default:
				a := splitArgs(v)
				if len(a) != 2 {
					c.fail(CodeSyntax, "invalid fast_pattern %q", v)
					continue
				}
				cc.FastPattern, cc.FPOffset, cc.FPLength = true, a[0], a[1]
			}
		case "pcre":
			p, err := c.parsePcre(v)
			if err != nil {
				c.fail(CodeSyntax, "pcre: %v", err)
				continue
			}
			// Snort 2 selects the buffer of a pcre with flags.
			flags := ""
			for _, f := range p.PcreFlags {
				if b, ok := snort2PcreFlags[f]; ok {
					if p.explicit != "" && p.explicit != b {
						c.fail(CodeSyntax, "pcre selects several buffers (%s)", p.PcreFlags)
					}
					p.explicit = b
					continue
				}
				flags += string(f)
			}
			p.PcreFlags = flags
			c.items = append(c.items, item{op: p})
		case "file_data":
			c.items = append(c.items, item{sticky: bufFile})
		case "pkt_data":
			c.items = append(c.items, item{sticky: bufPkt})
		case "base64_data":
			c.items = append(c.items, item{sticky: bufBase64})
		case "dce_stub_data":
			c.items = append(c.items, item{sticky: bufDCEStub})
		case "sip_header":
			c.items = append(c.items, item{sticky: bufSIPHeader})
		case "sip_body":
			c.items = append(c.items, item{sticky: bufSIPBody})
		case "urilen":
			c.urilen(v)
		case "dsize":
			c.rangeOpt(name, v, true)
		case "tag", "stream_size", "dce_iface":
			// Suricata kept the Snort 2 syntax of these options.
			c.keep(o)
		default:
			if payloadKinds[name] {
				p := &op{Kind: name, Args: splitArgs(v)}
				if hasArg(p.Args, "rawbytes") {
					p.Args = dropArg(p.Args, "rawbytes")
					p.explicit = bufRaw
				}
				c.items = append(c.items, item{op: p})
				continue
			}
			c.common(o)
		}
	}
}

// lowerSnort3 interprets the options of a Snort 3 rule.
func (c *conv) lowerSnort3() {
	var last *content // target of replace
	for _, o := range c.r.Options {
		name, v := o.Name, o.Value
		if b, ok := snort3Sticky[name]; ok {
			switch {
			case name == "http_header" && o.HasValue:
				b = c.snort3HeaderField(v)
			case (name == "http_uri" || name == "http_raw_uri") && o.HasValue:
				b = c.snort3URIPart(b, v)
			case o.HasValue && v != "":
				c.fail(CodeUnsupported, "%s with arguments (%s) is not supported", name, v)
			}
			c.items = append(c.items, item{sticky: b})
			continue
		}
		switch name {
		case "content":
			cc, err := parseContentValue(v, true)
			if err != nil {
				c.fail(CodeSyntax, "content: %v", err)
				continue
			}
			last = cc
			c.items = append(c.items, item{op: &op{Kind: "content", C: cc}})
		case "replace":
			c.replace(last, v)
		case "pcre", "regex":
			p, err := c.parsePcre(v)
			if err != nil {
				c.fail(CodeSyntax, "%s: %v", name, err)
				continue
			}
			c.items = append(c.items, item{op: p})
		case "bufferlen":
			c.items = append(c.items, item{op: &op{Kind: "bsize", Args: splitArgs(v)}})
		case "service":
			for _, s := range splitArgs(v) {
				c.services = append(c.services, strings.ToLower(s))
			}
		case "rem":
		case "dsize":
			c.rangeOpt(name, v, false)
		case "stream_size":
			c.snort3StreamSize(v)
		case "tag":
			c.snort3Tag(v)
		case "dce_iface":
			c.snort3DCEIface(v)
		default:
			if payloadKinds[name] {
				c.items = append(c.items, item{op: &op{Kind: name, Args: splitArgs(v)}})
				continue
			}
			c.common(o)
		}
	}
}

// snort3HeaderField handles "http_header:field <name>".
func (c *conv) snort3HeaderField(v string) buf {
	f := strings.Fields(v)
	if len(f) != 2 || f[0] != "field" {
		c.fail(CodeUnsupported, "http_header:%s is not supported", v)
		return bufHeader
	}
	if b, ok := headerFields[strings.ToLower(f[1])]; ok {
		return b
	}
	c.fail(CodeUnsupported, "http_header field %q has no Suricata buffer", f[1])
	return bufHeader
}

// headerFields maps HTTP header names to the Suricata buffers holding only
// that header's value.
var headerFields = map[string]buf{
	"user-agent":      bufUserAgent,
	"host":            bufHost,
	"cookie":          bufCookie,
	"content-type":    bufContentType,
	"content-length":  bufContentLen,
	"accept":          bufAccept,
	"accept-encoding": bufAcceptEnc,
	"connection":      bufConnection,
	"referer":         bufReferer,
	"location":        bufLocation,
	"server":          bufServer,
}

// snort3URIPart handles "http_uri:path" and "http_uri:query" (and the
// http_raw_uri forms), which select one part of the URI. Suricata only has
// the whole URI; emit checks the ops are still meaningful there.
func (c *conv) snort3URIPart(b buf, v string) buf {
	raw := b == bufRawURI
	switch {
	case v == "path" && raw:
		return bufRawURIPath
	case v == "path":
		return bufURIPath
	case v == "query" && raw:
		return bufRawURIQuery
	case v == "query":
		return bufURIQuery
	}
	c.fail(CodeUnsupported, "%s:%s has no Suricata buffer", map[bool]string{true: "http_raw_uri", false: "http_uri"}[raw], v)
	return b
}

// replace attaches Snort "replace" (inline rewrite) to the last content.
// Suricata requires the replacement to have the content's length.
func (c *conv) replace(cc *content, v string) {
	_, txt, rest, err := parseQuoted(v)
	switch {
	case cc == nil:
		c.fail(CodeSyntax, "replace without a preceding content")
	case err != nil || strings.TrimSpace(rest) != "":
		c.fail(CodeSyntax, "invalid replace %q", v)
	case contentLen(txt) != contentLen(cc.Str):
		c.fail(CodeUnsupported, "replace %q differs in length from content %q", txt, cc.Str)
	default:
		cc.Replace = txt
	}
}

var reSnort3ContentMod = regexp.MustCompile(`^(depth|offset|distance|within|fast_pattern_offset|fast_pattern_length)\s+(\S+)$`)

// parseContentValue parses a content value. For Snort 3 the modifiers
// follow the string, separated by commas.
func parseContentValue(v string, snort3 bool) (*content, error) {
	neg, str, rest, err := parseQuoted(v)
	if err != nil {
		return nil, err
	}
	cc := &content{Neg: neg, Str: str}
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return cc, nil
	}
	if !snort3 || rest[0] != ',' {
		return nil, fmt.Errorf("unexpected text after the content string: %q", rest)
	}
	for _, m := range splitArgs(rest[1:]) {
		switch m {
		case "nocase":
			cc.Nocase = true
			continue
		case "fast_pattern":
			cc.FastPattern = true
			continue
		}
		sm := reSnort3ContentMod.FindStringSubmatch(m)
		if sm == nil {
			return nil, fmt.Errorf("unsupported content modifier %q", m)
		}
		switch sm[1] {
		case "depth":
			cc.Depth = sm[2]
		case "offset":
			cc.Offset = sm[2]
		case "distance":
			cc.Distance = sm[2]
		case "within":
			cc.Within = sm[2]
		case "fast_pattern_offset":
			cc.FPOffset = sm[2]
		case "fast_pattern_length":
			cc.FPLength = sm[2]
		}
	}
	if (cc.FPOffset == "") != (cc.FPLength == "") {
		// Suricata needs both; Snort defaults the missing one.
		if cc.FPOffset == "" {
			cc.FPOffset = "0"
		} else {
			n := contentLen(cc.Str)
			off, _ := atoi(cc.FPOffset)
			cc.FPLength = fmt.Sprint(n - off)
		}
	}
	return cc, nil
}

// parsePcre parses `[!]"/re/flags"`. Like Snort, it takes everything up to
// the last quote, so the expression may contain unescaped quotes.
func (c *conv) parsePcre(v string) (*op, error) {
	v = strings.TrimSpace(v)
	neg := strings.HasPrefix(v, "!")
	if neg {
		v = strings.TrimSpace(v[1:])
	}
	if len(v) < 2 || v[0] != '"' || v[len(v)-1] != '"' {
		return nil, fmt.Errorf("expected a quoted expression in %q", v)
	}
	s := v[1 : len(v)-1]
	if !strings.HasPrefix(s, "/") {
		return nil, fmt.Errorf("pcre %q does not use / delimiters", s)
	}
	end := strings.LastIndexByte(s, '/')
	if end == 0 {
		return nil, fmt.Errorf("pcre %q has no closing delimiter", s)
	}
	return &op{Kind: "pcre", PcreNeg: neg, PcreRe: s[1:end], PcreFlags: s[end+1:]}, nil
}

// urilen converts Snort 2 "urilen:<range>[,raw|norm]". Snort 2 checks the
// raw URI by default and treats a<>b as inclusive (snort2lua converts it to
// "http_raw_uri; bufferlen:a<=>b"); Suricata checks the normalized URI by
// default and treats a<>b as exclusive.
func (c *conv) urilen(v string) {
	a := splitArgs(v)
	kind := "raw"
	if len(a) == 2 {
		kind = a[1]
	} else if len(a) != 1 {
		c.fail(CodeSyntax, "invalid urilen %q", v)
		return
	}
	expr, ok := normRange(a[0], true)
	if !ok {
		c.fail(CodeSyntax, "invalid urilen %q", v)
		return
	}
	switch kind {
	case "raw":
		c.keep(rawOpt{Name: "urilen", Value: expr + ",raw", HasValue: true})
	case "norm":
		c.keep(rawOpt{Name: "urilen", Value: expr, HasValue: true})
	default:
		c.fail(CodeSyntax, "invalid urilen buffer %q", kind)
	}
}

// rangeOpt converts a numeric comparison option (dsize).
func (c *conv) rangeOpt(name, v string, snort2 bool) {
	expr, ok := normRange(v, snort2)
	if !ok {
		c.fail(CodeSyntax, "invalid %s %q", name, v)
		return
	}
	c.keep(rawOpt{Name: name, Value: expr, HasValue: true})
}

var (
	reRange   = regexp.MustCompile(`^(\d+)\s*(<>|<=>)\s*(\d+)$`)
	reCompare = regexp.MustCompile(`^(<=|>=|<|>|=|!=|!)?\s*(\d+)$`)

	reSIPMethod    = regexp.MustCompile(`^[A-Za-z_-]+$`)
	reSIPStatClass = regexp.MustCompile(`^[1-9]$`)
	reSIPStatCode  = regexp.MustCompile(`^[1-9]\d\d$`)
)

// normRange rewrites a Snort numeric comparison into the subset Suricata's
// integer keywords accept: N, <N, >N, !N and the exclusive range a<>b.
// snort2 makes "a<>b" inclusive, as Snort 2 (and snort2lua) treat it.
func normRange(v string, snort2 bool) (string, bool) {
	v = strings.TrimSpace(v)
	if m := reRange.FindStringSubmatch(v); m != nil {
		lo, _ := atoi(m[1])
		hi, _ := atoi(m[3])
		if m[2] == "<=>" || snort2 {
			lo, hi = lo-1, hi+1
		}
		if lo < 0 {
			return fmt.Sprintf("<%d", hi), true
		}
		return fmt.Sprintf("%d<>%d", lo, hi), true
	}
	m := reCompare.FindStringSubmatch(v)
	if m == nil {
		return "", false
	}
	n, _ := atoi(m[2])
	switch m[1] {
	case "", "=":
		return fmt.Sprint(n), true
	case "<", ">":
		return m[1] + fmt.Sprint(n), true
	case "<=":
		return fmt.Sprintf("<%d", n+1), true
	case ">=":
		if n == 0 {
			return "", false
		}
		return fmt.Sprintf(">%d", n-1), true
	case "!=", "!":
		return fmt.Sprintf("!%d", n), true
	}
	return "", false
}

// snort3StreamSize converts "stream_size:<range>[,<direction>]" into the
// Snort 2 / Suricata form "stream_size:<side>,<op>,<n>". snort2lua maps
// the Snort 2 sides server→to_client and client→to_server.
func (c *conv) snort3StreamSize(v string) {
	a := splitArgs(v)
	dir := "either"
	if len(a) == 2 {
		dir = a[1]
	} else if len(a) != 1 {
		c.fail(CodeSyntax, "invalid stream_size %q", v)
		return
	}
	side := map[string]string{"to_client": "server", "to_server": "client", "both": "both", "either": "either"}[dir]
	m := reCompare.FindStringSubmatch(a[0])
	if side == "" || m == nil {
		c.fail(CodeUnsupported, "stream_size %q has no Suricata equivalent", v)
		return
	}
	opr := m[1]
	switch opr {
	case "":
		opr = "="
	case "!":
		opr = "!="
	}
	c.keep(rawOpt{Name: "stream_size", Value: side + "," + opr + "," + m[2], HasValue: true})
}

// snort3Tag converts "tag:<type>[,packets N][,seconds N][,bytes N]".
func (c *conv) snort3Tag(v string) {
	a := splitArgs(v)
	var typ, dir string
	switch a[0] {
	case "session":
		typ = "session"
	case "host_src":
		typ, dir = "host", "src"
	case "host_dst":
		typ, dir = "host", "dst"
	default:
		c.fail(CodeUnsupported, "tag type %q is not supported", a[0])
		return
	}
	val := typ
	if len(a) > 1 {
		f := strings.Fields(a[1])
		if len(f) != 2 {
			c.fail(CodeSyntax, "invalid tag %q", v)
			return
		}
		val += "," + f[1] + "," + f[0]
		if len(a) > 2 {
			c.approx(CodeTagLimit, "Suricata tags support one limit; kept %q and dropped %q", a[1], strings.Join(a[2:], ","))
		}
	} else if dir != "" {
		// Suricata needs the count and metric before the direction.
		val += ",256,packets"
		c.approx(CodeTagLimit, "Snort 3 default tag limit replaced by 256 packets")
	}
	if dir != "" {
		val += "," + dir
	}
	c.keep(rawOpt{Name: "tag", Value: val, HasValue: true})
}

// snort3DCEIface converts "dce_iface:uuid <uuid>[,version <op><n>][,any_frag]"
// into the Snort 2 / Suricata form.
func (c *conv) snort3DCEIface(v string) {
	var out []string
	for _, a := range splitArgs(v) {
		f := strings.Fields(a)
		switch {
		case len(f) == 2 && f[0] == "uuid":
			out = append(out, f[1])
		case len(f) == 2 && f[0] == "version":
			out = append(out, f[1])
		case len(f) == 1 && f[0] == "any_frag":
			out = append(out, f[0])
		default:
			c.fail(CodeSyntax, "invalid dce_iface %q", v)
			return
		}
	}
	if len(out) == 0 {
		c.fail(CodeSyntax, "invalid dce_iface %q", v)
		return
	}
	c.keep(rawOpt{Name: "dce_iface", Value: strings.Join(out, ","), HasValue: true})
}

// passthrough lists options whose syntax and meaning are the same in Snort
// and Suricata.
var passthrough = map[string]bool{
	"msg": true, "sid": true, "rev": true, "gid": true, "classtype": true,
	"priority": true, "reference": true, "flow": true, "detection_filter": true,
	"threshold": true, "flags": true, "ttl": true, "tos": true, "id": true,
	"seq": true, "ack": true, "window": true, "fragbits": true,
	"fragoffset": true, "itype": true, "icode": true,
	"icmp_id": true, "icmp_seq": true, "sameip": true,
	"ssl_version": true, "ftpbounce": true, "asn1": true, "rpc": true,
}

// common handles the options both Snort dialects share.
func (c *conv) common(o rawOpt) {
	name, v := o.Name, o.Value
	switch {
	case passthrough[name]:
		c.keep(o)
	case name == "metadata":
		for _, e := range splitArgs(v) {
			f := strings.Fields(e)
			if len(f) == 2 && f[0] == "service" {
				c.services = append(c.services, strings.ToLower(f[1]))
			}
		}
		c.keep(o)
	case name == "flowbits":
		c.flowbits(v)
	case name == "ssl_state":
		// Snort ORs a comma separated list; Suricata uses '|'.
		c.keep(rawOpt{Name: name, Value: strings.ReplaceAll(strings.ReplaceAll(v, " ", ""), ",", "|"), HasValue: true})
	case name == "dce_opnum":
		// Snort 3 also separates opnums with spaces ("16 23 40-41").
		c.keep(rawOpt{Name: name, Value: strings.Join(strings.Fields(strings.ReplaceAll(strings.Trim(v, `"`), ",", " ")), ","), HasValue: true})
	case name == "ip_proto":
		// Suricata only accepts ip_proto in "ip" rules; it is redundant
		// when it names the header protocol.
		if n, ok := ipProtoNumbers[strings.ToLower(c.r.Proto)]; ok && strings.TrimSpace(v) == n {
			return
		}
		c.keep(o)
	case name == "ipopts" && v == "lsrre":
		// Suricata has no separate check for the LSRR variant Snort calls
		// lsrre; lsrr matches every LSRR option.
		c.approx(CodeUnsupported, "ipopts:lsrre widened to ipopts:lsrr")
		c.keep(rawOpt{Name: name, Value: "lsrr", HasValue: true})
	case name == "ipopts":
		c.keep(o)
	case name == "modbus_func":
		c.modbusFunc(v)
	case name == "dnp3_ind":
		c.keep(rawOpt{Name: name, Value: strings.Trim(v, `"`), HasValue: true})
		c.note(CodeConfig, "needs app-layer.protocols.dnp3 enabled in suricata.yaml")
	case name == "sip_method":
		c.sipMethod(v)
	case name == "sip_stat_code":
		c.sipStatCode(v)
	default:
		if why := snort3Unsupported[name]; why != "" {
			c.fail(CodeUnsupported, "%s: %s", name, why)
			return
		}
		c.fail(CodeUnsupported, "option %q is not supported", name)
	}
}

// flowbits splits "a&b" groups, which Suricata does not support for state
// changing commands, into one option per bit. Snort applies the command to
// every bit, and isset/isnotset with '&' require all of them, so separate
// options are equivalent.
func (c *conv) flowbits(v string) {
	a := splitArgs(v)
	switch {
	case len(a) == 1:
		c.keep(rawOpt{Name: "flowbits", Value: v, HasValue: true})
		return
	case len(a) == 3:
		c.fail(CodeUnsupported, "flowbit groups (%q) are not supported by Suricata", v)
		return
	case len(a) != 2:
		c.fail(CodeSyntax, "invalid flowbits %q", v)
		return
	}
	cmd, names := a[0], a[1]
	if strings.Contains(names, "&") {
		if strings.Contains(names, "|") {
			c.fail(CodeSyntax, "flowbits mixes & and | (%q)", v)
			return
		}
		for _, n := range strings.Split(names, "&") {
			c.keep(rawOpt{Name: "flowbits", Value: cmd + "," + strings.TrimSpace(n), HasValue: true})
		}
		return
	}
	if strings.Contains(names, "|") && cmd != "isset" && cmd != "isnotset" {
		c.fail(CodeUnsupported, "flowbits %q: Suricata supports | only for isset/isnotset", v)
		return
	}
	c.keep(rawOpt{Name: "flowbits", Value: cmd + "," + names, HasValue: true})
}

// sipMethod converts "sip_method:[!]m1[,m2...]" to a sip.method match.
// Snort compares method names case-insensitively.
func (c *conv) sipMethod(v string) {
	var methods []string
	neg := false
	for _, m := range splitArgs(v) {
		if strings.HasPrefix(m, "!") {
			neg = true
			m = m[1:]
		}
		if !reSIPMethod.MatchString(m) {
			c.fail(CodeSyntax, "invalid sip_method %q", v)
			return
		}
		methods = append(methods, strings.ToUpper(m))
	}
	p := &op{explicit: bufSIPMethod, synthetic: true}
	if len(methods) == 1 {
		p.Kind = "content"
		p.C = &content{Neg: neg, Str: methods[0], Nocase: true, StartsWith: true, EndsWith: true}
	} else {
		p.Kind, p.PcreNeg = "pcre", neg
		p.PcreRe = "^(?:" + strings.Join(methods, "|") + ")$"
		p.PcreFlags = "i"
	}
	c.items = append(c.items, item{op: p})
}

// sipStatCode converts "sip_stat_code:<code>[,<code>...]"; a single digit
// matches the whole class (4 matches 4xx).
func (c *conv) sipStatCode(v string) {
	var alts []string
	for _, s := range splitArgs(v) {
		switch {
		case reSIPStatClass.MatchString(s):
			alts = append(alts, s+`\d\d`)
		case reSIPStatCode.MatchString(s):
			alts = append(alts, s)
		default:
			c.fail(CodeSyntax, "invalid sip_stat_code %q", v)
			return
		}
	}
	p := &op{explicit: bufSIPStatCode, synthetic: true}
	switch {
	case len(alts) == 1 && len(alts[0]) == 3:
		p.Kind = "content"
		p.C = &content{Str: alts[0], StartsWith: true, EndsWith: true}
	case len(alts) == 1:
		p.Kind = "content"
		p.C = &content{Str: alts[0][:1], StartsWith: true}
		c.items = append(c.items, item{op: p})
		p = &op{Kind: "bsize", Args: []string{"3"}, explicit: bufSIPStatCode, synthetic: true}
	default:
		p.Kind = "pcre"
		p.PcreRe = "^(?:" + strings.Join(alts, "|") + ")$"
	}
	c.items = append(c.items, item{op: p})
}

var ipProtoNumbers = map[string]string{"tcp": "6", "udp": "17", "icmp": "1"}

// modbusFunctions are Snort's modbus_func names.
var modbusFunctions = map[string]int{
	"read_coils": 1, "read_discrete_inputs": 2, "read_holding_registers": 3,
	"read_input_registers": 4, "write_single_coil": 5, "write_single_register": 6,
	"read_exception_status": 7, "diagnostics": 8, "get_comm_event_counter": 11,
	"get_comm_event_log": 12, "write_multiple_coils": 15,
	"write_multiple_registers": 16, "report_slave_id": 17, "read_file_record": 20,
	"write_file_record": 21, "mask_write_register": 22,
	"read_write_multiple_registers": 23, "read_fifo_queue": 24,
	"encapsulated_interface_transport": 43,
}

// modbusFunc converts "modbus_func:<name|number>" to "modbus:function <n>".
func (c *conv) modbusFunc(v string) {
	v = strings.ToLower(strings.TrimSpace(v))
	n, ok := modbusFunctions[v]
	if !ok {
		if n, ok = atoi(v); !ok || n < 0 || n > 255 {
			c.fail(CodeSyntax, "invalid modbus_func %q", v)
			return
		}
	}
	c.keep(rawOpt{Name: "modbus", Value: fmt.Sprintf("function %d", n), HasValue: true})
	c.note(CodeConfig, "needs app-layer.protocols.modbus enabled in suricata.yaml")
}
