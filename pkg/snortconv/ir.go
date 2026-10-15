package snortconv

import (
	"strconv"
	"strings"
)

// buf identifies the buffer a payload option inspects, independently of the
// engine: Snort 2 content modifiers and pcre flags, Snort 3 sticky buffers
// and Suricata sticky buffers all map to one of these.
type buf string

const (
	bufPkt         buf = "pkt"
	bufRaw         buf = "raw" // Snort rawbytes / raw_data: payload without Snort's normalizations
	bufFile        buf = "file"
	bufURI         buf = "uri"
	bufRawURI      buf = "raw_uri"
	bufURIPath     buf = "uri_path" // Snort 3 http_uri:path and friends
	bufURIQuery    buf = "uri_query"
	bufRawURIPath  buf = "raw_uri_path"
	bufRawURIQuery buf = "raw_uri_query"
	bufHeader      buf = "header"
	bufRawHeader   buf = "raw_header"
	bufCookie      buf = "cookie"
	bufRawCookie   buf = "raw_cookie"
	bufClientBody  buf = "client_body"
	bufServerBody  buf = "server_body" // only from Snort 3 http_raw_body on responses
	bufRawBody     buf = "raw_body"
	bufMethod      buf = "method"
	bufStatCode    buf = "stat_code"
	bufStatMsg     buf = "stat_msg"
	bufVersion     buf = "version"
	bufUserAgent   buf = "user_agent"
	bufHost        buf = "host"
	// Single header fields (Snort 3 http_header:field <name>).
	bufContentType buf = "content_type"
	bufContentLen  buf = "content_length"
	bufAccept      buf = "accept"
	bufAcceptEnc   buf = "accept_encoding"
	bufConnection  buf = "connection"
	bufReferer     buf = "referer"
	bufLocation    buf = "location"
	bufServer      buf = "server"
	bufRawRequest  buf = "raw_request"
	bufRawStatus   buf = "raw_status"
	bufBase64      buf = "base64"
	bufDCEStub     buf = "dce_stub"
	bufSIPHeader   buf = "sip_header"
	bufSIPBody     buf = "sip_body"
	bufSIPMethod   buf = "sip_method"
	bufSIPStatCode buf = "sip_stat_code"
)

// content is a content match with its modifiers. Numeric modifiers are kept
// as text because they may name byte_extract variables.
type content struct {
	Neg      bool
	Str      string // between the quotes, escapes as written
	Nocase   bool
	Offset   string
	Depth    string
	Distance string
	Within   string

	FastPattern bool
	FPOnly      bool   // Snort 2 fast_pattern:only
	FPOffset    string // fast_pattern:<offset>,<length>
	FPLength    string

	StartsWith, EndsWith bool

	Replace string // Snort replace:"..." (inline rewrite), quoted text
}

func (c *content) relative() bool { return c.Distance != "" || c.Within != "" }

// op is one payload option: something that inspects a buffer.
type op struct {
	Kind string // content, pcre, byte_test, byte_jump, byte_extract, byte_math, isdataat, base64_decode, bsize, isdataat_range
	Buf  buf
	C    *content

	// pcre
	PcreNeg   bool
	PcreRe    string // between the delimiters
	PcreFlags string

	// Args holds the comma separated arguments of byte_*, isdataat,
	// base64_decode and bsize options.
	Args []string

	// explicit is set when the buffer was fixed by the option itself (a
	// Snort 2 content modifier or pcre flag), as opposed to inherited from
	// the current sticky buffer.
	explicit buf
	// reset is set when the source engine starts this option at the
	// beginning of its buffer: it is the first payload option after a
	// buffer change, so "relative" refers to the start of the buffer.
	reset bool
	// synthetic marks ops generated from non-payload Snort options
	// (sip_method, sip_stat_code); they do not take part in cursor
	// tracking.
	synthetic bool
}

func (o *op) relative() bool {
	switch o.Kind {
	case "content":
		return o.C.relative()
	case "pcre":
		return strings.ContainsRune(o.PcreFlags, 'R')
	}
	return hasArg(o.Args, "relative")
}

func hasArg(args []string, name string) bool {
	for _, a := range args {
		if a == name {
			return true
		}
	}
	return false
}

func dropArg(args []string, name string) []string {
	out := args[:0:0]
	for _, a := range args {
		if a != name {
			out = append(out, a)
		}
	}
	return out
}

// item is an element of a lowered rule: either a payload op or a plain
// option already written in Suricata syntax.
type item struct {
	op     *op
	opt    *rawOpt
	sticky buf // a sticky buffer selection (only during lowering)
}

// contentLen returns the number of bytes a content string matches, or -1
// if it cannot be decoded.
func contentLen(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '|':
			end := strings.IndexByte(s[i+1:], '|')
			if end < 0 {
				return -1
			}
			hex := strings.Join(strings.Fields(s[i+1:i+1+end]), "")
			if len(hex)%2 != 0 {
				return -1
			}
			n += len(hex) / 2
			i += end + 1
		case '\\':
			if i+1 >= len(s) {
				return -1
			}
			i++
			n++
		default:
			n++
		}
	}
	return n
}

func atoi(s string) (int, bool) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	return n, err == nil
}
