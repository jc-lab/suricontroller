package snortconv

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Dialect is the Snort rule language of the input.
type Dialect int

const (
	// Auto detects the dialect of each rule (see DetectDialect).
	Auto Dialect = iota
	// Snort2 is the Snort 2.9 rule language (content modifiers).
	Snort2
	// Snort3 is the Snort 3 rule language (sticky buffers, service).
	Snort3
)

func (d Dialect) String() string {
	switch d {
	case Snort2:
		return "snort2"
	case Snort3:
		return "snort3"
	}
	return "auto"
}

// ParseDialect parses "auto", "snort2" or "snort3".
func ParseDialect(s string) (Dialect, error) {
	switch strings.ToLower(s) {
	case "", "auto":
		return Auto, nil
	case "snort2", "2":
		return Snort2, nil
	case "snort3", "3":
		return Snort3, nil
	}
	return Auto, fmt.Errorf("unknown dialect %q", s)
}

// Status is the outcome of converting one rule.
type Status int

const (
	// Exact means the Suricata rule inspects the same data with the same
	// conditions, as far as the two engines' buffers correspond.
	Exact Status = iota
	// Approx means the rule was converted with a documented change in
	// meaning (see the issues with Severity Approx).
	Approx
	// Failed means the rule has no Suricata equivalent.
	Failed
)

func (s Status) String() string {
	switch s {
	case Exact:
		return "exact"
	case Approx:
		return "approx"
	}
	return "failed"
}

// MarshalText implements encoding.TextMarshaler.
func (s Status) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// Issue codes.
const (
	CodeSyntax          = "syntax"           // the Snort rule is malformed
	CodeUnsupported     = "unsupported"      // no Suricata equivalent
	CodeAction          = "action"           // action without Suricata equivalent
	CodeProto           = "proto"            // header protocol without Suricata equivalent
	CodeNeverMatches    = "never-matches"    // the rule can never match
	CodePacketAppLayer  = "packet-app-layer" // Suricata cannot mix packet and app-layer matches
	CodeDirection       = "direction"        // buffers conflict with each other or the flow direction
	CodeApproxBuffer    = "approx-buffer"    // buffer mapped to a wider Suricata buffer
	CodeTagLimit        = "tag-limit"        // tag limits changed
	CodeFastPatternOnly = "fast-pattern-only"
	CodeFastPattern     = "fast-pattern-dropped"
	CodeRelativeReset   = "relative-reset"
	CodeRawPayload      = "raw-payload"
	CodeFlowbitsSplit   = "flowbits-split"
)

// Issue describes a change or a problem found while converting a rule.
type Issue struct {
	Code     string `json:"code"`
	Severity Status `json:"severity"` // Exact for informational notes
	Message  string `json:"message"`
}

// Result is the conversion of one rule.
type Result struct {
	GID, SID, Rev string
	Msg           string
	Enabled       bool // false for rules that were commented out
	Dialect       Dialect
	Status        Status
	Services      []string
	// Output is the Suricata rule, commented out when the source rule was.
	// It is empty when Status is Failed.
	Output string
	Issues []Issue
}

// ErrNotRule is returned by Convert for lines that are not rules.
var ErrNotRule = errNotRule

// Convert converts one Snort rule line. A commented out rule is converted
// and returned commented out. It returns ErrNotRule for comments, blank
// lines and other non-rule text, and another error for rule-like lines
// that cannot be parsed (Status is then Failed).
func Convert(line string, d Dialect) (*Result, error) {
	r, err := parseRule(line)
	if err != nil {
		if errors.Is(err, errNotRule) {
			return nil, err
		}
		res := &Result{Enabled: !strings.HasPrefix(strings.TrimSpace(line), "#"), Status: Failed}
		res.Issues = append(res.Issues, Issue{CodeSyntax, Failed, err.Error()})
		return res, nil
	}
	if d == Auto {
		d = ruleDialect(r)
	}
	c := &conv{d: d, r: r, res: &Result{Enabled: r.Enabled, Dialect: d}}
	for _, o := range r.Options {
		switch o.Name {
		case "gid":
			c.res.GID = o.Value
		case "sid":
			c.res.SID = o.Value
		case "rev":
			c.res.Rev = o.Value
		case "msg":
			_, c.res.Msg, _, _ = parseQuoted(o.Value)
		}
	}
	if c.res.GID == "" {
		c.res.GID = "1"
	}
	if d == Snort3 {
		c.lowerSnort3()
	} else {
		c.lowerSnort2()
	}
	c.res.Services = c.services
	out := c.emit()
	if c.res.Status != Failed {
		if !r.Enabled {
			out = "# " + out
		}
		c.res.Output = out
	}
	return c.res, nil
}

var snort3Only = regexp.MustCompile(`(^|; *)(service|rem|bufferlen|raw_data|http_param|http_version|http_true_ip|js_data|vba_data|ber_data|ber_skip|sd_pattern|http_raw_request|http_raw_status|regex) *[:;]|content: *!? *"(?:[^"\\]|\\.)*" *,`)
var snort2Only = regexp.MustCompile(`(^|; *)(uricontent|urilen|rawbytes|depth|offset|distance|within) *:|; *(rawbytes|nocase) *;|fast_pattern *: *only|content: *!? *"(?:[^"\\]|\\.)*" *; *(nocase|http_[a-z_]+) *;`)

// ruleDialect guesses the dialect of one rule from options that only exist
// in one of them. Rules without distinguishing options convert the same
// way in both, except for buffer selection, so Snort 2 is the default.
func ruleDialect(r *rawRule) Dialect {
	if r.Src == "" && r.Proto != "" {
		return Snort3
	}
	var b strings.Builder
	for _, o := range r.Options {
		b.WriteString(o.String())
		b.WriteString("; ")
	}
	s := b.String()
	if snort3Only.MatchString(s) {
		return Snort3
	}
	if snort2Only.MatchString(s) {
		return Snort2
	}
	// "http_uri; content:..." (sticky) versus "content:...; http_uri;".
	for i, o := range r.Options {
		if _, ok := snort3Sticky[o.Name]; ok && !o.HasValue && o.Name != "pkt_data" && o.Name != "file_data" && o.Name != "base64_data" && o.Name != "dce_stub_data" {
			if i > 0 && (r.Options[i-1].Name == "content" || r.Options[i-1].Name == "uricontent") {
				return Snort2
			}
			return Snort3
		}
	}
	return Snort2
}

// DetectDialect returns the dialect most rules of a file are written in.
func DetectDialect(lines []string) Dialect {
	n2, n3 := 0, 0
	for _, l := range lines {
		r, err := parseRule(l)
		if err != nil {
			continue
		}
		if ruleDialect(r) == Snort3 {
			n3++
		} else {
			n2++
		}
	}
	if n3 > n2 {
		return Snort3
	}
	return Snort2
}

// conv holds the state of one conversion.
type conv struct {
	d        Dialect
	r        *rawRule
	res      *Result
	items    []item
	services []string
}

func (c *conv) issue(sev Status, code, format string, args ...any) {
	c.res.Issues = append(c.res.Issues, Issue{Code: code, Severity: sev, Message: fmt.Sprintf(format, args...)})
	if sev > c.res.Status {
		c.res.Status = sev
	}
}

func (c *conv) fail(code, format string, args ...any) { c.issue(Failed, code, format, args...) }

func (c *conv) approx(code, format string, args ...any) { c.issue(Approx, code, format, args...) }

func (c *conv) note(code, format string, args ...any) {
	for _, i := range c.res.Issues {
		if i.Code == code {
			return
		}
	}
	c.issue(Exact, code, format, args...)
}

func (c *conv) keep(o rawOpt) { c.items = append(c.items, item{opt: &o}) }
