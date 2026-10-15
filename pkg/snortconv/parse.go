package snortconv

import (
	"errors"
	"fmt"
	"strings"
)

// rawRule is a rule split into its header fields and options, before any
// dialect specific interpretation.
type rawRule struct {
	Enabled bool // false when the rule was commented out ("# alert ...")
	Action  string
	Proto   string
	// Src, SrcPort, Dir, Dst and DstPort are empty for Snort 3 service
	// rules without addresses ("alert http (...)").
	Src, SrcPort, Dir, Dst, DstPort string
	Options                         []rawOpt
}

// rawOpt is one "name[:value]" rule option.
type rawOpt struct {
	Name     string
	Value    string
	HasValue bool
}

func (o rawOpt) String() string {
	if !o.HasValue {
		return o.Name
	}
	return o.Name + ":" + o.Value
}

var ruleActions = map[string]bool{
	"alert": true, "log": true, "pass": true, "drop": true, "reject": true,
	"sdrop": true, "block": true, "rewrite": true, "react": true,
	"activate": true, "dynamic": true, "file_id": true,
}

var errNotRule = errors.New("not a rule")

// parseRule parses one logical rule line. It returns errNotRule for blank
// lines, comments and other text that does not look like a rule.
func parseRule(line string) (*rawRule, error) {
	s := strings.TrimSpace(line)
	r := &rawRule{Enabled: true}
	if strings.HasPrefix(s, "#") {
		r.Enabled = false
		s = strings.TrimSpace(strings.TrimLeft(s, "# \t"))
	}
	p := strings.IndexByte(s, '(')
	if p < 0 || !strings.HasSuffix(s, ")") {
		return nil, errNotRule
	}
	hdr := strings.Fields(s[:p])
	if len(hdr) == 0 || !ruleActions[hdr[0]] {
		return nil, errNotRule
	}
	r.Action = hdr[0]
	switch len(hdr) {
	case 1:
		// Snort 3 "file_id (...)" style rule.
	case 2:
		r.Proto = hdr[1]
	case 7:
		r.Proto, r.Src, r.SrcPort, r.Dir, r.Dst, r.DstPort = hdr[1], hdr[2], hdr[3], hdr[4], hdr[5], hdr[6]
		if r.Dir != "->" && r.Dir != "<>" && r.Dir != "<-" {
			return nil, fmt.Errorf("invalid direction %q", r.Dir)
		}
	default:
		if !r.Enabled {
			return nil, errNotRule
		}
		return nil, fmt.Errorf("invalid rule header %q", strings.TrimSpace(s[:p]))
	}
	opts, err := splitOptions(s[p+1 : len(s)-1])
	if err != nil {
		if !r.Enabled {
			return nil, errNotRule
		}
		return nil, err
	}
	r.Options = opts
	return r, nil
}

// splitOptions splits the text between the rule parentheses on unquoted,
// unescaped semicolons.
func splitOptions(body string) ([]rawOpt, error) {
	var opts []rawOpt
	var cur strings.Builder
	inQuote := false
	for i := 0; i < len(body); i++ {
		c := body[i]
		switch {
		case c == '\\' && i+1 < len(body):
			cur.WriteByte(c)
			cur.WriteByte(body[i+1])
			i++
			continue
		case c == '"':
			inQuote = !inQuote
		case c == ';' && !inQuote:
			if o, ok := makeOpt(cur.String()); ok {
				opts = append(opts, o)
			}
			cur.Reset()
			continue
		}
		cur.WriteByte(c)
	}
	if inQuote {
		return nil, errors.New("unterminated quoted string")
	}
	if strings.TrimSpace(cur.String()) != "" {
		return nil, fmt.Errorf("option %q is not terminated by ';'", strings.TrimSpace(cur.String()))
	}
	return opts, nil
}

func makeOpt(s string) (rawOpt, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return rawOpt{}, false
	}
	if c := strings.IndexByte(s, ':'); c >= 0 {
		return rawOpt{Name: strings.TrimSpace(s[:c]), Value: strings.TrimSpace(s[c+1:]), HasValue: true}, true
	}
	return rawOpt{Name: s}, true
}

// splitArgs splits an option value on unquoted commas and trims each part.
func splitArgs(v string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c == '\\' && i+1 < len(v):
			cur.WriteByte(c)
			cur.WriteByte(v[i+1])
			i++
			continue
		case c == '"':
			inQuote = !inQuote
		case c == ',' && !inQuote:
			out = append(out, strings.TrimSpace(cur.String()))
			cur.Reset()
			continue
		}
		cur.WriteByte(c)
	}
	return append(out, strings.TrimSpace(cur.String()))
}

// parseQuoted parses `[!]"text"` at the start of s and returns the negation
// flag, the text between the quotes (escapes kept as written) and the rest
// of s after the closing quote.
func parseQuoted(s string) (neg bool, text, rest string, err error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "!") {
		neg = true
		s = strings.TrimSpace(s[1:])
	}
	if !strings.HasPrefix(s, "\"") {
		return false, "", "", fmt.Errorf("expected a quoted string in %q", s)
	}
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '"':
			return neg, s[1:i], s[i+1:], nil
		}
	}
	return false, "", "", fmt.Errorf("unterminated string in %q", s)
}
