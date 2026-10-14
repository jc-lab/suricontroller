package ruleset

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Rule is one parsed Suricata rule (possibly commented out / disabled).
//
// A Rule mirrors suricata-update's rule object. String renders the rule
// from the raw text it was parsed from, so only Enabled and Noalert affect
// the output; the remaining fields are informational and changing them does
// not rewrite the rule text.
type Rule struct {
	Enabled bool   // false when the line was commented out ("# alert ...")
	Action  string // alert, drop, pass, reject, sdrop, log, activate, dynamic
	Header  string // everything after the action, e.g. "tcp $HOME_NET any -> $EXTERNAL_NET any"
	GID     uint32 // default 1
	SID     uint32
	Rev     uint32
	Msg     string
	// Group is the source file name used by "group:" (base name) and
	// "filename:" (full name) matchers, e.g. "et-open/emerging-dns.rules".
	// An empty Group means the rule has no group.
	Group      string
	Noalert    bool
	Flowbits   []string // raw flowbits option values, e.g. "set,foo", "isset,foo"
	Metadata   []string // raw metadata entries, e.g. "created_at 2010_09_23"
	References []string // raw reference option values
	Classtype  string

	raw string // rule text without the disabled prefix

	proto, srcAddr, srcPort, direction, dstAddr, dstPort string

	// noalertParsed is the noalert state derived from the rule text at parse
	// time (suricata-update's rule["noalert"]), which is what drop filters
	// consult; Noalert may additionally be set by flowbits resolution.
	noalertParsed bool
	// groupless is set when suricata-update would have lost the group: drop
	// filters re-parse the rule without one.
	groupless bool
	// nilFlowbit is set when a "flowbits" option has no value, which makes
	// suricata-update's flowbit resolver crash.
	nilFlowbit bool
	usesLua    bool

	hasDataset bool   // a "dataset" option is present
	datasetNil bool   // the last "dataset" option has no value
	dataset    string // value of the last "dataset" option

	// datasetPath/datasetData are set when Process rewrote a dataset load.
	datasetPath string
	datasetData []byte
}

// Errors returned by Parse for lines that look like rules but that
// suricata-update rejects (it logs them and skips the line).
var (
	ErrNoSID          = errors.New("ruleset: sid cannot be null")
	ErrNoEndOfOption  = errors.New("ruleset: no end of option")
	errOptIndex       = errors.New("ruleset: malformed option list")
	errNoMetadataVal  = errors.New("ruleset: metadata option without value")
	errBadIntOption   = errors.New("ruleset: invalid integer option")
	errIntOutOfRange  = errors.New("ruleset: gid/sid/rev out of uint32 range")
	errNoActionParsed = errors.New("ruleset: re-parsed rule is not a rule")
)

var ruleActions = map[string]bool{
	"alert": true, "log": true, "pass": true, "activate": true,
	"dynamic": true, "drop": true, "reject": true, "sdrop": true,
}

var noalertRe = regexp.MustCompile(` *sid: *[0-9]+;`)

// Parse parses a single rule line the way suricata-update does. It returns
// (nil, nil) for blank lines, comments and lines suricata-update does not
// consider a rule (including actions it does not know, such as rejectsrc).
// A non-nil error is returned for rule-like lines that suricata-update
// fails to parse; it skips those lines too.
func Parse(line string) (*Rule, error) {
	return parseRule(line, "", true)
}

// parseRule emulates suricata.update.rule.parse(buf, group).
func parseRule(buf, group string, groupless bool) (*Rule, error) {
	s := pyStrip(buf)

	// Emulate rule_pattern:
	//   ^(?P<enabled>#)*[\s#]*(?P<raw>(?P<header>[^()]+)\((?P<options>.*)\)$)
	// Any match that needs to backtrack into the leading [\s#]* run yields a
	// header made of '#' and whitespace only, which never has a valid action.
	i := 0
	for i < len(s) {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r != '#' && !isPySpace(r) {
			break
		}
		i += size
	}
	rest := s[i:]
	p := strings.IndexByte(rest, '(')
	if p <= 0 || strings.IndexByte(rest[:p], ')') >= 0 {
		return nil, nil
	}
	if len(rest) < p+2 || rest[len(rest)-1] != ')' {
		return nil, nil
	}
	optText := rest[p+1 : len(rest)-1]
	if strings.IndexByte(optText, '\n') >= 0 {
		return nil, nil
	}
	header := pyStrip(rest[:p])

	r := &Rule{
		Enabled:   !strings.HasPrefix(s, "#"),
		Group:     group,
		groupless: groupless,
		GID:       1,
		raw:       rest,
	}

	if !strings.Contains(header, " ") {
		r.Action = header
	} else {
		rem := header
		for state := 0; state < 7; state++ {
			if rem == "" {
				return nil, nil
			}
			var tok string
			if rem[0] == '[' {
				end := strings.IndexByte(rem, ']')
				if end < 0 {
					return nil, nil
				}
				end++
				tok, rem = pyStrip(rem[:end]), pyStrip(rem[end:])
			} else if end := strings.IndexByte(rem, ' '); end < 0 {
				tok, rem = rem, ""
			} else {
				tok, rem = pyStrip(rem[:end]), pyStrip(rem[end:])
			}
			switch state {
			case 0:
				r.Action = tok
			case 1:
				r.proto = tok
			case 2:
				r.srcAddr = tok
			case 3:
				r.srcPort = tok
			case 4:
				r.direction = tok
			case 5:
				r.dstAddr = tok
			case 6:
				r.dstPort = tok
			}
		}
		r.Header = pyStrip(header[strings.IndexByte(header, ' '):])
	}
	if !ruleActions[r.Action] {
		return nil, nil
	}

	var sid int64
	opts := []rune(optText)
	for len(opts) > 0 {
		idx, err := findOptEnd(opts)
		if err != nil {
			return nil, err
		}
		if idx < 0 {
			return nil, ErrNoEndOfOption
		}
		option := string(pyStripRunes(opts[:idx]))
		opts = pyStripRunes(opts[idx+1:])

		name, val, hasVal := option, "", false
		if c := strings.IndexByte(option, ':'); c >= 0 {
			name, val, hasVal = pyStrip(option[:c]), pyStrip(option[c+1:]), true
		}

		switch name {
		case "gid", "sid", "rev":
			if !hasVal {
				return nil, errBadIntOption
			}
			v, ok, overflow := pyInt(val)
			if !ok {
				return nil, fmt.Errorf("%w: %s:%s", errBadIntOption, name, val)
			}
			if overflow || v < 0 || v > math.MaxUint32 {
				return nil, fmt.Errorf("%w: %s:%s", errIntOutOfRange, name, val)
			}
			switch name {
			case "gid":
				r.GID = uint32(v)
			case "sid":
				sid = v
				r.SID = uint32(v)
			case "rev":
				r.Rev = uint32(v)
			}
		case "metadata":
			if !hasVal {
				return nil, errNoMetadataVal
			}
			for _, v := range strings.Split(val, ",") {
				r.Metadata = append(r.Metadata, pyStrip(v))
			}
		case "flowbits":
			r.Flowbits = append(r.Flowbits, val)
			if !hasVal {
				r.nilFlowbit = true
			}
			if strings.Contains(val, "noalert") {
				r.noalertParsed = true
			}
		case "noalert":
			r.noalertParsed = true
		case "reference":
			r.References = append(r.References, val)
		case "msg":
			if hasVal && strings.HasPrefix(val, `"`) && strings.HasSuffix(val, `"`) {
				if len(val) >= 2 {
					val = val[1 : len(val)-1]
				} else {
					val = ""
				}
			}
			r.Msg = val
		default:
			// suricata-update stores every other option in the rule dict
			// under its own name; these are the ones that matter later.
			switch name {
			case "classtype":
				r.Classtype = val
			case "dataset":
				r.hasDataset, r.dataset, r.datasetNil = true, val, !hasVal
			case "lua", "luajit":
				r.usesLua = true
			case "enabled":
				r.Enabled = hasVal && val != ""
			case "group":
				r.Group, r.groupless = val, !hasVal
			}
		}
	}
	if sid == 0 {
		return nil, ErrNoSID
	}
	r.Noalert = r.noalertParsed
	return r, nil
}

// findOptEnd emulates suricata-update's find_opt_end, including its quirky
// handling of escaped semicolons and Python's negative indexing.
func findOptEnd(o []rune) (int, error) {
	n := len(o)
	offset := 0
	for {
		i := -1
		if offset < n {
			for k, c := range o[offset:] {
				if c == ';' {
					i = k
					break
				}
			}
		}
		idx := offset + i - 1
		if idx < 0 {
			idx += n
		}
		if idx < 0 || idx >= n {
			return 0, errOptIndex
		}
		if o[idx] == '\\' {
			offset += 2
			continue
		}
		return offset + i, nil
	}
}

// ParseFile parses all rules in r, attributing them to group. Rules
// continued over several lines with a trailing backslash are joined like
// suricata-update does. Lines that fail to parse are skipped, as
// suricata-update does; use ParseFileFunc to observe them. An error is
// returned for read errors and for invalid UTF-8 (which aborts
// suricata-update).
func ParseFile(group string, r io.Reader) ([]*Rule, error) {
	return ParseFileFunc(group, r, nil)
}

// ParseFileFunc is like ParseFile but calls onError, if non-nil, for every
// rule-like line that could not be parsed. line is the 1-based number of
// the first physical line of the (possibly continued) rule.
func ParseFileFunc(group string, r io.Reader, onError func(line int, text string, err error)) ([]*Rule, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return parseContent(group, data, onError)
}

func parseContent(group string, data []byte, onError func(int, string, error)) ([]*Rule, error) {
	var (
		rules     []*Rule
		buf       strings.Builder
		lineNo    int
		startLine = 1
	)
	for len(data) > 0 {
		var line []byte
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			line, data = data[:i+1], data[i+1:]
		} else {
			line, data = data, nil
		}
		lineNo++
		if !utf8.Valid(line) {
			return nil, fmt.Errorf("ruleset: %s:%d: invalid UTF-8", group, lineNo)
		}
		if buf.Len() == 0 {
			startLine = lineNo
		}
		s := string(line)
		if t := pyRStrip(s); strings.HasSuffix(t, `\`) {
			buf.WriteString(t[:len(t)-1])
			buf.WriteByte(' ')
			continue
		}
		buf.WriteString(s)
		text := buf.String()
		buf.Reset()
		rule, err := parseRule(text, group, group == "")
		if err != nil {
			if onError != nil {
				onError(startLine, pyRStrip(text), err)
			}
			continue
		}
		if rule != nil {
			rules = append(rules, rule)
		}
	}
	// A continuation pending at end of file is dropped, like suricata-update.
	return rules, nil
}

// ID returns the rule identifier formatted as "gid:sid".
func (r *Rule) ID() string {
	return strconv.FormatUint(uint64(r.GID), 10) + ":" + strconv.FormatUint(uint64(r.SID), 10)
}

// String returns the rule formatted exactly as suricata-update writes it:
// disabled rules get a "# " prefix and rules flagged Noalert get a
// "noalert;" option inserted before their sid option if missing.
func (r *Rule) String() string {
	return r.prefix() + r.noalertRaw()
}

// UsesLua reports whether the rule has a lua or luajit keyword.
func (r *Rule) UsesLua() bool { return r.usesLua }

func (r *Rule) prefix() string {
	if r.Enabled {
		return ""
	}
	return "# "
}

func (r *Rule) noalertRaw() string {
	if r.Noalert && !strings.Contains(r.raw, "noalert;") {
		return noalertRe.ReplaceAllString(r.raw, " noalert;${0}")
	}
	return r.raw
}

// format emulates Rule.format(), which also persists the noalert insertion
// into the raw text.
func (r *Rule) format() string {
	r.raw = r.noalertRaw()
	return r.prefix() + r.raw
}

// group returns the group as suricata-update sees it; ok is false when the
// rule has no group (Python None).
func (r *Rule) group() (string, bool) {
	if r.groupless || r.Group == "" {
		return "", false
	}
	return r.Group, true
}

func (r *Rule) clone() *Rule {
	c := *r
	c.Flowbits = append([]string(nil), r.Flowbits...)
	c.Metadata = append([]string(nil), r.Metadata...)
	c.References = append([]string(nil), r.References...)
	return &c
}

// Write writes rules to w in the format of suricata-update's merged output
// file (suricata.rules): one formatted rule per line, in the given order.
func Write(w io.Writer, rules []*Rule) error {
	bw := bufio.NewWriter(w)
	for _, r := range rules {
		if r == nil {
			continue
		}
		_, _ = bw.WriteString(r.String())
		_ = bw.WriteByte('\n')
	}
	return bw.Flush()
}
