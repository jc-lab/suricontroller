package ruleset

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"
)

// Matcher selects rules, like the matchers of suricata-update's
// enable.conf, disable.conf and drop.conf.
type Matcher interface {
	// Match reports whether the rule is selected. It returns false when
	// suricata-update would have failed while evaluating the matcher (see
	// Process, which reports that case as an error).
	Match(*Rule) bool
}

// ErrNoMatcher is returned by ParseMatcher for specs that do not denote any
// matcher; suricata-update logs and ignores such conf lines.
var ErrNoMatcher = errors.New("ruleset: not a rule matcher")

// ruleMatcher is implemented by all matchers of this package; matchErr
// reports evaluation failures that would crash suricata-update.
type ruleMatcher interface {
	Matcher
	matchErr(*Rule) (bool, error)
}

// ParseMatcher parses a matcher spec using the same syntax and precedence
// as suricata-update's parse_rule_match:
//
//   - all rules
//     2019401, 1:2019401, ...   comma separated [gid:]sid list
//     re:<python regex>         case-insensitive search in the rule text
//     filename:<glob>           fnmatch on the full group (file name)
//     group:<glob>              fnmatch on the group's base name, with or without extension
//     <name>.rules              same as group:<name>.rules
//     metadata:<key> <value>    case-insensitive metadata key/value match
//
// The error wraps ErrNoMatcher when spec is not a matcher at all, and
// ErrUnsupported when it is a regular expression Python accepts but Go
// cannot reproduce.
func ParseMatcher(spec string) (Matcher, error) {
	m, err := parseRuleMatch(spec)
	if err != nil {
		return nil, err
	}
	return m, nil
}

func parseRuleMatch(buf string) (ruleMatcher, error) {
	if pyStrip(buf) == "*" {
		return allMatcher{}, nil
	}
	if m := parseIDMatcher(buf); m != nil {
		return m, nil
	}
	var reErr error
	if strings.HasPrefix(buf, "re:") {
		_, pat, _ := strings.Cut(buf, ":")
		rx, err := compilePyRegex(pyStrip(pat), pyFlagI)
		if err == nil {
			return &reMatcher{rx: rx}, nil
		}
		if errors.Is(err, ErrUnsupported) {
			return nil, err
		}
		// Python fails to compile it; suricata-update tries the
		// remaining matcher kinds.
		reErr = err
	}
	if strings.HasPrefix(buf, "filename:") {
		_, pat, _ := strings.Cut(buf, ":")
		return newGlobMatcher(pyStrip(pat), false)
	}
	if strings.HasPrefix(buf, "group:") {
		_, pat, _ := strings.Cut(buf, ":")
		return newGlobMatcher(pyStrip(pat), true)
	}
	if strings.HasSuffix(buf, ".rules") {
		return newGlobMatcher(pyStrip(buf), true)
	}
	if strings.HasPrefix(buf, "metadata:") {
		_, rest, _ := strings.Cut(buf, ":")
		key, val, ok := strings.Cut(pyStrip(rest), " ")
		if ok {
			return &metadataMatcher{key: pyLower(pyStrip(key)), value: pyLower(pyStrip(val))}, nil
		}
	}
	if reErr != nil {
		return nil, fmt.Errorf("%w: %q: %w", ErrNoMatcher, buf, reErr)
	}
	return nil, fmt.Errorf("%w: %q", ErrNoMatcher, buf)
}

type allMatcher struct{}

func (allMatcher) Match(*Rule) bool             { return true }
func (allMatcher) matchErr(*Rule) (bool, error) { return true, nil }
func (allMatcher) String() string               { return "*" }

type gidSID struct{ gid, sid int64 }

// idMatcher matches a list of gid:sid pairs.
type idMatcher struct{ ids []gidSID }

func parseIDMatcher(buf string) *idMatcher {
	m := &idMatcher{}
	for _, entry := range strings.Split(buf, ",") {
		entry = pyStrip(entry)
		gidStr, sidStr, hasGID := strings.Cut(entry, ":")
		if !hasGID {
			gidStr, sidStr = "1", entry
		}
		gid, ok1, of1 := pyInt(gidStr)
		sid, ok2, of2 := pyInt(sidStr)
		if !ok1 || !ok2 {
			return nil
		}
		// Values beyond int64 are valid for Python but match nothing.
		if of1 {
			gid = math.MinInt64
		}
		if of2 {
			sid = math.MinInt64
		}
		m.ids = append(m.ids, gidSID{gid, sid})
	}
	return m
}

func (m *idMatcher) Match(r *Rule) bool { ok, _ := m.matchErr(r); return ok }

func (m *idMatcher) matchErr(r *Rule) (bool, error) {
	for _, id := range m.ids {
		if id.gid == int64(r.GID) && id.sid == int64(r.SID) {
			return true, nil
		}
	}
	return false, nil
}

// reMatcher searches the raw rule text, case-insensitively.
type reMatcher struct{ rx *pyRegex }

func (m *reMatcher) Match(r *Rule) bool { ok, _ := m.matchErr(r); return ok }

func (m *reMatcher) matchErr(r *Rule) (bool, error) { return m.rx.search(r.raw) }

// globMatcher implements the filename: (full group) and group: (base name
// with or without extension) matchers.
type globMatcher struct {
	pattern string
	re      *regexp.Regexp
	base    bool
}

func newGlobMatcher(pattern string, base bool) (*globMatcher, error) {
	re, err := compileFnmatch(pattern)
	if err != nil {
		return nil, err
	}
	return &globMatcher{pattern: pattern, re: re, base: base}, nil
}

func (m *globMatcher) Match(r *Rule) bool { ok, _ := m.matchErr(r); return ok }

func (m *globMatcher) matchErr(r *Rule) (bool, error) {
	g, ok := r.group()
	if !ok {
		return false, nil
	}
	if !m.base {
		return m.re.MatchString(g), nil
	}
	b := pyBasename(g)
	return m.re.MatchString(b) || m.re.MatchString(pySplitextRoot(b)), nil
}

// metadataMatcher matches "key value" metadata entries case-insensitively.
type metadataMatcher struct{ key, value string }

func (m *metadataMatcher) Match(r *Rule) bool { ok, _ := m.matchErr(r); return ok }

func (m *metadataMatcher) matchErr(r *Rule) (bool, error) {
	for _, entry := range r.Metadata {
		k, v, hasValue := strings.Cut(pyStrip(entry), " ")
		if pyLower(pyStrip(k)) != m.key {
			continue
		}
		if !hasValue {
			// suricata-update raises IndexError here.
			return false, fmt.Errorf("ruleset: rule %s: metadata entry %q has no value", r.ID(), entry)
		}
		if pyLower(pyStrip(v)) == m.value {
			return true, nil
		}
	}
	return false, nil
}
