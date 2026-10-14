package ruleset

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ruleFilter is a drop.conf or modify.conf entry.
type ruleFilter interface {
	match(*Rule) (bool, error)
	// run returns the filtered rule, which may be r itself.
	run(r *Rule, logf func(string, ...any)) (*Rule, error)
}

// dropFilter turns matching rules into drop rules (DropRuleFilter).
type dropFilter struct{ m ruleMatcher }

func (f *dropFilter) match(r *Rule) (bool, error) {
	if r.noalertParsed {
		return false, nil
	}
	return f.m.matchErr(r)
}

func (f *dropFilter) run(r *Rule, _ func(string, ...any)) (*Rule, error) {
	// re.sub("^\w+", "drop", rule.raw), re-parsed without a group.
	n := 0
	for _, c := range r.raw {
		if !isPyWord(c) {
			break
		}
		n += len(string(c))
	}
	d, err := parseRule("drop"+r.raw[n:], r.Group, true)
	if err != nil {
		return nil, fmt.Errorf("ruleset: rule %s: drop: %w", r.ID(), err)
	}
	if d == nil {
		return nil, fmt.Errorf("ruleset: rule %s: drop: %w", r.ID(), errNoActionParsed)
	}
	d.Enabled = r.Enabled
	return d, nil
}

// modifyFilter applies a regex substitution to the formatted rule
// (ModifyRuleFilter).
type modifyFilter struct {
	m       ruleMatcher
	rx      *pyRegex
	tmpl    *pyTemplate
	tmplErr error // raised by Python when the substitution runs
}

func (f *modifyFilter) match(r *Rule) (bool, error) { return f.m.matchErr(r) }

func (f *modifyFilter) run(r *Rule, logf func(string, ...any)) (*Rule, error) {
	if f.tmplErr != nil {
		return nil, f.tmplErr
	}
	modified, err := f.rx.sub(f.tmpl, r.format())
	if err != nil {
		return nil, err
	}
	return reparse(r, modified, "Modification of rule [%s] results in invalid rule: %s", logf)
}

// metadataAddFilter appends a metadata option (AddMetadataFilter).
type metadataAddFilter struct {
	m       ruleMatcher
	tmpl    *pyTemplate
	tmplErr error
}

var metadataAddRx = func() *pyRegex {
	rx, err := compilePyRegex(`;\s*\)$`, 0)
	if err != nil {
		panic(err)
	}
	return rx
}()

func (f *metadataAddFilter) match(r *Rule) (bool, error) { return f.m.matchErr(r) }

func (f *metadataAddFilter) run(r *Rule, logf func(string, ...any)) (*Rule, error) {
	if f.tmplErr != nil {
		return nil, f.tmplErr
	}
	modified, err := metadataAddRx.sub(f.tmpl, r.format())
	if err != nil {
		return nil, err
	}
	return reparse(r, modified, "Rule is not valid after adding metadata: [%s]: %s", logf)
}

// reparse parses modified with r's group. As in suricata-update, a result
// that is not a rule keeps the original rule, while a parse exception is
// fatal.
func reparse(r *Rule, modified, invalidMsg string, logf func(string, ...any)) (*Rule, error) {
	n, err := parseRule(modified, r.Group, r.groupless)
	if err != nil {
		return nil, fmt.Errorf("ruleset: rule %s: modified rule %q: %w", r.ID(), modified, err)
	}
	if n == nil {
		logf(invalidMsg, r.ID(), modified)
		return r, nil
	}
	return n, nil
}

var oinkmasterBackref = regexp.MustCompile(`\$\{(\p{Nd}+)\}`)

// parseModifyLine parses one modify.conf entry (after comment stripping),
// following load_filters, ModifyRuleFilter.parse and AddMetadataFilter.parse.
// Python only compiles the replacement template when the filter first
// runs; strict reports template errors immediately instead.
func parseModifyLine(line string, strict bool) (ruleFilter, error) {
	if strings.HasPrefix(line, "metadata-add") {
		tokens, err := shlexSplit(line)
		if err != nil || len(tokens) != 4 {
			return nil, errors.New("metadata-add: invalid number of arguments")
		}
		m, err := parseRuleMatch(tokens[1])
		if err != nil {
			return nil, err
		}
		f := &metadataAddFilter{m: m}
		f.tmpl, f.tmplErr = parsePyTemplate(fmt.Sprintf("; metadata: %s %s;)", tokens[2], tokens[3]), metadataAddRx)
		if strict && f.tmplErr != nil {
			return nil, f.tmplErr
		}
		return f, nil
	}

	line = strings.ReplaceAll(line, `\$`, `$`)
	tokens, err := shlexSplit(line)
	if err != nil {
		return nil, err
	}
	var matchString, pattern, repl string
	switch {
	case len(tokens) == 3:
		matchString, pattern, repl = tokens[0], tokens[1], tokens[2]
	case len(tokens) > 4 && tokens[0] == "modifysid":
		matchString, pattern, repl = tokens[1], tokens[2], tokens[4]
	default:
		return nil, errors.New("bad number of arguments")
	}
	m, err := parseRuleMatch(matchString)
	if err != nil {
		return nil, err
	}
	rx, err := compilePyRegex(pattern, 0)
	if err != nil {
		return nil, err
	}
	if rx.nullable {
		return nil, fmt.Errorf("%w: modify pattern %q can match the empty string", ErrUnsupported, pattern)
	}
	// Convert Oinkmaster style ${1} references to Python \1.
	repl = oinkmasterBackref.ReplaceAllString(repl, `\${1}`)
	f := &modifyFilter{m: m, rx: rx}
	f.tmpl, f.tmplErr = parsePyTemplate(repl, rx)
	if strict && f.tmplErr != nil {
		return nil, f.tmplErr
	}
	return f, nil
}
