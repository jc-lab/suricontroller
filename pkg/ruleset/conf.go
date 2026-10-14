package ruleset

import (
	"errors"
	"fmt"
	"strings"
)

// ConfError describes an invalid line of a disable/enable/drop/modify conf.
type ConfError struct {
	Kind string // "disable", "enable", "drop" or "modify"
	Line int    // 1-based line number within the conf lines
	Text string // the line, after comment stripping
	Err  error
}

func (e *ConfError) Error() string {
	return fmt.Sprintf("ruleset: %s.conf line %d: %q: %v", e.Kind, e.Line, e.Text, e.Err)
}

func (e *ConfError) Unwrap() error { return e.Err }

// ValidateConfig strictly checks every non-comment line of cfg.Disable,
// cfg.Enable, cfg.Drop and cfg.Modify without needing any rules, e.g. to
// reject bad edits before they are committed. It reports unparsable
// matcher specs, invalid or unsupported regular expressions in "re:"
// matchers and modify.conf patterns and replacements, and malformed modify
// lines. The result joins one *ConfError per bad line (use errors.As to
// inspect them); it is nil when the configuration is valid.
//
// cfg.IgnoreInvalid is not consulted: validation is always strict.
func ValidateConfig(cfg Config) error {
	_, err := compileConfig(cfg, true, func(string, ...any) {})
	return err
}

// compiledConfig is a parsed Config.
type compiledConfig struct {
	disable, enable []ruleMatcher
	drop, modify    []ruleFilter
}

// compileConfig parses the conf lines. In strict mode every bad line is an
// error; otherwise lines that suricata-update ignores with a warning are
// logged and skipped, and replacement template errors are deferred until a
// rule matches (when suricata-update would crash), exactly like
// suricata-update. All errors are collected and joined.
func compileConfig(cfg Config, strict bool, logf func(string, ...any)) (*compiledConfig, error) {
	var (
		cc   compiledConfig
		errs []error
	)
	matchers := func(kind string, lines []string) []ruleMatcher {
		var ms []ruleMatcher
		confLines(lines, func(n int, l string) {
			m, err := parseRuleMatch(l)
			switch {
			case err == nil:
				ms = append(ms, m)
			case !strict && errors.Is(err, ErrNoMatcher):
				logf("%s.conf line %d: Failed to parse: %q", kind, n, l)
			default:
				errs = append(errs, &ConfError{Kind: kind, Line: n, Text: l, Err: err})
			}
		})
		return ms
	}
	cc.disable = matchers("disable", cfg.Disable)
	cc.enable = matchers("enable", cfg.Enable)
	for _, m := range matchers("drop", cfg.Drop) {
		cc.drop = append(cc.drop, &dropFilter{m: m})
	}
	confLines(cfg.Modify, func(n int, l string) {
		f, err := parseModifyLine(pyStrip(l), strict)
		if err != nil {
			errs = append(errs, &ConfError{Kind: "modify", Line: n, Text: l, Err: err})
			return
		}
		cc.modify = append(cc.modify, f)
	})
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return &cc, nil
}

// confLines emulates the comment handling of suricata-update's conf file
// readers and calls fn with the 1-based line number and content of every
// remaining line: lines are stripped, blank lines and lines starting with
// "#" are skipped and anything from the first " #" on is removed. An
// element of lines may hold several lines; numbering runs across elements.
func confLines(lines []string, fn func(n int, line string)) {
	n := 0
	for _, line := range lines {
		// Python reads conf files with universal newlines.
		line = strings.ReplaceAll(line, "\r\n", "\n")
		line = strings.ReplaceAll(line, "\r", "\n")
		for _, l := range strings.Split(line, "\n") {
			n++
			l = pyStrip(l)
			if l == "" || strings.HasPrefix(l, "#") {
				continue
			}
			if i := strings.Index(l, " #"); i >= 0 {
				l = l[:i]
			}
			fn(n, l)
		}
	}
}
