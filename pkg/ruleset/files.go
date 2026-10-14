package ruleset

import (
	"cmp"
	"slices"
	"strings"
)

// SourceFile is a file of a rule source, e.g. one entry of a provider's
// rule tree. Name is used as the group of the rules it contains.
type SourceFile struct {
	Name    string
	Content []byte
}

// DefaultIgnore is suricata-update's default list of ignored rule files.
var DefaultIgnore = []string{"*deleted.rules"}

// LoadOptions configures ParseFiles.
type LoadOptions struct {
	// Ignore lists fnmatch patterns matched against the base name of rule
	// files to skip (suricata-update's "ignore" setting). suricata-update
	// uses DefaultIgnore unless configured otherwise.
	Ignore []string
	// Logf, if non-nil, receives warnings about unparsable rules.
	Logf func(format string, args ...any)
}

// ParseFiles loads rules from source files the way suricata-update does
// before processing: files are visited sorted by name, files whose name
// contains "classification.config" are skipped, other files not ending in
// ".rules" are returned as dependency files (for Config.DepFiles), and
// ".rules" files not matching opts.Ignore are parsed with their name as
// group. The returned rules are in the order Process expects.
func ParseFiles(files []SourceFile, opts LoadOptions) (rules []*Rule, depFiles map[string][]byte, err error) {
	ignore := make([]*globMatcher, 0, len(opts.Ignore))
	for _, p := range opts.Ignore {
		m, err := newGlobMatcher(p, false)
		if err != nil {
			return nil, nil, err
		}
		ignore = append(ignore, m)
	}
	sorted := slices.Clone(files)
	slices.SortStableFunc(sorted, func(a, b SourceFile) int { return cmp.Compare(a.Name, b.Name) })

	depFiles = map[string][]byte{}
	for _, f := range sorted {
		if strings.Contains(f.Name, "classification.config") {
			continue
		}
		if !strings.HasSuffix(f.Name, ".rules") {
			depFiles[f.Name] = f.Content
			continue
		}
		base := pyBasename(f.Name)
		if slices.ContainsFunc(ignore, func(m *globMatcher) bool { return m.re.MatchString(base) }) {
			if opts.Logf != nil {
				opts.Logf("Ignoring file %s", f.Name)
			}
			continue
		}
		var onError func(int, string, error)
		if opts.Logf != nil {
			onError = func(line int, text string, err error) {
				opts.Logf("Failed to parse rule: %s:%d: %s: %v", f.Name, line, text, err)
			}
		}
		rs, err := parseContent(f.Name, f.Content, onError)
		if err != nil {
			return nil, nil, err
		}
		rules = append(rules, rs...)
	}
	return rules, depFiles, nil
}
