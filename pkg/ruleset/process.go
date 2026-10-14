package ruleset

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
)

// Config holds the user rule-processing configuration, i.e. the contents
// of suricata-update's disable.conf, enable.conf, drop.conf and
// modify.conf.
type Config struct {
	// Disable, Enable, Drop and Modify are the raw lines of each conf
	// file. Comments and blank lines are allowed.
	Disable, Enable, Drop, Modify []string
	// ResolveFlowbits enables the flowbits pass that enables (with
	// noalert) the disabled rules setting flowbits checked by enabled
	// rules. suricata-update always does this; callers normally set it.
	ResolveFlowbits bool
	// DepFiles holds the non-rule files of the sources (e.g. dataset
	// lists), keyed by file name as returned by ParseFiles. They are used
	// to resolve "dataset:...,load <file>" options the way suricata-update
	// does; see DatasetFiles.
	DepFiles map[string][]byte
	// IgnoreInvalid makes Process skip, with a warning through Logf, the
	// conf lines that suricata-update ignores (unparsable matcher specs,
	// including "re:" patterns Python cannot compile), and defer modify.conf
	// replacement errors until a rule matches, which reproduces
	// suricata-update exactly. By default Process validates the conf up
	// front like ValidateConfig and fails on any bad line. Unsupported
	// constructs and malformed modify lines are always errors.
	IgnoreInvalid bool
	// Logf, if non-nil, receives the warnings suricata-update would log
	// (ignored conf lines, duplicate SIDs, invalid modifications...).
	Logf func(format string, args ...any)
}

// Stats summarises a Process run.
type Stats struct {
	Total           int // rules in the output (after duplicate removal)
	Enabled         int // enabled rules in the output
	Disabled        int // disabled (commented out) rules in the output
	Dropped         int // rules converted by drop.conf ("Dropped N rules")
	Modified        int // rules matched by modify.conf ("Modified N rules")
	FlowbitsEnabled int // rules enabled for flowbit dependencies

	Loaded         int // rules passed to Process ("Loaded N rules")
	Duplicates     int // rules discarded as duplicate gid:sid
	DisabledByConf int // rules disabled by disable.conf ("Disabled N rules")
	EnabledByConf  int // rules enabled by enable.conf ("Enabled N rules")
	// DatasetDisabled counts enabled rules disabled because the file of
	// their dataset "load" is missing. suricata-update does this while
	// writing, so its logged enabled count still includes them.
	DatasetDisabled int
}

// Process applies cfg to rules exactly like suricata-update does and
// returns the resulting rules in suricata-update's output order.
//
// rules must be in suricata-update's load order (files sorted by name,
// rules in file order), as returned by ParseFiles. Duplicate gid:sid pairs
// keep the rule with the highest rev (the first one on ties) at the
// position of the first occurrence. Each rule then goes through the
// disable matchers, enable matchers, drop filters and modify filters, and
// finally flowbits are resolved and dataset files referenced by enabled
// rules are located.
//
// The input rules are not modified. The conf lines are validated first (see
// ValidateConfig and Config.IgnoreInvalid); constructs this package cannot
// reproduce are reported with errors wrapping ErrUnsupported, and conditions
// that make suricata-update crash while processing are returned as errors.
func Process(rules []*Rule, cfg Config) ([]*Rule, Stats, error) {
	logf := cfg.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	var st Stats

	cc, err := compileConfig(cfg, !cfg.IgnoreInvalid, logf)
	if err != nil {
		return nil, st, err
	}

	out := buildRuleMap(rules, logf)
	for _, r := range rules {
		if r != nil {
			st.Loaded++
		}
	}

	results := make([]ruleResult, len(out))
	runParallel(len(out), func(i int) {
		results[i] = processRule(out[i], cc.disable, cc.enable, cc.drop, cc.modify)
	})
	for i, res := range results {
		for _, l := range res.logs {
			logf(l.format, l.args...)
		}
		if res.err != nil {
			return nil, st, res.err
		}
		out[i] = res.rule
		st.DisabledByConf += b2i(res.disabled)
		st.EnabledByConf += b2i(res.enabled)
		st.Modified += b2i(res.modified)
		st.Dropped += b2i(res.dropped)
	}

	if cfg.ResolveFlowbits {
		n, err := resolveFlowbits(out)
		if err != nil {
			return nil, st, err
		}
		st.FlowbitsEnabled = n
	}

	if st.DatasetDisabled, err = handleDatasets(out, cfg.DepFiles, logf); err != nil {
		return nil, st, err
	}

	st.Total = len(out)
	for _, r := range out {
		if r.Enabled {
			st.Enabled++
		}
	}
	st.Disabled = st.Total - st.Enabled
	st.Duplicates = st.Loaded - st.Total
	return out, st, nil
}

type logEntry struct {
	format string
	args   []any
}

// ruleResult is the outcome of the per-rule conf pass.
type ruleResult struct {
	rule                                 *Rule
	disabled, enabled, modified, dropped bool
	logs                                 []logEntry
	err                                  error
}

// processRule runs the disable matchers, enable matchers, drop filters and
// modify filters on one rule, like the main loop of suricata-update. It
// only touches r, so rules can be processed concurrently.
func processRule(r *Rule, disable, enable []ruleMatcher, drop, modify []ruleFilter) (res ruleResult) {
	logf := func(format string, args ...any) {
		res.logs = append(res.logs, logEntry{format, args})
	}
	for _, m := range disable {
		if !r.Enabled {
			break
		}
		ok, err := m.matchErr(r)
		if err != nil {
			res.err = err
			return res
		}
		if ok {
			r.Enabled = false
			res.disabled = true
		}
	}
	for _, m := range enable {
		if r.Enabled {
			break
		}
		ok, err := m.matchErr(r)
		if err != nil {
			res.err = err
			return res
		}
		if ok {
			r.Enabled = true
			res.enabled = true
		}
	}
	var err error
	if r, err = applyFilters(r, drop, &res.dropped, logf); err != nil {
		res.err = err
		return res
	}
	if r, err = applyFilters(r, modify, &res.modified, logf); err != nil {
		res.err = err
		return res
	}
	res.rule = r
	return res
}

// runParallel calls fn(i) for every i in [0, n) using all CPUs.
func runParallel(n int, fn func(i int)) {
	const chunk = 256
	workers := min(runtime.GOMAXPROCS(0), (n+chunk-1)/chunk)
	if workers <= 1 {
		for i := range n {
			fn(i)
		}
		return
	}
	var next atomic.Int64
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for {
				start := int(next.Add(chunk)) - chunk
				if start >= n {
					return
				}
				for i := start; i < min(start+chunk, n); i++ {
					fn(i)
				}
			}
		})
	}
	wg.Wait()
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func applyFilters(r *Rule, filters []ruleFilter, applied *bool, logf func(string, ...any)) (*Rule, error) {
	for _, f := range filters {
		ok, err := f.match(r)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		if r, err = f.run(r, logf); err != nil {
			return nil, err
		}
		*applied = true
	}
	return r, nil
}

// buildRuleMap ports build_rule_map: it de-duplicates rules by gid:sid,
// keeping the greatest rev (first seen on ties) in the slot of the first
// occurrence. The returned rules are copies.
func buildRuleMap(rules []*Rule, logf func(string, ...any)) []*Rule {
	type key struct{ gid, sid uint32 }
	index := make(map[key]int, len(rules))
	out := make([]*Rule, 0, len(rules))
	for _, r := range rules {
		if r == nil {
			continue
		}
		k := key{r.GID, r.SID}
		i, dup := index[k]
		if !dup {
			index[k] = len(out)
			out = append(out, r)
			continue
		}
		switch {
		case r.Rev == out[i].Rev:
			logf("Found duplicate rule SID %d with same revision, keeping the first rule seen.", r.SID)
		case r.Rev > out[i].Rev:
			logf("Found duplicate rule SID %d, keeping the rule with greater revision.", r.SID)
			out[i] = r
		}
	}
	for i, r := range out {
		out[i] = r.clone()
	}
	return out
}

type flowbitKey struct {
	name  string
	valid bool // false for a flowbit without a name (Python None)
}

func parseFlowbit(fb string) (op string, k flowbitKey) {
	op, name, ok := strings.Cut(fb, ",")
	return op, flowbitKey{name, ok}
}

func isFlowbitSetter(op string) bool {
	return op == "set" || op == "setx" || op == "unset" || op == "toggle"
}

// resolveFlowbits ports resolve_flowbits: until a fixpoint is reached,
// disabled rules that set a flowbit checked (isset/isnotset) by an enabled
// rule are enabled and flagged noalert. It returns the number of rules
// enabled.
func resolveFlowbits(rules []*Rule) (int, error) {
	for _, r := range rules {
		if r.nilFlowbit {
			return 0, fmt.Errorf("ruleset: rule %s: flowbits option without value (suricata-update crashes on it)", r.ID())
		}
	}
	enabled := map[*Rule]bool{}
	for {
		required := map[flowbitKey]bool{}
		for _, r := range rules {
			if !r.Enabled {
				continue
			}
			for _, fb := range r.Flowbits {
				if op, k := parseFlowbit(fb); op == "isset" || op == "isnotset" {
					required[k] = true
				}
			}
		}
		var toEnable []*Rule
		for _, r := range rules {
			if r.Enabled {
				continue
			}
			for _, fb := range r.Flowbits {
				if op, k := parseFlowbit(fb); isFlowbitSetter(op) && required[k] {
					toEnable = append(toEnable, r)
				}
			}
		}
		if len(toEnable) == 0 {
			return len(enabled), nil
		}
		for _, r := range toEnable {
			r.Enabled = true
			r.Noalert = true
			enabled[r] = true
		}
	}
}

// handleDatasets ports handle_dataset_files, which suricata-update runs
// while writing the merged rule file: enabled rules whose last dataset
// option has a "load <file>" argument get the file name replaced by
// "datasets/<md5 of content>", or are disabled when the file is missing.
func handleDatasets(rules []*Rule, dep map[string][]byte, logf func(string, ...any)) (disabled int, err error) {
	for _, r := range rules {
		if !r.hasDataset || !r.Enabled {
			continue
		}
		if r.datasetNil {
			return 0, fmt.Errorf("ruleset: rule %s: dataset option without value (suricata-update crashes on it)", r.ID())
		}
		var load string
		found := false
		for _, el := range strings.Split(r.dataset, ",") {
			if strings.HasPrefix(el, "load") {
				load, found = pyStrip(el), true
				break
			}
		}
		if !found {
			continue
		}
		_, name, ok := pySplitMax1(load)
		if !ok {
			return 0, fmt.Errorf("ruleset: rule %s: dataset load without file name (suricata-update crashes on it)", r.ID())
		}
		name = pyStrip(name)
		g, ok := r.group()
		if !ok {
			return 0, fmt.Errorf("ruleset: rule %s: dataset rule without group (suricata-update crashes on it)", r.ID())
		}
		source := pyDirname(g) + "/" + name
		content, ok := dep[source]
		if !ok {
			if strings.HasPrefix(source, "/") {
				logf("Local dataset file '%s' was not found for rule [%s], rule will be disabled", source, r.ID())
			} else {
				logf("Dataset file '%s' was not found for rule [%s], rule will be disabled", name, r.ID())
			}
			r.Enabled = false
			disabled++
			continue
		}
		sum := md5.Sum(content)
		hash := hex.EncodeToString(sum[:])
		rx, err := compilePyRegex(`(dataset.*?load\s+)`+name, 0)
		if err != nil {
			return 0, fmt.Errorf("ruleset: rule %s: dataset file name %q: %w", r.ID(), name, err)
		}
		tmpl, err := parsePyTemplate(`\g<1>datasets/`+hash, rx)
		if err != nil {
			return 0, err
		}
		text, err := rx.sub(tmpl, r.format())
		if err != nil {
			return 0, err
		}
		r.raw = text
		r.datasetPath = "datasets/" + hash
		r.datasetData = content
	}
	return disabled, nil
}

// DatasetFiles returns the dataset files that must be installed next to
// the output rule file for rules processed by Process, keyed by the path
// the rewritten rules reference ("datasets/<md5>").
func DatasetFiles(rules []*Rule) map[string][]byte {
	files := map[string][]byte{}
	for _, r := range rules {
		if r != nil && r.datasetPath != "" && r.Enabled {
			files[r.datasetPath] = r.datasetData
		}
	}
	return files
}
