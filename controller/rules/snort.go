package rules

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/jc-lab/suricontroller/controller/store"
	"github.com/jc-lab/suricontroller/pkg/snortconv"
)

// TypeSnort downloads a Talos Snort ruleset and converts it to Suricata.
const TypeSnort = "snort"

// DefaultSnortVersion selects the snortrules-snapshot build. Talos ships
// the same text rules in every Snort 3 snapshot; the version only selects
// shared object builds, which are not used.
const DefaultSnortVersion = "3.9.0.0"

// Snort rulesets (option "ruleset").
const (
	// SnortAuto uses the subscription the oinkcode gives access to
	// (snortrules-snapshot) and the community ruleset without oinkcode.
	SnortAuto = "auto"
	// SnortCommunity is the free community ruleset (no oinkcode).
	SnortCommunity = "community"
	// SnortSnapshot is snortrules-snapshot-<version>. snort.org serves it
	// according to the oinkcode's account: current rules to Snort
	// Subscriber Rule Set subscribers, rules 30 days old to registered
	// users.
	SnortSnapshot = "registered"
	// SnortLightSPD is the Talos LightSPD package (Snort 3).
	SnortLightSPD = "lightspd"
)

// Snort rule policies (option "policy"): Talos marks rules with the IPS
// policies they belong to; rules outside the selected policy are written
// commented out, so enable.conf can still turn them on.
var snortPolicies = map[string]bool{"connectivity": true, "balanced": true, "security": true, "max-detect": true, "all": true}

// SecretOptions lists provider options that are never returned by the API.
var SecretOptions = map[string]bool{"oinkcode": true}

// MaskedSecret replaces secret option values in API responses. An update
// that sends it back leaves the stored value unchanged.
const MaskedSecret = "********"

// RedactOptions returns options with secret values masked.
func RedactOptions(opts map[string]string) map[string]string {
	out := make(map[string]string, len(opts))
	for k, v := range opts {
		if SecretOptions[k] && v != "" {
			v = MaskedSecret
		}
		out[k] = v
	}
	return out
}

// snortReportFile lists the rules left out of the converted ruleset.
const snortReportFile = "snort2suricata-report.txt"

// convVersion is part of the stored checksum so a converter change
// converts the ruleset again even when upstream did not change.
const convVersion = "1"

var (
	oinkcodeRe     = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)
	snortVersionRe = regexp.MustCompile(`^[23](\.\d+){1,3}(-\d+)?$`)
	nonAlnumRe     = regexp.MustCompile(`[^0-9A-Za-z]`)
)

// ValidateSnortOptions checks the options of a snort provider.
func ValidateSnortOptions(o map[string]string) error {
	rs := o["ruleset"]
	switch rs {
	case "", SnortAuto, SnortCommunity, SnortSnapshot, SnortLightSPD:
	default:
		return fmt.Errorf("ruleset must be auto, community, registered or lightspd")
	}
	if oc := o["oinkcode"]; oc != "" && !oinkcodeRe.MatchString(oc) {
		return errors.New("oinkcode must be 40 hexadecimal characters")
	}
	if (rs == SnortSnapshot || rs == SnortLightSPD) && o["oinkcode"] == "" {
		return fmt.Errorf("ruleset %s needs an oinkcode", rs)
	}
	if p := o["policy"]; p != "" && !snortPolicies[p] {
		return errors.New("policy must be connectivity, balanced, security, max-detect or all")
	}
	if a := o["approx"]; a != "" && a != "include" && a != "exclude" {
		return errors.New("approx must be include or exclude")
	}
	if v := o["snort_version"]; v != "" && !snortVersionRe.MatchString(v) {
		return fmt.Errorf("invalid snort_version %q", v)
	}
	return nil
}

// Snort fetches a Talos ruleset from snort.org and converts it to Suricata
// rules with snortconv.
type Snort struct {
	Client *http.Client
	// BaseURL overrides https://www.snort.org (tests).
	BaseURL string
}

type snortSource struct {
	name    string // for messages and commits
	url     string // without oinkcode
	oinked  bool   // needs the oinkcode
	keep    func(member string) bool
	policy  bool // apply the policy option
	dialect snortconv.Dialect
}

func (f *Snort) source(o map[string]string) (*snortSource, error) {
	base := f.BaseURL
	if base == "" {
		base = "https://www.snort.org"
	}
	version := o["snort_version"]
	if version == "" {
		version = DefaultSnortVersion
	}
	rs := o["ruleset"]
	if rs == "" || rs == SnortAuto {
		rs = SnortCommunity
		if o["oinkcode"] != "" {
			rs = SnortSnapshot
		}
	}
	snort2 := strings.HasPrefix(version, "2.")
	dialect := snortconv.Snort3
	if snort2 {
		dialect = snortconv.Snort2
	}
	switch rs {
	case SnortCommunity:
		file := "snort3-community-rules.tar.gz"
		if snort2 {
			file = "community-rules.tar.gz"
		}
		return &snortSource{name: "community", url: base + "/downloads/community/" + file, dialect: dialect,
			keep: func(m string) bool { return strings.HasSuffix(m, ".rules") }}, nil
	case SnortSnapshot:
		v := nonAlnumRe.ReplaceAllString(version, "")
		return &snortSource{name: "snortrules-snapshot-" + v, url: base + "/rules/snortrules-snapshot-" + v + ".tar.gz",
			oinked: true, policy: true, dialect: dialect,
			// Text rules only: so_rules are shared object stubs and
			// builtins are Snort decoder events.
			keep: func(m string) bool {
				return path.Dir(m) == "rules" && strings.HasSuffix(m, ".rules") || path.Dir(m) == "etc" && strings.HasSuffix(m, ".config")
			}}, nil
	case SnortLightSPD:
		return &snortSource{name: "Talos_LightSPD", url: base + "/rules/Talos_LightSPD.tar.gz", oinked: true, policy: true, dialect: snortconv.Snort3,
			keep: func(m string) bool {
				return path.Dir(m) == "lightspd/rules/3.0.0.0" && strings.HasSuffix(m, ".rules")
			}}, nil
	}
	return nil, fmt.Errorf("unknown ruleset %q", rs)
}

// Fetch implements Fetcher.
func (f *Snort) Fetch(ctx context.Context, p *store.Provider) (*FetchResult, error) {
	if err := ValidateSnortOptions(p.Options); err != nil {
		return nil, err
	}
	src, err := f.source(p.Options)
	if err != nil {
		return nil, err
	}
	oinkcode := ""
	if src.oinked {
		oinkcode = p.Options["oinkcode"]
	}
	conv := snortConvOptions(p.Options, src.policy)

	md5sum, err := f.get(ctx, src.url+".md5", oinkcode, 1024)
	if err != nil {
		return nil, fmt.Errorf("%s md5: %w", src.name, err)
	}
	fields := strings.Fields(string(md5sum))
	if len(fields) == 0 || !md5Re.MatchString(strings.ToLower(fields[0])) {
		return nil, fmt.Errorf("invalid md5 for %s", src.name)
	}
	sumHex := strings.ToLower(fields[0])
	checksum := sumHex + "/" + convVersion
	if checksum == p.Checksum {
		return nil, ErrNotModified
	}
	data, err := f.get(ctx, src.url, oinkcode, maxArchiveSize)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", src.name, err)
	}
	sum := md5.Sum(data)
	if got := hex.EncodeToString(sum[:]); got != sumHex {
		return nil, fmt.Errorf("%s: md5 mismatch: got %s, published %s", src.name, got, sumHex)
	}
	members, err := extractMembers(data, src.keep)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", src.name, err)
	}
	files, err := convertSnort(members, src.name, src.dialect, conv)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", src.name, err)
	}
	return &FetchResult{Files: files, Checksum: checksum}, nil
}

// get downloads url (adding the oinkcode, if any) and turns snort.org's
// error replies (`["Invalid oinkcode"]`) into errors. The oinkcode never
// appears in returned errors.
func (f *Snort) get(ctx context.Context, rawURL, oinkcode string, limit int64) ([]byte, error) {
	u := rawURL
	if oinkcode != "" {
		u += "?oinkcode=" + url.QueryEscape(oinkcode)
	}
	redact := func(err error) error {
		if err == nil || oinkcode == "" {
			return err
		}
		return errors.New(strings.ReplaceAll(err.Error(), oinkcode, "<oinkcode>"))
	}
	c := f.Client
	if c == nil {
		c = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, redact(err)
	}
	req.Header.Set("User-Agent", "suricontroller")
	resp, err := c.Do(req)
	if err != nil {
		return nil, redact(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		var msgs []string
		msg := ""
		if json.Unmarshal(body, &msgs) == nil && len(msgs) > 0 {
			msg = ": " + strings.Join(msgs, "; ")
		}
		return nil, redact(fmt.Errorf("GET %s: %s%s", rawURL, resp.Status, msg))
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, redact(err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("GET %s: response larger than %d bytes", rawURL, limit)
	}
	return data, nil
}

// extractMembers returns the archive members keep accepts, keyed by their
// path in the archive (without a leading "./").
func extractMembers(data []byte, keep func(string) bool) (map[string][]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("gunzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	out := map[string][]byte{}
	var total int64
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("untar: %w", err)
		}
		name := strings.TrimPrefix(path.Clean(hdr.Name), "./")
		if hdr.Typeflag != tar.TypeReg || !keep(name) || strings.HasPrefix(path.Base(name), ".") {
			continue
		}
		total += hdr.Size
		if total > 4*maxArchiveSize {
			return nil, errors.New("archive expands too much")
		}
		b, err := io.ReadAll(io.LimitReader(tr, hdr.Size))
		if err != nil {
			return nil, err
		}
		out[name] = b
	}
	if len(out) == 0 {
		return nil, errors.New("archive contains no rule files")
	}
	return out, nil
}

type snortConv struct {
	policy        string // "" keeps the file's enabled state
	excludeApprox bool
}

func snortConvOptions(o map[string]string, usePolicy bool) snortConv {
	c := snortConv{excludeApprox: o["approx"] == "exclude"}
	if usePolicy {
		c.policy = o["policy"]
		if c.policy == "" {
			c.policy = "balanced"
		}
	}
	return c
}

var rePolicy = regexp.MustCompile(`policy\s+(connectivity|balanced|security|max-detect)-ips\b`)

// inPolicy reports whether a Snort rule belongs to an IPS policy. Talos
// rules list their policies in metadata ("policy balanced-ips drop").
func inPolicy(rule, policy string) bool {
	if policy == "all" {
		return true
	}
	for _, m := range rePolicy.FindAllStringSubmatch(rule, -1) {
		if m[1] == policy {
			return true
		}
	}
	return false
}

// snortVars maps Snort variables that Suricata's default configuration
// does not define to their Snort default (snort_defaults.lua).
var snortVars = strings.NewReplacer("$SIP_SERVERS", "$HOME_NET")

type snortStats struct {
	total, enabled, disabled, approx, failed, config, excluded, flowbits int
}

// snortEntry is one converted rule of an output file.
type snortEntry struct {
	comment string // "# snort2suricata: approx: ..." line, if any
	rule    string // Suricata rule, not commented out
	enabled bool
}

var reFlowbits = regexp.MustCompile(`flowbits:\s*(\w+)\s*,\s*([^;]+)`)

// enableFlowbitSetters enables, with noalert, disabled rules that set a
// flowbit an enabled rule checks, until nothing changes. The rule
// processing of the controller (a port of suricata-update) does the same
// but treats "isset,a|b" as one bit name; Talos policies rely on such OR
// lists, so they are resolved here.
func enableFlowbitSetters(entries []*snortEntry) int {
	n := 0
	for {
		required := map[string]bool{}
		for _, e := range entries {
			if !e.enabled {
				continue
			}
			for _, m := range reFlowbits.FindAllStringSubmatch(e.rule, -1) {
				if m[1] == "isset" || m[1] == "isnotset" {
					for _, b := range strings.FieldsFunc(m[2], func(r rune) bool { return r == '|' || r == '&' }) {
						required[strings.TrimSpace(b)] = true
					}
				}
			}
		}
		changed := false
		for _, e := range entries {
			if e.enabled {
				continue
			}
			for _, m := range reFlowbits.FindAllStringSubmatch(e.rule, -1) {
				if (m[1] == "set" || m[1] == "setx" || m[1] == "unset" || m[1] == "toggle") && required[strings.TrimSpace(m[2])] {
					e.enabled, changed = true, true
					if !strings.Contains(e.rule, "noalert") {
						e.rule = strings.TrimSuffix(e.rule, ")") + " noalert;)"
					}
					n++
					break
				}
			}
		}
		if !changed {
			return n
		}
	}
}

// convertSnort converts the rule files of a Snort ruleset. Each source
// file becomes a Suricata rule file of the same base name; rules that are
// not converted are listed in snort2suricata-report.txt with the reason.
func convertSnort(members map[string][]byte, source string, dialect snortconv.Dialect, cfg snortConv) (map[string][]byte, error) {
	names := make([]string, 0, len(members))
	for n := range members {
		names = append(names, n)
	}
	sort.Strings(names)
	files := map[string][]byte{}
	var st snortStats
	var report bytes.Buffer
	var failed, needConfig, excluded bytes.Buffer
	type outFile struct {
		name    string
		entries []*snortEntry
	}
	var outs []*outFile
	var all []*snortEntry
	for _, name := range names {
		base := path.Base(name)
		if strings.HasSuffix(base, ".config") {
			files[base] = members[name]
			continue
		}
		if base == "includes.rules" {
			continue
		}
		lines := splitLines(members[name])
		of := &outFile{name: base}
		outs = append(outs, of)
		for i, line := range lines {
			t := strings.TrimSpace(line)
			fileEnabled := !strings.HasPrefix(t, "#")
			rule := strings.TrimSpace(strings.TrimLeft(t, "#"))
			res, err := snortconv.Convert(rule, dialect)
			if errors.Is(err, snortconv.ErrNotRule) || !strings.Contains(rule, "sid:") {
				continue
			}
			if err != nil {
				return nil, err
			}
			st.total++
			enabled := fileEnabled
			if cfg.policy != "" {
				enabled = inPolicy(rule, cfg.policy)
			}
			where := fmt.Sprintf("%s:%d %s:%s", base, i+1, res.GID, res.SID)
			switch {
			case res.Status == snortconv.Failed:
				st.failed++
				fmt.Fprintf(&failed, "# %s: %s\n%s\n", where, reasons(res, snortconv.Approx), rule)
				continue
			case hasIssue(res, snortconv.CodeConfig):
				// Suricata refuses the whole ruleset when a rule needs an
				// app-layer parser that is disabled, which modbus and dnp3
				// are by default; such rules are listed instead.
				st.config++
				fmt.Fprintf(&needConfig, "# %s: %s\n%s\n", where, reasons(res, snortconv.Exact), strings.TrimPrefix(res.Output, "# "))
				continue
			case res.Status == snortconv.Approx && cfg.excludeApprox:
				st.excluded++
				fmt.Fprintf(&excluded, "# %s: %s\n%s\n", where, reasons(res, snortconv.Approx), strings.TrimPrefix(res.Output, "# "))
				continue
			}
			e := &snortEntry{enabled: enabled, rule: strings.TrimPrefix(res.Output, "# ")}
			if res.Status == snortconv.Approx {
				st.approx++
				e.comment = "# snort2suricata: approx: " + reasons(res, snortconv.Approx) + "\n"
			}
			if hdr, rest, ok := strings.Cut(e.rule, "("); ok {
				e.rule = snortVars.Replace(hdr) + "(" + rest
			}
			of.entries = append(of.entries, e)
			all = append(all, e)
		}
	}
	if st.total == 0 {
		return nil, errors.New("no rules found")
	}
	st.flowbits = enableFlowbitSetters(all)
	for _, of := range outs {
		var out bytes.Buffer
		fmt.Fprintf(&out, "# Converted from the Snort %s ruleset (%s) by suricontroller. Do not edit.\n", source, of.name)
		for _, e := range of.entries {
			out.WriteString(e.comment)
			if e.enabled {
				st.enabled++
			} else {
				st.disabled++
				out.WriteString("# ")
			}
			out.WriteString(e.rule)
			out.WriteByte('\n')
		}
		files[of.name] = out.Bytes()
	}
	fmt.Fprintf(&report, "# snort2suricata conversion of the Snort %s ruleset\n", source)
	if cfg.policy != "" {
		fmt.Fprintf(&report, "# policy: %s\n", cfg.policy)
	}
	fmt.Fprintf(&report, "# rules: %d, written enabled: %d, written disabled: %d (approx: %d, enabled with noalert for flowbits: %d)\n", st.total, st.enabled, st.disabled, st.approx, st.flowbits)
	fmt.Fprintf(&report, "# not written: %d failed, %d need suricata.yaml changes, %d approx excluded\n", st.failed, st.config, st.excluded)
	for _, sec := range []struct {
		title string
		b     *bytes.Buffer
	}{
		{"Rules that need app-layer protocols disabled in the default suricata.yaml (add them as local rules after enabling the protocol)", &needConfig},
		{"Approximate conversions excluded by approx=exclude", &excluded},
		{"Rules without a Suricata equivalent", &failed},
	} {
		if sec.b.Len() == 0 {
			continue
		}
		fmt.Fprintf(&report, "\n# ==== %s\n", sec.title)
		report.Write(sec.b.Bytes())
	}
	files[snortReportFile] = report.Bytes()
	return files, nil
}

func splitLines(b []byte) []string {
	var lines []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines
}

func hasIssue(res *snortconv.Result, code string) bool {
	for _, is := range res.Issues {
		if is.Code == code {
			return true
		}
	}
	return false
}

func reasons(res *snortconv.Result, min snortconv.Status) string {
	var r []string
	for _, is := range res.Issues {
		if is.Severity >= min {
			r = append(r, is.Message)
		}
	}
	return strings.Join(r, "; ")
}
