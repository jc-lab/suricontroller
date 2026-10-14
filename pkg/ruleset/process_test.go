package ruleset

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func parseWithGroup(t *testing.T, group, line string) *Rule {
	t.Helper()
	rules, err := ParseFile(group, strings.NewReader(line))
	if err != nil || len(rules) != 1 {
		t.Fatalf("ParseFile(%q) = %v, %v", line, rules, err)
	}
	return rules[0]
}

func TestMatchers(t *testing.T) {
	r := parseWithGroup(t, "et-open/emerging-dns.rules",
		`alert dns any any -> any any (msg:"ET DNS Query .su"; content:".su"; sid:2014169; rev:3; metadata:created_at 2012_01_31, Signature_Severity  Major, keyonly;)`)
	g3 := parseWithGroup(t, "et-open/emerging-dns.rules", `alert dns any any -> any any (msg:"x"; gid:3; sid:2014169;)`)
	noGroup := mustParse(t, `alert dns any any -> any any (msg:"ET DNS"; sid:2014169;)`)

	tests := []struct {
		spec          string
		r             *Rule
		want          bool
		wantNoGroupOK bool // result for the rule without group
	}{
		{"*", r, true, true},
		{"2014169", r, true, true},
		{"1:2014169", r, true, true},
		{" 1 : 2014169 ", r, true, true},
		{"2014170, 1:2014169", r, true, true},
		{"3:2014169", r, false, false},
		{"3:2014169", g3, true, false},
		{"2014169", g3, false, true},
		{"2_014_169", r, true, true},
		{"99999999999999999999", r, false, false},
		{"re:et dns query", r, true, false},
		{"re:^alert", r, true, true},
		{"re:\\.su\"", r, true, false},
		{"re:nomatch", r, false, false},
		{"group:emerging-dns.rules", r, true, false},
		{"group:emerging-dns", r, true, false},
		{"group:emerging-d?s", r, true, false},
		{"group:emerging-*", r, true, false},
		{"group:et-open/emerging-dns.rules", r, false, false},
		{"emerging-dns.rules", r, true, false},
		{"filename:et-open/emerging-dns.rules", r, true, false},
		{"filename:*/emerging-dns.rules", r, true, false},
		{"filename:emerging-dns.rules", r, false, false},
		{"metadata: signature_severity major", r, true, false},
		{"metadata:SIGNATURE_SEVERITY MAJOR", r, true, false},
		{"metadata:signature_severity minor", r, false, false},
		{"metadata:created_at 2012_01_31", r, true, false},
	}
	for _, tt := range tests {
		m, err := ParseMatcher(tt.spec)
		if err != nil {
			t.Errorf("ParseMatcher(%q): %v", tt.spec, err)
			continue
		}
		if got := m.Match(tt.r); got != tt.want {
			t.Errorf("%q.Match = %v, want %v", tt.spec, got, tt.want)
		}
		if got := m.Match(noGroup); got != tt.wantNoGroupOK {
			t.Errorf("%q.Match(no group) = %v, want %v", tt.spec, got, tt.wantNoGroupOK)
		}
	}

	for _, spec := range []string{"foo", "2001,", "1:", "1:2:3", "metadata:onlykey", "re:(unclosed", "emerging-dns.rules ", "group"} {
		if _, err := ParseMatcher(spec); !errors.Is(err, ErrNoMatcher) {
			t.Errorf("ParseMatcher(%q) = %v, want ErrNoMatcher", spec, err)
		}
	}
	// A bad regex ending in ".rules" is a group matcher, like in
	// suricata-update.
	if m, err := ParseMatcher("re:(x.rules"); err != nil {
		t.Errorf("ParseMatcher(re:(x.rules): %v", err)
	} else if _, ok := m.(*globMatcher); !ok {
		t.Errorf("ParseMatcher(re:(x.rules) = %T", m)
	}
	if _, err := ParseMatcher("re:a(?!b)"); !errors.Is(err, ErrUnsupported) {
		t.Errorf("ParseMatcher(lookahead) = %v, want ErrUnsupported", err)
	}

	// suricata-update crashes on a key-only metadata entry with a
	// matching key.
	m, _ := parseRuleMatch("metadata:keyonly x")
	if _, err := m.matchErr(r); err == nil {
		t.Error("metadata key without value: want error")
	}
	if _, _, err := Process([]*Rule{r}, Config{Disable: []string{"metadata:keyonly x"}}); err == nil {
		t.Error("Process with crashing metadata matcher: want error")
	}
}

func process(t *testing.T, rules []*Rule, cfg Config) ([]string, Stats) {
	t.Helper()
	out, st, err := Process(rules, cfg)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, r := range out {
		lines = append(lines, r.String())
	}
	return lines, st
}

func TestProcessOrderAndFilters(t *testing.T) {
	g := "rules/emerging-test.rules"
	rules := []*Rule{
		parseWithGroup(t, g, `alert tcp $HOME_NET any -> any any (msg:"one"; content:"seconds 60"; sid:1; rev:1;)`),
		parseWithGroup(t, g, `#alert tcp $HOME_NET any -> any any (msg:"two"; sid:2; rev:1;)`),
		parseWithGroup(t, g, `alert tcp $HOME_NET any -> any any (msg:"three noalert"; flowbits:set,x; flowbits:noalert; sid:3; rev:1;)`),
		parseWithGroup(t, g, `alert tcp $HOME_NET any -> any any (msg:"four"; sid:4; rev:1;)`),
		parseWithGroup(t, g, `alert tcp $HOME_NET any -> any any (msg:"five"; sid:5; rev:1;)`),
	}
	orig := rules[0].String()
	cfg := Config{
		Disable: []string{"1", "2", "4"}, // 2 is already disabled: not counted
		Enable:  []string{"2", "4"},      // enable runs after disable
		Drop:    []string{"re:.", "group:emerging-test.rules"},
		Modify: []string{
			`1 "(seconds) (\d+)" "${1} 3600"`,
			`group:emerging-test.rules "\\$HOME_NET" "any"`, // dropped rules lost their group
			`metadata-add 3 "k" "v"`,
			`4 "\)$" ""`, // result is not a rule: original kept
			`5 "^drop" "# drop"`,
		},
	}
	var logs []string
	cfg.Logf = func(f string, a ...any) { logs = append(logs, f) }
	got, st := process(t, rules, cfg)
	want := []string{
		`# drop tcp $HOME_NET any -> any any (msg:"one"; content:"seconds 3600"; sid:1; rev:1;)`,
		`drop tcp $HOME_NET any -> any any (msg:"two"; sid:2; rev:1;)`,
		`alert tcp any any -> any any (msg:"three noalert"; flowbits:set,x; flowbits:noalert; sid:3; rev:1; metadata: k v;)`,
		`drop tcp $HOME_NET any -> any any (msg:"four"; sid:4; rev:1;)`,
		`# drop tcp $HOME_NET any -> any any (msg:"five"; sid:5; rev:1;)`,
	}
	if !slices.Equal(got, want) {
		t.Errorf("output:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	wantStats := Stats{Total: 5, Enabled: 3, Disabled: 2, Dropped: 4, Modified: 4, Loaded: 5, DisabledByConf: 2, EnabledByConf: 2}
	if st != wantStats {
		t.Errorf("stats = %+v, want %+v", st, wantStats)
	}
	if len(logs) != 1 || !strings.Contains(logs[0], "invalid rule") {
		t.Errorf("logs = %q", logs)
	}
	if rules[0].String() != orig || !rules[0].Enabled {
		t.Error("Process modified its input")
	}

	// A modification removing the sid makes suricata-update crash.
	cfg = Config{Modify: []string{`1 "sid:1;" ""`}}
	if _, _, err := Process(rules, cfg); err == nil {
		t.Error("modification removing sid: want error")
	}
}

func TestDuplicates(t *testing.T) {
	rules := []*Rule{
		parseWithGroup(t, "a.rules", `alert tcp any any -> any any (msg:"a rev2"; sid:1; rev:2;)`),
		parseWithGroup(t, "a.rules", `alert tcp any any -> any any (msg:"b"; sid:2; rev:1;)`),
		parseWithGroup(t, "a.rules", `alert tcp any any -> any any (msg:"c rev1"; sid:3; rev:1;)`),
		parseWithGroup(t, "b.rules", `alert tcp any any -> any any (msg:"a rev1"; sid:1; rev:1;)`),
		parseWithGroup(t, "b.rules", `#alert tcp any any -> any any (msg:"c rev5"; sid:3; rev:5;)`),
		parseWithGroup(t, "b.rules", `alert tcp any any -> any any (msg:"b same rev"; sid:2; rev:1;)`),
		parseWithGroup(t, "b.rules", `alert tcp any any -> any any (msg:"gid 2"; gid:2; sid:1; rev:0;)`),
	}
	var logs []string
	got, st := process(t, rules, Config{Logf: func(f string, a ...any) { logs = append(logs, f) }})
	want := []string{
		`alert tcp any any -> any any (msg:"a rev2"; sid:1; rev:2;)`,
		`alert tcp any any -> any any (msg:"b"; sid:2; rev:1;)`,
		`# alert tcp any any -> any any (msg:"c rev5"; sid:3; rev:5;)`,
		`alert tcp any any -> any any (msg:"gid 2"; gid:2; sid:1; rev:0;)`,
	}
	if !slices.Equal(got, want) {
		t.Errorf("output:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if st.Loaded != 7 || st.Total != 4 || st.Duplicates != 3 || len(logs) != 2 {
		t.Errorf("stats = %+v, logs = %q", st, logs)
	}
}

func TestFlowbits(t *testing.T) {
	rules := []*Rule{
		mustParse(t, `alert tcp any any -> any any (msg:"A"; flowbits:isset,b; sid:1;)`),
		mustParse(t, `#alert tcp any any -> any any (msg:"B"; flowbits:isset,c; flowbits:set,b; sid:2;)`),
		mustParse(t, `#alert tcp any any -> any any (msg:"C"; flowbits:toggle,c; sid:3;)`),
		mustParse(t, `#alert tcp any any -> any any (msg:"D"; flowbits:set,unrelated; sid:4;)`),
		mustParse(t, `alert tcp any any -> any any (msg:"E"; flowbits:isnotset,e; sid:5;)`),
		mustParse(t, `#alert tcp any any -> any any (msg:"F"; flowbits:unset,e; flowbits:setx,e; sid:6;)`),
		mustParse(t, `alert tcp any any -> any any (msg:"G"; flowbits:isset,g1|g2; sid:7;)`),
		mustParse(t, `#alert tcp any any -> any any (msg:"H"; flowbits:set,g1; sid:8;)`),
		mustParse(t, `#alert tcp any any -> any any (msg:"I"; flowbits:isset,b; sid:9;)`),
	}
	got, st := process(t, rules, Config{ResolveFlowbits: true})
	want := []string{
		`alert tcp any any -> any any (msg:"A"; flowbits:isset,b; sid:1;)`,
		`alert tcp any any -> any any (msg:"B"; flowbits:isset,c; flowbits:set,b; noalert; sid:2;)`,
		`alert tcp any any -> any any (msg:"C"; flowbits:toggle,c; noalert; sid:3;)`,
		`# alert tcp any any -> any any (msg:"D"; flowbits:set,unrelated; sid:4;)`,
		`alert tcp any any -> any any (msg:"E"; flowbits:isnotset,e; sid:5;)`,
		`alert tcp any any -> any any (msg:"F"; flowbits:unset,e; flowbits:setx,e; noalert; sid:6;)`,
		`alert tcp any any -> any any (msg:"G"; flowbits:isset,g1|g2; sid:7;)`,
		`# alert tcp any any -> any any (msg:"H"; flowbits:set,g1; sid:8;)`,
		`# alert tcp any any -> any any (msg:"I"; flowbits:isset,b; sid:9;)`,
	}
	if !slices.Equal(got, want) {
		t.Errorf("output:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if st.FlowbitsEnabled != 3 || st.Enabled != 6 {
		t.Errorf("stats = %+v", st)
	}

	// Without ResolveFlowbits nothing is enabled.
	if _, st := process(t, rules, Config{}); st.FlowbitsEnabled != 0 || st.Enabled != 3 {
		t.Errorf("stats without resolution = %+v", st)
	}

	// A valueless flowbits option crashes suricata-update's resolver.
	bad := mustParse(t, `alert tcp any any -> any any (msg:"x"; flowbits; sid:10;)`)
	if _, _, err := Process([]*Rule{bad}, Config{ResolveFlowbits: true}); err == nil {
		t.Error("valueless flowbits: want error")
	}
}

func TestDatasets(t *testing.T) {
	g := "src/local.rules"
	rules := []*Rule{
		parseWithGroup(t, g, `alert http any any -> any any (msg:"present"; dataset:isset,ua,type string,load ua.lst; sid:1;)`),
		parseWithGroup(t, g, `alert http any any -> any any (msg:"missing"; dataset:isset,ua,type string,load nope.lst; sid:2;)`),
		parseWithGroup(t, g, `#alert http any any -> any any (msg:"disabled"; dataset:isset,ua,type string,load nope.lst; sid:3;)`),
		parseWithGroup(t, g, `alert http any any -> any any (msg:"no load"; dataset:isset,ua,type string; sid:4;)`),
	}
	cfg := Config{DepFiles: map[string][]byte{"src/ua.lst": []byte("curl\n")}}
	out, st, err := Process(rules, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got := out[0].String(); got != `alert http any any -> any any (msg:"present"; dataset:isset,ua,type string,load datasets/37055243218efa7c8adb2346f2386f7a; sid:1;)` {
		t.Errorf("rewritten = %q", got)
	}
	if out[1].Enabled || !strings.HasPrefix(out[2].String(), "# ") || !out[3].Enabled {
		t.Errorf("enabled states: %v %v %v", out[1].Enabled, out[2].Enabled, out[3].Enabled)
	}
	if st.DatasetDisabled != 1 || st.Enabled != 2 {
		t.Errorf("stats = %+v", st)
	}
	files := DatasetFiles(out)
	if len(files) != 1 || string(files["datasets/37055243218efa7c8adb2346f2386f7a"]) != "curl\n" {
		t.Errorf("DatasetFiles = %v", files)
	}

	// A dropped dataset rule has no group, which crashes suricata-update.
	if _, _, err := Process(rules[:1], Config{Drop: []string{"1"}, DepFiles: cfg.DepFiles}); err == nil {
		t.Error("dropped dataset rule: want error")
	}
}
