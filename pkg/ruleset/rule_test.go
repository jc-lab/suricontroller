package ruleset

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	r := mustParse(t, `alert dns $HOME_NET any -> any any (msg:"ET DNS Query"; dns.query; content:".su"; flowbits:set,a; flowbits:isset,b; reference:url,x; classtype:bad-unknown; gid:1; sid:2014169; rev:3; metadata:created_at 2012_01_31, former_category DNS;)`)
	if !r.Enabled || r.Action != "alert" || r.Header != "dns $HOME_NET any -> any any" {
		t.Errorf("enabled=%v action=%q header=%q", r.Enabled, r.Action, r.Header)
	}
	if r.GID != 1 || r.SID != 2014169 || r.Rev != 3 || r.ID() != "1:2014169" {
		t.Errorf("gid=%d sid=%d rev=%d id=%s", r.GID, r.SID, r.Rev, r.ID())
	}
	if r.Msg != "ET DNS Query" || r.Classtype != "bad-unknown" {
		t.Errorf("msg=%q classtype=%q", r.Msg, r.Classtype)
	}
	if !slices.Equal(r.Flowbits, []string{"set,a", "isset,b"}) {
		t.Errorf("flowbits=%q", r.Flowbits)
	}
	if !slices.Equal(r.Metadata, []string{"created_at 2012_01_31", "former_category DNS"}) {
		t.Errorf("metadata=%q", r.Metadata)
	}
	if !slices.Equal(r.References, []string{"url,x"}) || r.Noalert || r.UsesLua() || r.Group != "" {
		t.Errorf("references=%q noalert=%v lua=%v group=%q", r.References, r.Noalert, r.UsesLua(), r.Group)
	}

	tests := []struct {
		line    string
		enabled bool
		want    string // String() output; "" means not a rule
	}{
		{"#alert tcp any any -> any any (sid:1;)", false, "# alert tcp any any -> any any (sid:1;)"},
		{"## alert tcp any any -> any any (sid:1;)", false, "# alert tcp any any -> any any (sid:1;)"},
		{" \t# #  alert tcp any any -> any any (sid:1;)  ", false, "# alert tcp any any -> any any (sid:1;)"},
		{"   alert tcp any any -> any any (sid:1;)\r\n", true, "alert tcp any any -> any any (sid:1;)"},
		{"alert (msg:\"one word header\"; sid:1;)", true, "alert (msg:\"one word header\"; sid:1;)"},
		{"alert tcp [1.1.1.0/24,![1.1.1.1,1.1.1.2]] any -> any [80,443] (sid:1;)", true, "alert tcp [1.1.1.0/24,![1.1.1.1,1.1.1.2]] any -> any [80,443] (sid:1;)"},
		{"drop tcp any any -> any any (sid:1;)", true, "drop tcp any any -> any any (sid:1;)"},
		{"sdrop tcp any any -> any any (sid:1;)", true, "sdrop tcp any any -> any any (sid:1;)"},
		{"log tcp any any -> any any (sid:1;)", true, "log tcp any any -> any any (sid:1;)"},
		{"rejectsrc tcp any any -> any any (sid:1;)", true, ""},
		{"Alert tcp any any -> any any (sid:1;)", true, ""},
		{"alert\ttcp any any -> any any (sid:1;)", true, ""},
		{"\ufeffalert tcp any any -> any any (sid:1;)", true, ""},
		{"# This is a comment (with parentheses)", false, ""},
		{"alert tcp any any -> any any msg:\"x\"; sid:1;", true, ""},
		{"alert tcp any any -> any any (sid:1;) trailing", true, ""},
		{"alert tcp any any -> any any (content:\"a\nb\"; sid:1;)", true, ""},
		{"alert tcp any any (sid:1;)", true, ""},
		{"", true, ""},
		{"#", false, ""},
	}
	for _, tt := range tests {
		r, err := Parse(tt.line)
		if err != nil {
			t.Errorf("Parse(%q): %v", tt.line, err)
			continue
		}
		if tt.want == "" {
			if r != nil {
				t.Errorf("Parse(%q) = %q, want no rule", tt.line, r)
			}
			continue
		}
		if r == nil {
			t.Errorf("Parse(%q) = nil, want rule", tt.line)
			continue
		}
		if r.Enabled != tt.enabled || r.String() != tt.want {
			t.Errorf("Parse(%q) = %v %q, want %v %q", tt.line, r.Enabled, r.String(), tt.enabled, tt.want)
		}
	}
}

func TestParseOptions(t *testing.T) {
	r := mustParse(t, `alert tcp any any -> any any (msg:"a\;b sid:9; x"; content:"x\;;y"; pcre:"/a\;b/"; sid:1_000; flowbits:noalert; lua:x.lua;)`)
	if r.SID != 1000 || !r.Noalert || !r.UsesLua() {
		t.Errorf("sid=%d noalert=%v lua=%v", r.SID, r.Noalert, r.UsesLua())
	}
	// find_opt_end splits inside quoted strings, so msg is cut at "sid:9".
	if r.Msg != `"a\;b sid:9` {
		t.Errorf("msg = %q", r.Msg)
	}
	if r := mustParse(t, `alert tcp any any -> any any (msg:"x"; noalert; sid:2;)`); !r.Noalert {
		t.Error("noalert option not detected")
	}
	if r := mustParse(t, `alert tcp any any -> any any (msg:"; sid:3;)`); r.Msg != "" || r.SID != 3 {
		t.Errorf("msg=%q sid=%d", r.Msg, r.SID)
	}
	if r := mustParse(t, `alert tcp any any -> any any (msg:"x"; gid:3; sid:4; rev:2; luajit:y.lua;)`); r.GID != 3 || r.ID() != "3:4" || !r.UsesLua() {
		t.Errorf("gid=%d id=%s lua=%v", r.GID, r.ID(), r.UsesLua())
	}

	errTests := []struct {
		line string
		err  error
	}{
		{`alert tcp any any -> any any (msg:"x"; rev:1;)`, ErrNoSID},
		{`alert tcp any any -> any any (msg:"x"; sid:0;)`, ErrNoSID},
		{`alert tcp any any -> any any ()`, ErrNoSID},
		{`alert tcp any any -> any any (msg:"x"; sid:1)`, ErrNoEndOfOption},
		{`alert tcp any any -> any any (msg:"x"; sid:abc;)`, errBadIntOption},
		{`alert tcp any any -> any any (msg:"x"; sid;)`, errBadIntOption},
		{`alert tcp any any -> any any (msg:"x"; metadata; sid:1;)`, errNoMetadataVal},
		{`alert tcp any any -> any any (msg:"x"; sid:-1;)`, errIntOutOfRange},
		{`alert tcp any any -> any any (msg:"x"; sid:4294967296;)`, errIntOutOfRange},
	}
	for _, tt := range errTests {
		if _, err := Parse(tt.line); !errors.Is(err, tt.err) {
			t.Errorf("Parse(%q) = %v, want %v", tt.line, err, tt.err)
		}
	}
}

func TestFindOptEnd(t *testing.T) {
	tests := []struct {
		in   string
		want int
		err  bool
	}{
		{"a;b", 1, false},
		{`a\;b;c`, 4, false},
		{`a\;;b`, 3, false},
		{`\;;;`, 2, false},
		{`ab\;;c;`, 4, false},
		{`a\;;b;`, 5, false}, // offset steps by two, lands on and skips the ';' at index 3
		{"abc", -1, false},
		{"a", 0, true},
		{";", 0, false},
	}
	for _, tt := range tests {
		got, err := findOptEnd([]rune(tt.in))
		if (err != nil) != tt.err || (!tt.err && got != tt.want) {
			t.Errorf("findOptEnd(%q) = %d, %v; want %d, err=%v", tt.in, got, err, tt.want, tt.err)
		}
	}
}

func TestStringNoalert(t *testing.T) {
	tests := []struct{ line, want string }{
		{`alert tcp any any -> any any (msg:"x"; sid:1; rev:1;)`, `alert tcp any any -> any any (msg:"x"; noalert; sid:1; rev:1;)`},
		{`alert tcp any any -> any any (msg:"x";sid: 12 ;)`, `alert tcp any any -> any any (msg:"x";sid: 12 ;)`},
		{`alert tcp any any -> any any (msg:"x";   sid: 12;)`, `alert tcp any any -> any any (msg:"x"; noalert;   sid: 12;)`},
		{`alert tcp any any -> any any (msg:"sid:7; x"; sid:1;)`, `alert tcp any any -> any any (msg:" noalert;sid:7; x"; noalert; sid:1;)`},
		{`alert tcp any any -> any any (msg:"x"; flowbits:noalert; sid:1;)`, `alert tcp any any -> any any (msg:"x"; flowbits:noalert; sid:1;)`},
		{`#alert tcp any any -> any any (msg:"x"; sid:1;)`, `# alert tcp any any -> any any (msg:"x"; noalert; sid:1;)`},
	}
	for _, tt := range tests {
		r := mustParse(t, tt.line)
		r.Noalert = true
		if got := r.String(); got != tt.want {
			t.Errorf("String(%q) = %q, want %q", tt.line, got, tt.want)
		}
		if got := r.format(); got != tt.want {
			t.Errorf("format(%q) = %q, want %q", tt.line, got, tt.want)
		}
	}
}

func TestParseFile(t *testing.T) {
	in := "# header\n" +
		"alert tcp any any -> any any (msg:\"one\"; sid:1;)\n" +
		"alert tcp any any -> any any (msg:\"two\"; \\\r\n" +
		"   content:\"x\"; \\   \n" +
		"   sid:2;)\r\n" +
		"alert tcp any any -> any any (msg:\"bad\"; rev:1;)\n" +
		"#alert tcp any any -> any any (msg:\"three\"; sid:3;)\n" +
		"alert tcp any any -> any any (msg:\"pending\"; \\\n"
	var failed []int
	rules, err := ParseFileFunc("rules/x.rules", strings.NewReader(in), func(line int, text string, err error) {
		failed = append(failed, line)
	})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range rules {
		got = append(got, r.String())
		if r.Group != "rules/x.rules" {
			t.Errorf("group = %q", r.Group)
		}
	}
	want := []string{
		`alert tcp any any -> any any (msg:"one"; sid:1;)`,
		`alert tcp any any -> any any (msg:"two";     content:"x";     sid:2;)`,
		`# alert tcp any any -> any any (msg:"three"; sid:3;)`,
	}
	if !slices.Equal(got, want) {
		t.Errorf("rules =\n%q\nwant\n%q", got, want)
	}
	if !slices.Equal(failed, []int{6}) {
		t.Errorf("failed lines = %v", failed)
	}

	if _, err := ParseFile("x", bytes.NewReader([]byte("alert tcp any any -> any any (msg:\"\xff\"; sid:1;)\n"))); err == nil {
		t.Error("invalid UTF-8: want error")
	}

	var buf bytes.Buffer
	if err := Write(&buf, append(rules, nil)); err != nil {
		t.Fatal(err)
	}
	if buf.String() != strings.Join(want, "\n")+"\n" {
		t.Errorf("Write = %q", buf.String())
	}
}

func TestParseFiles(t *testing.T) {
	files := []SourceFile{
		{Name: "p/b.rules", Content: []byte("alert tcp any any -> any any (msg:\"b\"; sid:2;)\n")},
		{Name: "p/emerging-deleted.rules", Content: []byte("alert tcp any any -> any any (msg:\"del\"; sid:3;)\n")},
		{Name: "p/a.rules", Content: []byte("alert tcp any any -> any any (msg:\"a\"; sid:1;)\n")},
		{Name: "p/classification.config", Content: []byte("config classification: x,y,1\n")},
		{Name: "p/list.lst", Content: []byte("x\n")},
	}
	rules, deps, err := ParseFiles(files, LoadOptions{Ignore: DefaultIgnore})
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, r := range rules {
		ids = append(ids, r.Group+"="+r.ID())
	}
	if !slices.Equal(ids, []string{"p/a.rules=1:1", "p/b.rules=1:2"}) {
		t.Errorf("rules = %v", ids)
	}
	if len(deps) != 1 || string(deps["p/list.lst"]) != "x\n" {
		t.Errorf("deps = %v", deps)
	}
	rules, _, err = ParseFiles(files, LoadOptions{})
	if err != nil || len(rules) != 3 {
		t.Errorf("without ignore: %d rules, %v", len(rules), err)
	}
}
