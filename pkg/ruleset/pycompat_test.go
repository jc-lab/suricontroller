package ruleset

import (
	"errors"
	"slices"
	"testing"
)

// Expected values in this file were produced with CPython 3.12 (the
// interpreter suricata-update 1.3.0 runs on).

func TestFnmatch(t *testing.T) {
	tests := []struct {
		pat, name string
		want      bool
	}{
		{"*.rules", "emerging-dns.rules", true},
		{"*.rules", "x.rule", false},
		{"emerging-*", "emerging-dns", true},
		{"emerging-d?s", "emerging-dns", true},
		{"emerging-[a-d]ns", "emerging-dns", true},
		{"emerging-[!a-d]ns", "emerging-dns", false},
		{"emerging-[!a-d]ns", "emerging-ens", true},
		{"[]]x", "]x", true},
		{"[!]]x", "ax", true},
		{"[!]]x", "]x", false},
		{"[z-a]x", "zx", false},
		{"[z-a]x", "-x", false},
		{"[a-]x", "-x", true},
		{"[-a]x", "-x", true},
		{"[^a]x", "^x", true},
		{"[^a]x", "bx", false},
		{"[", "[", true},
		{"a[b", "a[b", true},
		{"*", "", true},
		{"*/foo.rules", "rules/foo.rules", true},
		{"*/foo.rules", "a/b/foo.rules", true},
		{"rules/*", "rules/a/b", true},
		{"a\\*b", "a\\xb", true},
		{"a\\*b", "a*b", false},
		{"[\\]a", "\\a", true},
		{"[!]", "!", false},
		{"[!]", "a", false},
		{"[a-c-e]x", "dx", false},
		{"[a-c-e]x", "-x", true},
		{"[a&&b]x", "&x", true},
		{"**a", "xxa", true},
		{"?", "é", true},
		{"[[:alpha:]]", "a]", true},
		{"[[:alpha:]]", "[]", true},
		{"a-*", "a-b", true},
		{"[!a-c]x", "\nx", true},
	}
	for _, tt := range tests {
		got, err := fnmatch(tt.name, tt.pat)
		if err != nil {
			t.Errorf("fnmatch(%q, %q): %v", tt.name, tt.pat, err)
			continue
		}
		if got != tt.want {
			t.Errorf("fnmatch(%q, %q) = %v, want %v", tt.name, tt.pat, got, tt.want)
		}
	}
}

func TestShlexSplit(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"2019401 \"seconds \\d+\" \"seconds 3600\"", []string{"2019401", "seconds \\d+", "seconds 3600"}},
		{"a 'b c' d", []string{"a", "b c", "d"}},
		{"a \"b\\\"c\" d", []string{"a", "b\"c", "d"}},
		{"a \"b\\\\c\" d", []string{"a", "b\\c", "d"}},
		{"a b\\ c", []string{"a", "b c"}},
		{"x \"\" y", []string{"x", "", "y"}},
		{"x '' y", []string{"x", "", "y"}},
		{"ab\"cd\"ef", []string{"abcdef"}},
		{"  lead  trail  ", []string{"lead", "trail"}},
		{"'it''s'", []string{"its"}},
		{"\"a\\nb\"", []string{"a\\nb"}},
		{"a\\'b", []string{"a'b"}},
		{"modifysid 1 \"a\" | \"b\"", []string{"modifysid", "1", "a", "|", "b"}},
		{"\"tab\tin\"", []string{"tab\tin"}},
		{"a\tb\rc\nd", []string{"a", "b", "c", "d"}},
		{"", nil},
	}
	for _, tt := range tests {
		got, err := shlexSplit(tt.in)
		if err != nil {
			t.Errorf("shlexSplit(%q): %v", tt.in, err)
			continue
		}
		if !slices.Equal(got, tt.want) {
			t.Errorf("shlexSplit(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
	for _, in := range []string{"\"unterminated", "a\\"} {
		if _, err := shlexSplit(in); err == nil {
			t.Errorf("shlexSplit(%q): want error", in)
		}
	}
}

func TestPyRegexSearch(t *testing.T) {
	tests := []struct {
		pat     string
		icase   bool
		subject string
		want    bool
	}{
		{"ET INFO", true, "alert (msg:\"et info x\";)", true},
		{"^alert", false, "alert tcp", true},
		{"^alert", false, "# alert", false},
		{"\\d+", false, "abc", false},
		{"\\d+", false, "a1", true},
		{"\\d", false, "٣", true},
		{"\\w+é", false, "café", true},
		{"[\\w-]+\\.com", false, "x my-site.com", true},
		{"\\s", false, "\u001c", true},
		{"\\s", false, "\u00a0", true},
		{"\\S", false, "  ", false},
		{"[^\\W]", false, "é", true},
		{"[\\W]", false, "é", false},
		{"[\\Wa]", false, "a", true},
		{"[^\\Wa]", false, "a", false},
		{"[^\\Wa]", false, "b", true},
		{"(?i)abc", false, "ABC", true},
		{"(?i:a)B", false, "Ab", false},
		{"(?i:a)B", false, "AB", true},
		{"a{2,3}", false, "aa", true},
		{"a{,2}b", false, "b", true},
		{"a{,}b", false, "aaab", true},
		{"x{", false, "x{", true},
		{"x{a}", false, "x{a}", true},
		{"x{}", false, "x{}", true},
		{"a{1,2", false, "a{1,2", true},
		{"[]a]", false, "]", true},
		{"[^]a]", false, "]", false},
		{"a.c", false, "a\nc", false},
		{"(?s)a.c", false, "a\nc", true},
		{"(?m)^b", false, "a\nb", true},
		{"^b", false, "a\nb", false},
		{"\\Aa", false, "ba", false},
		{"a\\Z", false, "ba", true},
		{"\\x41\\u0042\\U00000043", false, "ABC", true},
		{"\\101", false, "A", true},
		{"\\0", false, "\u0000", true},
		{"[\\0-\\x08]", false, "\u0005", true},
		{"(?x) a b # comment", false, "ab", true},
		{"(?x)a\\ b", false, "a b", true},
		{"(?x)[ ]", false, " ", true},
		{"a(?#comment)b", false, "ab", true},
		{"(?P<n>x)y", false, "xy", true},
		{"a|b|", false, "c", true},
		{"\\$HOME_NET", false, "$HOME_NET", true},
		{"$HOME_NET", false, "$HOME_NET", false},
		{"[a-c]+", true, "ABC", true},
		{"\\bfoo\\b", false, "a foo b", true},
		{"\\bfoo\\b", false, "afoob", false},
		{"(?a)\\w", false, "é", false},
		{"(?a:\\d)", false, "٣", false},
		{"[\\d]", false, "٣", true},
		{"[\\s]", false, "\u2028", true},
		{"\\-\\;\\:\\\"", false, "-;:\"", true},
		{"\\é", false, "é", true},
		{"a*?b", false, "aab", true},
		{"(?:ab)+", false, "abab", true},
		{"[\\b]", false, "\b", true},
		{"\\\\", false, "\\", true},
	}
	for _, tt := range tests {
		flags := 0
		if tt.icase {
			flags = pyFlagI
		}
		rx, err := compilePyRegex(tt.pat, flags)
		if err != nil {
			t.Errorf("compilePyRegex(%q): %v", tt.pat, err)
			continue
		}
		got, err := rx.search(tt.subject)
		if err != nil {
			t.Errorf("search(%q, %q): %v", tt.pat, tt.subject, err)
			continue
		}
		if got != tt.want {
			t.Errorf("search(%q, %q) = %v, want %v (go: %s)", tt.pat, tt.subject, got, tt.want, rx.re)
		}
	}
}

func TestPyRegexErrors(t *testing.T) {
	invalid := []string{
		"(unclosed", "[a-", "a**", "a{2}{3}", "\\q", "*a", "a)", "(?<x>a)", "(?P<1>a)",
		"[z-a]", "\\x4", "\\u12", "(?Q)", "a(?i)b", "\\1", "(a)\\2", "(a\\1)", "[\\A]",
		"[\\8]", "\\p{L}", "(?P<a>x)(?P<a>y)", "a{3,2}", "^*", "(?L)a", "(?au)a",
		"(?-a:x)", "(?i-i:x)", "x\\",
	}
	for _, p := range invalid {
		_, err := compilePyRegex(p, 0)
		if !errors.Is(err, errPyInvalid) {
			t.Errorf("compilePyRegex(%q) = %v, want invalid", p, err)
		}
	}
	unsupported := []string{
		"a(?=b)", "(?<!a)b", "(a)\\1", "(?P<n>a)(?P=n)", "(?>a)", "a*+",
		"(a)?(?(1)b|c)", "a{1001}", "\\N{EM DASH}", "(?P<é>a)",
	}
	for _, p := range unsupported {
		_, err := compilePyRegex(p, 0)
		if !errors.Is(err, ErrUnsupported) {
			t.Errorf("compilePyRegex(%q) = %v, want unsupported", p, err)
		}
	}
	if _, err := compilePyRegex(`x\\`, 0); err != nil {
		t.Errorf(`compilePyRegex("x\\\\"): %v`, err)
	}
}

func TestPyRegexWordBoundaryNonASCII(t *testing.T) {
	rx, err := compilePyRegex(`\bcafé\b`, 0)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := rx.search("a café b"); !errors.Is(err, ErrUnsupported) {
		t.Errorf("search = %v, %v; want ErrUnsupported", ok, err)
	}
	// Non-ASCII text without word characters is fine.
	if ok, err := rx.search("— cafe —"); err == nil {
		_ = ok
	} else {
		t.Errorf("unexpected error: %v", err)
	}
	ascii, err := compilePyRegex(`(?a)\bé`, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ascii.search("é"); err != nil {
		t.Errorf("ASCII \\b should be exact: %v", err)
	}
}

func TestPySub(t *testing.T) {
	tests := []struct{ pat, repl, subject, want string }{
		{"(seconds) (\\d+)", "\\1 3600", "count 5, seconds 60;", "count 5, seconds 3600;"},
		{"(msg:\\\")ET", "\\1XX", "msg:\"ET a\"; msg:\"ET b\"", "msg:\"XX a\"; msg:\"XX b\""},
		{"(?P<k>a)", "<\\g<k>\\g<0>\\g<1>>", "xax", "x<aaa>x"},
		{"a", "\\n\\t\\\\", "a", "\n\t\\"},
		{"a", "\\;\\$\\-", "a", "\\;\\$\\-"},
		{"a", "\\0\\01\\012", "a", "\u0000\u0001\n"},
		{"a", "\\101x", "a", "Ax"},
		{"(a)|(b)", "[\\2]", "ab", "[][b]"},
		{"(a)(b)(c)(d)(e)(f)(g)(h)(i)(j)(k)", "\\11\\10\\1", "abcdefghijk", "kja"},
		{";\\s*\\)$", "; metadata: k v;)", "alert (msg:\"x\"; sid:1;  )", "alert (msg:\"x\"; sid:1; metadata: k v;)"},
		{"\\$HOME_NET", "$INT", "a $HOME_NET b $HOME_NET", "a $INT b $INT"},
	}
	for _, tt := range tests {
		rx, err := compilePyRegex(tt.pat, 0)
		if err != nil {
			t.Errorf("compilePyRegex(%q): %v", tt.pat, err)
			continue
		}
		tmpl, err := parsePyTemplate(tt.repl, rx)
		if err != nil {
			t.Errorf("parsePyTemplate(%q): %v", tt.repl, err)
			continue
		}
		got, err := rx.sub(tmpl, tt.subject)
		if err != nil {
			t.Errorf("sub(%q, %q): %v", tt.pat, tt.repl, err)
			continue
		}
		if got != tt.want {
			t.Errorf("sub(%q, %q, %q) = %q, want %q", tt.pat, tt.repl, tt.subject, got, tt.want)
		}
	}

	badTemplates := []struct{ pat, repl string }{
		{"a", "\\q"}, {"(a)", "\\2"}, {"a", "\\g<x>"}, {"a", "\\g<"}, {"a", "x\\"},
		{"(a)", "\\g<2>"}, {"a", "\\g"}, {"a", "\\777"}, {"x", "é\\x"},
	}
	for _, tt := range badTemplates {
		rx, err := compilePyRegex(tt.pat, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parsePyTemplate(tt.repl, rx); err == nil {
			t.Errorf("parsePyTemplate(%q, %q): want error", tt.pat, tt.repl)
		}
	}

	rx, err := compilePyRegex("x*", 0)
	if err != nil {
		t.Fatal(err)
	}
	if !rx.nullable {
		t.Error("x* should be nullable")
	}
	if _, err := rx.sub(&pyTemplate{}, "abc"); !errors.Is(err, ErrUnsupported) {
		t.Errorf("sub with nullable pattern: %v, want ErrUnsupported", err)
	}
}

func TestPyHelpers(t *testing.T) {
	intTests := []struct {
		in       string
		want     int64
		ok, over bool
	}{
		{"42", 42, true, false},
		{" +7 ", 7, true, false},
		{"-3", -3, true, false},
		{"1_000", 1000, true, false},
		{"007", 7, true, false},
		{"٣٤", 34, true, false},
		{"1__0", 0, false, false},
		{"_1", 0, false, false},
		{"1_", 0, false, false},
		{"", 0, false, false},
		{"0x10", 0, false, false},
		{"- 1", 0, false, false},
		{"99999999999999999999", 0, true, true},
	}
	for _, tt := range intTests {
		v, ok, over := pyInt(tt.in)
		if v != tt.want || ok != tt.ok || over != tt.over {
			t.Errorf("pyInt(%q) = %d, %v, %v; want %d, %v, %v", tt.in, v, ok, over, tt.want, tt.ok, tt.over)
		}
	}
	for in, want := range map[string]string{"rules/a.rules": "rules", "a.rules": "", "/a": "/", "//a": "//", "a//b/c": "a//b", "a/b//c": "a/b"} {
		if got := pyDirname(in); got != want {
			t.Errorf("pyDirname(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{"a.rules": "a", ".rules": ".rules", "a.b.c": "a.b", "..x": "..x", "a": "a", "x/.y.z": "x/.y"} {
		if got := pySplitextRoot(in); got != want {
			t.Errorf("pySplitextRoot(%q) = %q, want %q", in, got, want)
		}
	}
	if got := pyStrip("\u00a0\x1c x \u3000"); got != "x" {
		t.Errorf("pyStrip = %q", got)
	}
	if got := pyLower("İX"); got != "i\u0307x" {
		t.Errorf("pyLower = %q", got)
	}
}
