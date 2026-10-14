package ruleset

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestValidateConfig(t *testing.T) {
	valid := Config{
		Disable: []string{"# comment", "", "2019401", "1:2019401,2019402 # trailing", "group:emerging-*.rules", "emerging-dns.rules", "re:ET\\s+INFO", "filename:*/x.rules", "metadata: signature_severity Minor", "*"},
		Enable:  []string{"group:emerging-exploit"},
		Drop:    []string{"re:ET TROJAN"},
		Modify: []string{
			`2019401 "seconds \d+" "seconds 3600"`,
			`re:foo "(msg:\")" "${1}x"`,
			`modifysid 2019401 "alert" | "drop"`,
			`metadata-add group:emerging-dns.rules "k" "v"`,
		},
	}
	if err := ValidateConfig(valid); err != nil {
		t.Fatalf("ValidateConfig(valid): %v", err)
	}

	type bad struct {
		kind string
		line int
	}
	tests := []struct {
		name string
		cfg  Config
		want []bad
		// unsupported reports whether the error must wrap ErrUnsupported.
		unsupported bool
	}{
		{"unclosed re", Config{Disable: []string{"re:(unclosed"}}, []bad{{"disable", 1}}, false},
		{"unparsable spec", Config{Enable: []string{"# c", "", "foo bar"}}, []bad{{"enable", 3}}, false},
		{"trailing comma", Config{Drop: []string{"2001,"}}, []bad{{"drop", 1}}, false},
		{"lookahead re", Config{Disable: []string{"re:a(?=b)"}}, []bad{{"disable", 1}}, true},
		{"modify arg count", Config{Modify: []string{`2001 "a"`}}, []bad{{"modify", 1}}, false},
		{"modify unclosed quote", Config{Modify: []string{`2001 "a "b"`}}, []bad{{"modify", 1}}, false},
		{"modify bad matcher", Config{Modify: []string{`foo "a" "b"`}}, []bad{{"modify", 1}}, false},
		{"modify bad pattern", Config{Modify: []string{`2001 "(a" "b"`}}, []bad{{"modify", 1}}, false},
		{"modify unsupported pattern", Config{Modify: []string{`2001 "(?<=a)b" "c"`}}, []bad{{"modify", 1}}, true},
		{"modify empty-matching pattern", Config{Modify: []string{`2001 "x*" "c"`}}, []bad{{"modify", 1}}, true},
		{"modify bad replacement", Config{Modify: []string{`2001 "a" "\2"`}}, []bad{{"modify", 1}}, false},
		{"modify bad escape in replacement", Config{Modify: []string{`2001 "a" "\q"`}}, []bad{{"modify", 1}}, false},
		{"metadata-add args", Config{Modify: []string{`metadata-add 2001 "k"`}}, []bad{{"modify", 1}}, false},
		{"metadata-add bad escape", Config{Modify: []string{`metadata-add 2001 "k" "\q"`}}, []bad{{"modify", 1}}, false},
		{"several", Config{
			Disable: []string{"2001", "re:[a-"},
			Modify:  []string{"# x", `2001 "a" "b"`, `2001 "a"`},
		}, []bad{{"disable", 2}, {"modify", 3}}, false},
		{"multi-line element", Config{Disable: []string{"2001\n\nre:(\r\n2002"}}, []bad{{"disable", 3}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateConfig(tt.cfg)
			if err == nil {
				t.Fatal("want error")
			}
			var got []bad
			for _, e := range err.(interface{ Unwrap() []error }).Unwrap() {
				var ce *ConfError
				if !errors.As(e, &ce) {
					t.Fatalf("error %v is not a *ConfError", e)
				}
				got = append(got, bad{ce.Kind, ce.Line})
				if !strings.Contains(ce.Error(), ce.Kind+".conf line") {
					t.Errorf("message %q lacks kind and line", ce.Error())
				}
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("errors at %v, want %v (%v)", got, tt.want, err)
			}
			if tt.unsupported && !errors.Is(err, ErrUnsupported) {
				t.Errorf("error %v does not wrap ErrUnsupported", err)
			}

			// Process fails fast with the same error, even without rules.
			if _, _, perr := Process(nil, tt.cfg); perr == nil || perr.Error() != err.Error() {
				t.Errorf("Process error = %v, want %v", perr, err)
			}
		})
	}
}

func TestProcessIgnoreInvalid(t *testing.T) {
	r := mustParse(t, `alert tcp any any -> any any (msg:"x"; content:"a"; sid:1; rev:1;)`)
	var logs []string
	cfg := Config{
		Disable:       []string{"re:(unclosed", "foo", "1"},
		IgnoreInvalid: true,
		Logf:          func(f string, a ...any) { logs = append(logs, f) },
	}
	out, st, err := Process([]*Rule{r}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if out[0].Enabled || st.DisabledByConf != 1 || len(logs) != 2 {
		t.Errorf("enabled=%v disabledByConf=%d logs=%q", out[0].Enabled, st.DisabledByConf, logs)
	}

	// Unsupported constructs are errors even when ignoring invalid lines.
	cfg.Disable = []string{"re:a(?=b)"}
	if _, _, err := Process([]*Rule{r}, cfg); !errors.Is(err, ErrUnsupported) {
		t.Errorf("Process = %v, want ErrUnsupported", err)
	}

	// Python compiles replacement templates lazily: with IgnoreInvalid a
	// bad replacement only fails when a rule matches.
	cfg.Disable = nil
	cfg.Modify = []string{`2 "a" "\q"`}
	if _, _, err := Process([]*Rule{r}, cfg); err != nil {
		t.Errorf("Process with unmatched bad replacement: %v", err)
	}
	cfg.Modify = []string{`1 "a" "\q"`}
	if _, _, err := Process([]*Rule{r}, cfg); err == nil {
		t.Error("Process with matched bad replacement: want error")
	}
}

func mustParse(t *testing.T, line string) *Rule {
	t.Helper()
	r, err := Parse(line)
	if err != nil || r == nil {
		t.Fatalf("Parse(%q) = %v, %v", line, r, err)
	}
	return r
}
