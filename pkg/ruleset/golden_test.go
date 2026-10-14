package ruleset

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The golden files under testdata/cases were produced by the real
// suricata-update with testdata/gen-golden.sh.

func loadDirFiles(t *testing.T, dir, prefix string) []SourceFile {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var files []SourceFile
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, SourceFile{Name: prefix + e.Name(), Content: data})
	}
	return files
}

func readConf(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return []string{string(data)}
}

func confFromDir(t *testing.T, dir string) Config {
	return Config{
		Disable:         readConf(t, filepath.Join(dir, "disable.conf")),
		Enable:          readConf(t, filepath.Join(dir, "enable.conf")),
		Drop:            readConf(t, filepath.Join(dir, "drop.conf")),
		Modify:          readConf(t, filepath.Join(dir, "modify.conf")),
		ResolveFlowbits: true,
		// Reproduce suricata-update, which skips bad conf lines.
		IgnoreInvalid: true,
	}
}

// readStats parses a stats.txt written by gen-golden.sh.
func readStats(t *testing.T, path string) map[string]int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]int{}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		k, v, _ := strings.Cut(line, " ")
		n, err := strconv.Atoi(v)
		if err != nil {
			t.Fatalf("%s: bad line %q", path, line)
		}
		m[k] = n
	}
	return m
}

func statsMap(st Stats) map[string]int {
	return map[string]int{
		"loaded":           st.Loaded,
		"disabled_by_conf": st.DisabledByConf,
		"enabled_by_conf":  st.EnabledByConf,
		"modified":         st.Modified,
		"dropped":          st.Dropped,
		"flowbits_enabled": st.FlowbitsEnabled,
		"total":            st.Total,
		// suricata-update counts before disabling rules with missing
		// dataset files.
		"enabled": st.Enabled + st.DatasetDisabled,
	}
}

// compareGolden runs ParseFiles+Process+Write and compares the output, the
// stats and the dataset files with what suricata-update produced in dir.
func compareGolden(t *testing.T, files []SourceFile, cfg Config, dir string) {
	t.Helper()
	rules, deps, err := ParseFiles(files, LoadOptions{Ignore: DefaultIgnore})
	if err != nil {
		t.Fatal(err)
	}
	cfg.DepFiles = deps
	out, st, err := Process(rules, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if st.Disabled != st.Total-st.Enabled {
		t.Errorf("Disabled = %d, want %d", st.Disabled, st.Total-st.Enabled)
	}
	var buf bytes.Buffer
	if err := Write(&buf, out); err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join(dir, "suricata.rules"))
	if err != nil {
		t.Fatal(err)
	}
	if diff := lineDiff(want, buf.Bytes()); diff != "" {
		t.Errorf("output differs from suricata-update:\n%s", diff)
	}

	wantStats := readStats(t, filepath.Join(dir, "stats.txt"))
	gotStats := statsMap(st)
	for k, v := range wantStats {
		if gotStats[k] != v {
			t.Errorf("stats %s = %d, want %d", k, gotStats[k], v)
		}
	}

	data, err := os.ReadFile(filepath.Join(dir, "datasets.txt"))
	if err != nil {
		t.Fatal(err)
	}
	wantSets := strings.Fields(string(data))
	var gotSets []string
	for p := range DatasetFiles(out) {
		gotSets = append(gotSets, strings.TrimPrefix(p, "datasets/"))
	}
	slices.Sort(gotSets)
	if !slices.Equal(gotSets, wantSets) {
		t.Errorf("dataset files = %v, want %v", gotSets, wantSets)
	}
}

// lineDiff reports the first few differing lines between want and got.
func lineDiff(want, got []byte) string {
	if bytes.Equal(want, got) {
		return ""
	}
	wl := strings.SplitAfter(string(want), "\n")
	gl := strings.SplitAfter(string(got), "\n")
	var b strings.Builder
	fmt.Fprintf(&b, "want %d lines, got %d lines\n", len(wl), len(gl))
	shown := 0
	for i := 0; i < max(len(wl), len(gl)) && shown < 10; i++ {
		var w, g string
		if i < len(wl) {
			w = wl[i]
		}
		if i < len(gl) {
			g = gl[i]
		}
		if w != g {
			fmt.Fprintf(&b, "line %d:\n  want: %q\n  got:  %q\n", i+1, w, g)
			shown++
		}
	}
	return b.String()
}

func TestGolden(t *testing.T) {
	files := loadDirFiles(t, "testdata/rules", "rules/")
	cases, err := os.ReadDir("testdata/cases")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		if !c.IsDir() {
			continue
		}
		dir := filepath.Join("testdata/cases", c.Name())
		t.Run(c.Name(), func(t *testing.T) {
			cfg := confFromDir(t, dir)
			err := ValidateConfig(cfg)
			if c.Name() == "invalid" {
				if err == nil {
					t.Fatal("ValidateConfig: want error for the invalid case")
				}
			} else if err != nil {
				t.Fatalf("ValidateConfig: %v", err)
			}
			compareGolden(t, files, cfg, dir)
			if err == nil {
				// Strict mode must give the same result for valid confs.
				cfg.IgnoreInvalid = false
				compareGolden(t, files, cfg, dir)
			}
		})
	}
}
