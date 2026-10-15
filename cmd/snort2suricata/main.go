// Command snort2suricata converts Snort 2.9 and Snort 3 rules to Suricata 8
// rules.
//
//	snort2suricata [-dialect auto|snort2|snort3] [-o out.rules]
//	    [-rejected rejected.rules] [-report report.json] [-exact-only]
//	    [-enable-all] [file...]
//
// Rules that cannot be converted are left out of the output (and written to
// -rejected with the reasons). Rules converted with a documented change in
// meaning are written with a "# snort2suricata: approx" comment line, or
// rejected with -exact-only.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/jc-lab/suricontroller/pkg/snortconv"
)

type ruleReport struct {
	File    string            `json:"file"`
	Line    int               `json:"line"`
	GID     string            `json:"gid"`
	SID     string            `json:"sid"`
	Msg     string            `json:"msg"`
	Enabled bool              `json:"enabled"`
	Dialect string            `json:"dialect"`
	Status  snortconv.Status  `json:"status"`
	Issues  []snortconv.Issue `json:"issues,omitempty"`
}

type report struct {
	Total    int            `json:"total"`
	Enabled  int            `json:"enabled"`
	Exact    int            `json:"exact"`
	Approx   int            `json:"approx"`
	Failed   int            `json:"failed"`
	Written  int            `json:"written"`
	Codes    map[string]int `json:"issue_codes"`
	NonExact []ruleReport   `json:"non_exact"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "snort2suricata:", err)
		os.Exit(1)
	}
}

func run() error {
	dialect := flag.String("dialect", "auto", "input dialect: auto, snort2 or snort3")
	outPath := flag.String("o", "-", "output rules file")
	rejPath := flag.String("rejected", "", "write rules that were not converted to this file")
	repPath := flag.String("report", "", "write a JSON report to this file")
	exactOnly := flag.Bool("exact-only", false, "reject rules that only convert approximately")
	enableAll := flag.Bool("enable-all", false, "enable rules that are commented out in the input")
	quiet := flag.Bool("q", false, "do not print the summary")
	flag.Parse()

	d, err := snortconv.ParseDialect(*dialect)
	if err != nil {
		return err
	}
	out, closeOut, err := create(*outPath, os.Stdout)
	if err != nil {
		return err
	}
	defer closeOut()
	rej := io.Discard
	if *rejPath != "" {
		w, closeRej, err := create(*rejPath, nil)
		if err != nil {
			return err
		}
		defer closeRej()
		rej = w
	}

	rep := &report{Codes: map[string]int{}}
	files := flag.Args()
	if len(files) == 0 {
		files = []string{"-"}
	}
	for _, f := range files {
		if err := convertFile(f, d, *exactOnly, *enableAll, out, rej, rep); err != nil {
			return err
		}
	}
	if err := out.Flush(); err != nil {
		return err
	}
	if b, ok := rej.(*bufio.Writer); ok {
		if err := b.Flush(); err != nil {
			return err
		}
	}
	if *repPath != "" {
		b, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(*repPath, append(b, '\n'), 0o644); err != nil {
			return err
		}
	}
	if !*quiet {
		printSummary(rep)
	}
	return nil
}

func create(path string, std *os.File) (*bufio.Writer, func(), error) {
	if path == "-" && std != nil {
		return bufio.NewWriter(std), func() {}, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, err
	}
	return bufio.NewWriter(f), func() { f.Close() }, nil
}

func convertFile(name string, d snortconv.Dialect, exactOnly, enableAll bool, out, rej io.Writer, rep *report) error {
	var data []byte
	var err error
	if name == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(name)
	}
	if err != nil {
		return err
	}
	lines := joinContinuations(strings.Split(string(data), "\n"))
	if d == snortconv.Auto {
		d = snortconv.DetectDialect(lines)
	}
	for i, line := range lines {
		if enableAll {
			line = uncomment(line)
		}
		res, err := snortconv.Convert(line, d)
		if errors.Is(err, snortconv.ErrNotRule) {
			continue
		}
		if err != nil {
			return fmt.Errorf("%s:%d: %w", name, i+1, err)
		}
		rep.Total++
		if res.Enabled {
			rep.Enabled++
		}
		status := res.Status
		switch status {
		case snortconv.Exact:
			rep.Exact++
		case snortconv.Approx:
			rep.Approx++
		default:
			rep.Failed++
		}
		for _, is := range res.Issues {
			rep.Codes[is.Severity.String()+":"+is.Code]++
		}
		if status != snortconv.Exact {
			rep.NonExact = append(rep.NonExact, ruleReport{
				File: name, Line: i + 1, GID: res.GID, SID: res.SID, Msg: res.Msg,
				Enabled: res.Enabled, Dialect: res.Dialect.String(), Status: status, Issues: res.Issues,
			})
		}
		if status == snortconv.Failed || (exactOnly && status == snortconv.Approx) {
			fmt.Fprintf(rej, "# %s %s:%s: %s\n%s\n", status, res.GID, res.SID, reasons(res, snortconv.Approx), strings.TrimSpace(line))
			continue
		}
		if status == snortconv.Approx {
			fmt.Fprintf(out, "# snort2suricata: approx: %s\n", reasons(res, snortconv.Approx))
		}
		fmt.Fprintln(out, res.Output)
		rep.Written++
	}
	return nil
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

// joinContinuations joins lines ending with a backslash, as Snort does.
// The result keeps one entry per physical line so line numbers stay valid.
func joinContinuations(lines []string) []string {
	out := make([]string, len(lines))
	for i := 0; i < len(lines); i++ {
		start := i
		cur := lines[i]
		for strings.HasSuffix(strings.TrimRight(cur, " \t\r"), "\\") && i+1 < len(lines) {
			cur = strings.TrimSuffix(strings.TrimRight(cur, " \t\r"), "\\") + lines[i+1]
			i++
		}
		out[start] = cur
	}
	return out
}

func uncomment(line string) string {
	t := strings.TrimLeft(line, " \t")
	if !strings.HasPrefix(t, "#") {
		return line
	}
	return strings.TrimLeft(t, "# \t")
}

func printSummary(rep *report) {
	fmt.Fprintf(os.Stderr, "rules: %d (enabled %d)\n", rep.Total, rep.Enabled)
	fmt.Fprintf(os.Stderr, "exact: %d, approx: %d, failed: %d, written: %d\n", rep.Exact, rep.Approx, rep.Failed, rep.Written)
	codes := make([]string, 0, len(rep.Codes))
	for k := range rep.Codes {
		codes = append(codes, k)
	}
	sort.Slice(codes, func(i, j int) bool { return rep.Codes[codes[i]] > rep.Codes[codes[j]] })
	for _, k := range codes {
		fmt.Fprintf(os.Stderr, "  %6d %s\n", rep.Codes[k], k)
	}
}
