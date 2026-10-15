// Package engine manages Suricata instances on the node: rendering their
// configuration, validating it with `suricata -T`, and running them.
//
// The Runtime interface hides how Suricata runs. The Supervisor
// implementation starts Suricata as child processes of the agent (docker
// profile, or any host without a service manager); service-manager based
// runtimes (procd, systemd) can implement the same interface.
package engine

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// CaptureMode selects the Suricata runmode of an instance.
type CaptureMode string

const (
	CaptureAFPacket CaptureMode = "af-packet"
	CaptureNFQ      CaptureMode = "nfq"
	// CapturePlugin runs the suritap capture plugin (fed by proxies).
	CapturePlugin CaptureMode = "plugin"
)

// PluginCaptureName is the name the suritap plugin registers its capture
// method under (--capture-plugin=suritap).
const PluginCaptureName = "suritap"

// Info describes the Suricata build.
type Info struct {
	Version  string
	Features []string
	NFQ      bool
	AFPacket bool
}

// InstanceSpec describes a running instance.
type InstanceSpec struct {
	Name       string
	Capture    CaptureMode
	Interfaces []string
	Queues     []uint16
	ConfigPath string
	// ConfigHash changes whenever the instance must be restarted.
	ConfigHash string
	SocketPath string
	PidFile    string
	LogDir     string
}

// RuleError is a rule that failed to load.
type RuleError struct {
	File    string
	Line    int
	SID     int
	Message string
}

// ValidationResult is the outcome of `suricata -T`.
type ValidationResult struct {
	OK         bool
	Output     string
	RuleErrors []RuleError
}

// InstanceStatus describes an instance.
type InstanceStatus struct {
	Name        string
	Capture     CaptureMode
	Interfaces  []string
	Running     bool
	Uptime      time.Duration
	RSSBytes    uint64
	Counters    map[string]uint64
	RulesLoaded int
	RulesFailed int
	LastError   string
}

// LogLine is a line of engine output.
type LogLine struct {
	Instance string
	Line     string
}

// Runtime runs Suricata instances.
type Runtime interface {
	Info(ctx context.Context) (Info, error)
	Validate(ctx context.Context, spec InstanceSpec) (*ValidationResult, error)
	// Ensure converges the running instances to specs: instances with an
	// unchanged ConfigHash keep running, others are (re)started or stopped.
	Ensure(ctx context.Context, specs []InstanceSpec) error
	ReloadRules(ctx context.Context, instance string) error
	Signal(instance string, sig os.Signal) error
	Status(ctx context.Context) []InstanceStatus
	// Output delivers engine stdout/stderr lines.
	Output() <-chan LogLine
	Stop(ctx context.Context) error
}

var versionRe = regexp.MustCompile(`This is Suricata version (\S+)`)

// ParseBuildInfo parses `suricata --build-info` output.
func ParseBuildInfo(out []byte) Info {
	var info Info
	if m := versionRe.FindSubmatch(out); m != nil {
		info.Version = string(m[1])
	}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if f, ok := strings.CutPrefix(line, "Features:"); ok {
			info.Features = strings.Fields(f)
		}
	}
	for _, f := range info.Features {
		switch f {
		case "NFQ":
			info.NFQ = true
		case "AF_PACKET":
			info.AFPacket = true
		}
	}
	return info
}

// ruleErrorRe matches Suricata's rule load errors, e.g.
// `error parsing signature "alert ..." from file /x/suricata.rules at line 12`.
var ruleErrorRe = regexp.MustCompile(`error parsing signature "(.*)" from file (\S+) at line (\d+)`)

var sidRe = regexp.MustCompile(`\bsid\s*:\s*(\d+)`)

// ParseRuleErrors extracts rule load errors from Suricata output.
func ParseRuleErrors(out string) []RuleError {
	var errs []RuleError
	lines := strings.Split(out, "\n")
	for i, line := range lines {
		m := ruleErrorRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		e := RuleError{File: m[2]}
		e.Line, _ = strconv.Atoi(m[3])
		if s := sidRe.FindStringSubmatch(m[1]); s != nil {
			e.SID, _ = strconv.Atoi(s[1])
		}
		// The reason is usually logged on the preceding line.
		if i > 0 {
			e.Message = trimLogPrefix(lines[i-1])
		}
		errs = append(errs, e)
	}
	return errs
}

func trimLogPrefix(line string) string {
	// "14/10/2026 -- 10:00:00 - <Error> - [ERRCODE: ...] - msg" or
	// "E: detect-parse: msg"
	if i := strings.LastIndex(line, " - "); i >= 0 {
		return strings.TrimSpace(line[i+3:])
	}
	if _, rest, ok := strings.Cut(line, ": "); ok {
		return strings.TrimSpace(rest)
	}
	return strings.TrimSpace(line)
}
