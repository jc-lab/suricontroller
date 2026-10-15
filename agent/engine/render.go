package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"

	yaml "go.yaml.in/yaml/v3"

	"github.com/jc-lab/suricontroller/pkg/bundle"
	"github.com/jc-lab/suricontroller/pkg/overlay"
	"github.com/jc-lab/suricontroller/pkg/yamlmerge"
)

// RenderInput holds everything needed to build an instance configuration.
type RenderInput struct {
	Instance string
	Capture  CaptureMode
	// Interfaces captured with af-packet (IDS instance).
	Interfaces []string
	// BaseConfig is the user's suricata.yaml path (relative includes are
	// resolved against its directory).
	BaseConfig string
	Base       *yaml.Node
	// InstanceConfig is the node user's settings for this instance only
	// (tap), merged over Base; nil when there are none.
	InstanceConfig *yaml.Node
	// Managed is the controller overlay (nil when no bundle is applied).
	Managed *yaml.Node
	// RulesDir holds suricata.rules and optional classification/reference/
	// threshold files ("" when no bundle is applied).
	RulesDir      string
	LocalRulesDir string
	LogDir        string
	SocketPath    string
	PidFile       string
	AllowLua      bool
	FailOpen      bool
	// Tap holds the agent-owned suritap settings (CapturePlugin).
	Tap *TapSettings
}

// TapSettings are the suritap plugin settings the agent owns.
type TapSettings struct {
	Plugin     string
	SocketDir  string
	SocketMode string
	Threads    string
	PolicyFile string
}

// Rendered is an effective instance configuration.
type Rendered struct {
	YAML []byte
	// Shadowed lists user settings overridden by the controller overlay.
	Shadowed []string
}

// Render builds the effective configuration of an instance:
// user base < controller overlay < agent runtime layer.
func Render(in RenderInput) (*Rendered, error) {
	if in.Managed != nil {
		if err := overlay.Check(in.Managed); err != nil {
			return nil, err
		}
	}
	eff := yamlmerge.Clone(in.Base)
	if eff == nil {
		eff = yamlmerge.NewMap()
	}
	absolutizeIncludes(eff, filepath.Dir(in.BaseConfig))
	user := in.Base
	if in.InstanceConfig != nil {
		yamlmerge.Merge(eff, in.InstanceConfig)
		user = yamlmerge.Clone(eff)
	}
	var shadowed []string
	if in.Managed != nil {
		shadowed = yamlmerge.Shadowed(user, in.Managed)
		yamlmerge.Merge(eff, in.Managed)
	}
	rt, err := runtimeLayer(in)
	if err != nil {
		return nil, err
	}
	yamlmerge.Merge(eff, rt)
	// Agent-owned settings go last so nothing earlier in the document (for
	// example a dotted key in the user's file) can override them.
	yamlmerge.MoveToEnd(eff, yamlmerge.TopKeys(rt)...)
	out, err := yamlmerge.Encode(eff)
	if err != nil {
		return nil, err
	}
	return &Rendered{YAML: out, Shadowed: shadowed}, nil
}

func seq(items ...*yaml.Node) *yaml.Node {
	return &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: items}
}

func runtimeLayer(in RenderInput) (*yaml.Node, error) {
	rt := yamlmerge.NewMap()
	set := func(v string, path ...string) { yamlmerge.Set(rt, yamlmerge.Scalar(v), path...) }

	set(in.LogDir, "default-log-dir")
	set(in.PidFile, "pid-file")
	set("yes", "unix-command", "enabled")
	set(in.SocketPath, "unix-command", "filename")

	var ruleFiles []*yaml.Node
	if in.RulesDir != "" {
		set(in.RulesDir, "default-rule-path")
		ruleFiles = append(ruleFiles, yamlmerge.Scalar(filepath.Join(in.RulesDir, "suricata.rules")))
		for file, key := range map[string]string{
			bundle.PathClassification: "classification-file",
			bundle.PathReference:      "reference-config-file",
			bundle.PathThreshold:      "threshold-file",
		} {
			p := filepath.Join(in.RulesDir, filepath.Base(file))
			if _, err := os.Stat(p); err == nil {
				set(p, key)
			}
		}
	}
	if in.LocalRulesDir != "" {
		local, _ := filepath.Glob(filepath.Join(in.LocalRulesDir, "*.rules"))
		sort.Strings(local)
		for _, p := range local {
			ruleFiles = append(ruleFiles, yamlmerge.Scalar(p))
		}
	}
	if in.RulesDir != "" || len(ruleFiles) > 0 {
		yamlmerge.Set(rt, seq(ruleFiles...), "rule-files")
	}
	if !in.AllowLua {
		set("no", "security", "lua", "allow-rules")
	}

	switch in.Capture {
	case CaptureAFPacket:
		yamlmerge.Set(rt, afPacketList(in.Base, in.Interfaces), "af-packet")
	case CapturePlugin:
		if in.Tap == nil {
			return nil, fmt.Errorf("engine: plugin capture without tap settings")
		}
		yamlmerge.Set(rt, seq(yamlmerge.Scalar(in.Tap.Plugin)), "plugins")
		set(in.Tap.SocketDir, "suritap", "socket-dir")
		set(in.Tap.PolicyFile, "suritap", "policy-file")
		set(in.Tap.Threads, "suritap", "threads")
		// The endpoint policy decides what blocks; the engine runs in IPS
		// mode so that it reports drops.
		set("yes", "suritap", "ips")
		if in.Tap.SocketMode != "" {
			set(in.Tap.SocketMode, "suritap", "socket-mode")
		}
	case CaptureNFQ:
		nfq := yamlmerge.Clone(yamlmerge.Get(in.Base, "nfq"))
		if nfq == nil || nfq.Kind != yaml.MappingNode {
			nfq = yamlmerge.NewMap()
		}
		failOpen := "no"
		if in.FailOpen {
			failOpen = "yes"
		}
		yamlmerge.Set(nfq, yamlmerge.Scalar(failOpen), "fail-open")
		if yamlmerge.GetString(nfq, "mode") == "" {
			yamlmerge.Set(nfq, yamlmerge.Scalar("accept"), "mode")
		}
		yamlmerge.Set(rt, nfq, "nfq")
	default:
		return nil, fmt.Errorf("engine: unknown capture mode %q", in.Capture)
	}
	return rt, nil
}

// afPacketList builds the af-packet section for the managed interfaces,
// reusing the user's per-interface or "default" entries for tuning.
func afPacketList(base *yaml.Node, ifaces []string) *yaml.Node {
	user := yamlmerge.Get(base, "af-packet")
	find := func(name string) *yaml.Node {
		if user == nil || user.Kind != yaml.SequenceNode {
			return nil
		}
		for _, e := range user.Content {
			if e.Kind == yaml.MappingNode && yamlmerge.GetString(e, "interface") == name {
				return e
			}
		}
		return nil
	}
	out := seq()
	for i, ifc := range ifaces {
		e := yamlmerge.Clone(find(ifc))
		if e == nil {
			e = yamlmerge.Clone(find("default"))
		}
		if e == nil {
			e = yamlmerge.NewMap()
			yamlmerge.Set(e, yamlmerge.Scalar("cluster_flow"), "cluster-type")
			yamlmerge.Set(e, yamlmerge.Scalar("yes"), "defrag")
		}
		yamlmerge.Set(e, yamlmerge.Scalar(ifc), "interface")
		yamlmerge.Set(e, yamlmerge.Scalar(strconv.Itoa(99-i)), "cluster-id")
		// IDS only: never bridge interfaces.
		yamlmerge.Delete(e, "copy-mode")
		yamlmerge.Delete(e, "copy-iface")
		out.Content = append(out.Content, e)
	}
	if d := find("default"); d != nil {
		out.Content = append(out.Content, yamlmerge.Clone(d))
	}
	return out
}

// absolutizeIncludes rewrites relative include paths (top-level "include"
// and !include tags) against dir, because the effective configuration is
// written elsewhere.
func absolutizeIncludes(root *yaml.Node, dir string) {
	abs := func(n *yaml.Node) {
		if n.Kind == yaml.ScalarNode && n.Value != "" && !filepath.IsAbs(n.Value) {
			n.Value = filepath.Join(dir, n.Value)
		}
	}
	if inc := yamlmerge.Get(root, "include"); inc != nil {
		switch inc.Kind {
		case yaml.ScalarNode:
			abs(inc)
		case yaml.SequenceNode:
			for _, c := range inc.Content {
				abs(c)
			}
		}
	}
	var walk func(n *yaml.Node)
	walk = func(n *yaml.Node) {
		if n.Tag == "!include" {
			abs(n)
		}
		for _, c := range n.Content {
			walk(c)
		}
	}
	walk(root)
}
