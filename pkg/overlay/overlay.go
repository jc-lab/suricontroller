// Package overlay defines what the controller-managed Suricata configuration
// overlay (config.git suricata.yaml) may contain. The controller validates
// overlays on write and render; the agent enforces the same rules before
// applying a bundle, so a compromised controller cannot use the overlay to
// take over a node or to change settings owned by the node user.
package overlay

import (
	"fmt"
	"sort"
	"strings"

	yaml "go.yaml.in/yaml/v3"
)

// Forbidden lists top-level keys the overlay must not set, with the reason.
var Forbidden = map[string]string{
	// Owned by the agent runtime layer.
	"af-packet":             "capture is managed by the agent",
	"nfq":                   "capture is managed by the agent",
	"pcap":                  "capture is managed by the agent",
	"af-xdp":                "capture is managed by the agent",
	"dpdk":                  "capture is managed by the agent",
	"pfring":                "capture is managed by the agent",
	"netmap":                "capture is managed by the agent",
	"ipfw":                  "capture is managed by the agent",
	"napatech":              "capture is managed by the agent",
	"unix-command":          "managed by the agent",
	"pid-file":              "managed by the agent",
	"default-rule-path":     "managed by the agent",
	"rule-files":            "managed by the agent",
	"classification-file":   "managed by the agent",
	"reference-config-file": "managed by the agent",
	"threshold-file":        "managed by the agent",
	// Owned by the node user.
	"default-log-dir": "log locations are owned by the node user",
	"logging":         "log locations are owned by the node user",
	"outputs":         "log outputs are owned by the node user",
	// Security sensitive.
	"plugins":  "loading plugins is not allowed",
	"include":  "includes are not allowed",
	"security": "security settings are controlled locally on the node",
	"run-as":   "process identity is controlled locally on the node",
	"datasets": "dataset file settings are controlled locally on the node",
	"coredump": "controlled locally on the node",
}

// NormalizeKey returns a key the way Suricata's configuration loader sees
// it: underscores are treated as dashes.
func NormalizeKey(k string) string { return strings.ReplaceAll(k, "_", "-") }

// Check reports an error listing every forbidden key set by root, any key
// containing a dot (Suricata expands "a.b: x" into nested nodes, which would
// otherwise bypass the top-level check), and any YAML tag that could make
// Suricata read other files.
func Check(root *yaml.Node) error {
	if root == nil {
		return nil
	}
	var bad []string
	for i := 0; i+1 < len(root.Content); i += 2 {
		k := root.Content[i].Value
		if reason, ok := Forbidden[NormalizeKey(k)]; ok {
			bad = append(bad, fmt.Sprintf("%s (%s)", k, reason))
		}
	}
	seen := map[string]bool{}
	walk(root, func(n *yaml.Node) {
		if n.Tag == "!include" && !seen["!include"] {
			seen["!include"] = true
			bad = append(bad, "!include tag is not allowed")
		}
		if n.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(n.Content); i += 2 {
				if k := n.Content[i].Value; strings.Contains(k, ".") && !seen[k] {
					seen[k] = true
					bad = append(bad, fmt.Sprintf("%q (dotted keys are not allowed)", k))
				}
			}
		}
		if n.Kind == yaml.AliasNode || n.Anchor != "" {
			if !seen["&"] {
				seen["&"] = true
				bad = append(bad, "YAML anchors/aliases are not allowed")
			}
		}
	})
	if len(bad) == 0 {
		return nil
	}
	sort.Strings(bad)
	return fmt.Errorf("overlay sets forbidden keys: %s", strings.Join(bad, ", "))
}

func walk(n *yaml.Node, fn func(*yaml.Node)) {
	fn(n)
	for _, c := range n.Content {
		walk(c, fn)
	}
}
