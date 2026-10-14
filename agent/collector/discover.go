package collector

import (
	"path/filepath"
	"slices"

	yaml "go.yaml.in/yaml/v3"

	agentv1 "github.com/jc-lab/suricontroller/gen/suricontroller/agent/v1"
	"github.com/jc-lab/suricontroller/pkg/yamlmerge"
)

// Source is a log the collector reads. An empty Path means the engine's
// process output (used for suricata.log when no file output exists).
type Source struct {
	Type     agentv1.LogType
	Instance string
	Path     string
	EveTypes []string
}

// Instance is the effective configuration of a running Suricata instance.
type Instance struct {
	Name      string
	LogDir    string
	Effective *yaml.Node
}

func isTrue(s string) bool {
	switch s {
	case "yes", "true", "on", "1", "Yes", "True", "YES", "TRUE":
		return true
	}
	return false
}

// eveTypeNames maps eve output type names to their event_type values when
// they differ.
var eveTypeNames = map[string]string{"files": "fileinfo"}

// Discover finds the logs written by an instance from its effective
// configuration. Only file outputs can be collected.
func Discover(inst Instance) []Source {
	root := inst.Effective
	logDir := yamlmerge.GetString(root, "default-log-dir")
	if logDir == "" {
		logDir = inst.LogDir
	}
	abs := func(name, def string) string {
		if name == "" {
			name = def
		}
		if filepath.IsAbs(name) {
			return name
		}
		return filepath.Join(logDir, name)
	}
	var out []Source
	if outputs := yamlmerge.Get(root, "outputs"); outputs != nil && outputs.Kind == yaml.SequenceNode {
		for _, item := range outputs.Content {
			if item.Kind != yaml.MappingNode || len(item.Content) < 2 {
				continue
			}
			kind, cfg := item.Content[0].Value, item.Content[1]
			if !isTrue(yamlmerge.GetString(cfg, "enabled")) {
				continue
			}
			switch kind {
			case "eve-log":
				ft := yamlmerge.GetString(cfg, "filetype")
				if ft != "" && ft != "regular" && ft != "file" {
					continue
				}
				src := Source{Type: agentv1.LogType_LOG_TYPE_EVE, Instance: inst.Name, Path: abs(yamlmerge.GetString(cfg, "filename"), "eve.json")}
				if types := yamlmerge.Get(cfg, "types"); types != nil && types.Kind == yaml.SequenceNode {
					for _, t := range types.Content {
						name := t.Value
						if t.Kind == yaml.MappingNode && len(t.Content) >= 2 {
							name = t.Content[0].Value
							if en := yamlmerge.GetString(t.Content[1], "enabled"); en != "" && !isTrue(en) {
								continue
							}
						}
						if mapped, ok := eveTypeNames[name]; ok {
							name = mapped
						}
						if name != "" && !slices.Contains(src.EveTypes, name) {
							src.EveTypes = append(src.EveTypes, name)
						}
					}
				}
				out = append(out, src)
			case "fast":
				out = append(out, Source{Type: agentv1.LogType_LOG_TYPE_FAST, Instance: inst.Name, Path: abs(yamlmerge.GetString(cfg, "filename"), "fast.log")})
			case "stats":
				out = append(out, Source{Type: agentv1.LogType_LOG_TYPE_STATS, Instance: inst.Name, Path: abs(yamlmerge.GetString(cfg, "filename"), "stats.log")})
			}
		}
	}
	engineLog := false
	if lo := yamlmerge.Get(root, "logging", "outputs"); lo != nil && lo.Kind == yaml.SequenceNode {
		for _, item := range lo.Content {
			if item.Kind != yaml.MappingNode || len(item.Content) < 2 || item.Content[0].Value != "file" {
				continue
			}
			cfg := item.Content[1]
			if !isTrue(yamlmerge.GetString(cfg, "enabled")) {
				continue
			}
			out = append(out, Source{Type: agentv1.LogType_LOG_TYPE_SURICATA, Instance: inst.Name, Path: abs(yamlmerge.GetString(cfg, "filename"), "suricata.log")})
			engineLog = true
		}
	}
	if !engineLog {
		out = append(out, Source{Type: agentv1.LogType_LOG_TYPE_SURICATA, Instance: inst.Name})
	}
	return out
}
