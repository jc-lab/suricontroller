// Package configrepo reads the layered Suricata configuration from the
// config repository:
//
//	common/{file}            applies to every node
//	nodes/{node-id}/{file}   node-specific override
//
// Known files are suricata.yaml (overlay), sources.yaml, disable.conf,
// enable.conf, drop.conf, modify.conf and threshold.config.
package configrepo

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	yaml "go.yaml.in/yaml/v3"

	"github.com/jc-lab/suricontroller/controller/gitrepo"
	"github.com/jc-lab/suricontroller/pkg/nodeid"
	"github.com/jc-lab/suricontroller/pkg/overlay"
	"github.com/jc-lab/suricontroller/pkg/yamlmerge"
)

// Known file names.
const (
	FileSuricataYAML = "suricata.yaml"
	FileSources      = "sources.yaml"
	FileDisable      = "disable.conf"
	FileEnable       = "enable.conf"
	FileDrop         = "drop.conf"
	FileModify       = "modify.conf"
	FileThreshold    = "threshold.config"
)

// ReplaceMarker as the first line of a node file makes it replace the
// common file instead of being appended/merged.
const ReplaceMarker = "# suricontroller: replace"

// CommonDir holds the configuration shared by all nodes.
const CommonDir = "common"

// NodesDir holds per-node directories.
const NodesDir = "nodes"

// KnownFiles lists the files allowed in common/ and nodes/{id}/.
var KnownFiles = []string{FileSuricataYAML, FileSources, FileDisable, FileEnable, FileDrop, FileModify, FileThreshold}

// ErrInvalidPath is returned for paths outside the allowed layout.
var ErrInvalidPath = errors.New("configrepo: invalid path")

// Sources selects which rule files of the rules repository are used.
type Sources struct {
	// Providers lists provider directories to use; empty means all.
	Providers []string `yaml:"providers"`
	// Exclude lists path globs (relative to the rules repository root, e.g.
	// "et-open/emerging-games.rules") to skip.
	Exclude []string `yaml:"exclude"`
}

// Layered is the effective configuration of one node.
type Layered struct {
	Overlay   *yaml.Node
	Sources   Sources
	Disable   []string
	Enable    []string
	Drop      []string
	Modify    []string
	Threshold []byte
}

// ConfValidator validates the lines of a disable/enable/drop/modify file.
// It is set by the renderer, which knows the matcher syntax.
type ConfValidator func(file string, lines []string) error

// ValidatePath checks that p is common/{known} or nodes/{node-id}/{known}.
func ValidatePath(p string) error {
	clean, err := gitrepo.CleanPath(p)
	if err != nil {
		return fmt.Errorf("%w: %q", ErrInvalidPath, p)
	}
	parts := strings.Split(clean, "/")
	var file string
	switch {
	case len(parts) == 2 && parts[0] == CommonDir:
		file = parts[1]
	case len(parts) == 3 && parts[0] == NodesDir:
		if err := nodeid.Validate(parts[1]); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidPath, err)
		}
		file = parts[2]
	default:
		return fmt.Errorf("%w: %q (use common/<file> or nodes/<node-id>/<file>)", ErrInvalidPath, p)
	}
	for _, k := range KnownFiles {
		if file == k {
			return nil
		}
	}
	return fmt.Errorf("%w: unknown file %q (allowed: %s)", ErrInvalidPath, file, strings.Join(KnownFiles, ", "))
}

// ValidateFile checks the content of a file before it is committed.
func ValidateFile(p string, content []byte, conf ConfValidator) error {
	if err := ValidatePath(p); err != nil {
		return err
	}
	switch path.Base(p) {
	case FileSuricataYAML:
		root, err := yamlmerge.Parse(content)
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		if err := overlay.Check(root); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
	case FileSources:
		if _, err := parseSources(content); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
	case FileDisable, FileEnable, FileDrop, FileModify:
		if conf != nil {
			if err := conf(path.Base(p), splitLines(content)); err != nil {
				return fmt.Errorf("%s: %w", p, err)
			}
		}
	}
	return nil
}

func parseSources(b []byte) (Sources, error) {
	var s Sources
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&s); err != nil && !errors.Is(err, io.EOF) {
		return s, err
	}
	for _, g := range s.Exclude {
		if _, err := path.Match(g, ""); err != nil {
			return s, fmt.Errorf("invalid exclude glob %q", g)
		}
	}
	return s, nil
}

func splitLines(b []byte) []string {
	s := strings.ReplaceAll(string(b), "\r\n", "\n")
	if s == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(s, "\n"), "\n")
}

func isReplace(b []byte) bool {
	first, _, _ := strings.Cut(string(b), "\n")
	return strings.TrimSpace(first) == ReplaceMarker
}

// Load reads the effective configuration of nodeID at commit. An empty
// commit (empty repository) yields an empty configuration.
func Load(repo *gitrepo.Repo, commit, nodeID string) (*Layered, error) {
	l := &Layered{Overlay: yamlmerge.NewMap()}
	if commit == "" {
		return l, nil
	}
	common, err := repo.ReadDir(commit, CommonDir)
	if err != nil {
		return nil, err
	}
	node, err := repo.ReadDir(commit, NodesDir+"/"+nodeID)
	if err != nil {
		return nil, err
	}
	layers := []map[string][]byte{common, node}

	for i, files := range layers {
		if b, ok := files[FileSuricataYAML]; ok {
			root, err := yamlmerge.Parse(b)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", layerPath(i, nodeID, FileSuricataYAML), err)
			}
			if err := overlay.Check(root); err != nil {
				return nil, fmt.Errorf("%s: %w", layerPath(i, nodeID, FileSuricataYAML), err)
			}
			if i > 0 && isReplace(b) {
				l.Overlay = root
			} else {
				yamlmerge.Merge(l.Overlay, root)
			}
		}
		if b, ok := files[FileSources]; ok {
			s, err := parseSources(b)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", layerPath(i, nodeID, FileSources), err)
			}
			l.Sources = s
		}
		for _, f := range []struct {
			name string
			dst  *[]string
		}{{FileDisable, &l.Disable}, {FileEnable, &l.Enable}, {FileDrop, &l.Drop}, {FileModify, &l.Modify}} {
			b, ok := files[f.name]
			if !ok {
				continue
			}
			if i > 0 && isReplace(b) {
				*f.dst = nil
			}
			*f.dst = append(*f.dst, splitLines(b)...)
		}
		if b, ok := files[FileThreshold]; ok {
			if i > 0 && isReplace(b) {
				l.Threshold = nil
			}
			if len(l.Threshold) > 0 && !bytes.HasSuffix(l.Threshold, []byte("\n")) {
				l.Threshold = append(l.Threshold, '\n')
			}
			l.Threshold = append(l.Threshold, b...)
		}
	}
	return l, nil
}

func layerPath(i int, nodeID, file string) string {
	if i == 0 {
		return CommonDir + "/" + file
	}
	return NodesDir + "/" + nodeID + "/" + file
}
