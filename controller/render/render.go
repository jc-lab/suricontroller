// Package render builds node bundles from the rules and config repositories:
// it selects the rule files of the enabled providers, applies the layered
// disable/enable/drop/modify configuration with suricata-update semantics
// and packs the result together with the merged suricata.yaml overlay.
package render

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jc-lab/suricontroller/controller/configrepo"
	"github.com/jc-lab/suricontroller/controller/gitrepo"
	"github.com/jc-lab/suricontroller/pkg/bundle"
	"github.com/jc-lab/suricontroller/pkg/ruleset"
	"github.com/jc-lab/suricontroller/pkg/yamlmerge"
)

// Config configures a Renderer.
type Config struct {
	Rules  *gitrepo.Repo
	Config *gitrepo.Repo
	// Key signs bundle manifests (the controller host key).
	Key      ed25519.PrivateKey
	CacheDir string
	Logger   *slog.Logger
}

// Result describes a rendered bundle.
type Result struct {
	ID             string
	Size           int64
	RulesCommit    string
	ConfigCommit   string
	Manifest       *bundle.Manifest
	ControllerYAML []byte
	Warnings       []string
}

// Renderer renders and caches bundles.
type Renderer struct {
	cfg Config
	log *slog.Logger

	renderMu sync.Mutex // one render at a time bounds memory use

	mu    sync.Mutex
	index map[string]*Result // key -> result
	used  map[string]time.Time
}

// New creates a renderer.
func New(cfg Config) (*Renderer, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if err := os.MkdirAll(cfg.CacheDir, 0o750); err != nil {
		return nil, err
	}
	return &Renderer{cfg: cfg, log: cfg.Logger.With("component", "render"), index: map[string]*Result{}, used: map[string]time.Time{}}, nil
}

func cacheKey(rulesCommit, configCommit, nodeID string) string {
	return rulesCommit + "|" + configCommit + "|" + nodeID
}

// Render returns the bundle of nodeID for the given commits ("" means the
// repository is empty), rendering it if it is not cached.
func (r *Renderer) Render(ctx context.Context, rulesCommit, configCommit, nodeID string) (*Result, error) {
	key := cacheKey(rulesCommit, configCommit, nodeID)
	r.mu.Lock()
	if res, ok := r.index[key]; ok && r.exists(res.ID) {
		r.used[res.ID] = time.Now()
		r.mu.Unlock()
		return res, nil
	}
	r.mu.Unlock()

	r.renderMu.Lock()
	defer r.renderMu.Unlock()
	r.mu.Lock()
	if res, ok := r.index[key]; ok && r.exists(res.ID) {
		r.mu.Unlock()
		return res, nil
	}
	r.mu.Unlock()

	start := time.Now()
	res, archive, err := r.render(ctx, rulesCommit, configCommit, nodeID)
	if err != nil {
		return nil, err
	}
	if err := r.store(res.ID, archive); err != nil {
		return nil, err
	}
	r.mu.Lock()
	r.index[key] = res
	r.used[res.ID] = time.Now()
	r.mu.Unlock()
	r.log.Debug("rendered bundle", "node", nodeID, "bundle", res.ID, "size", res.Size, "rules", res.Manifest.RuleStats.Enabled, "took", time.Since(start))
	return res, nil
}

// Preview renders without caching the archive.
func (r *Renderer) Preview(ctx context.Context, rulesCommit, configCommit, nodeID string) (*Result, error) {
	r.renderMu.Lock()
	defer r.renderMu.Unlock()
	res, _, err := r.render(ctx, rulesCommit, configCommit, nodeID)
	return res, err
}

func (r *Renderer) render(ctx context.Context, rulesCommit, configCommit, nodeID string) (*Result, []byte, error) {
	layered, err := configrepo.Load(r.cfg.Config, configCommit, nodeID)
	if err != nil {
		return nil, nil, fmt.Errorf("config: %w", err)
	}
	files := map[string][]byte{}
	var warnings []string

	rules, deps, classification, reference, err := r.loadRules(ctx, rulesCommit, layered.Sources)
	if err != nil {
		return nil, nil, fmt.Errorf("rules: %w", err)
	}
	processed, stats, err := ruleset.Process(rules, ruleset.Config{
		Disable:         layered.Disable,
		Enable:          layered.Enable,
		Drop:            layered.Drop,
		Modify:          layered.Modify,
		ResolveFlowbits: true,
		DepFiles:        deps,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("process rules: %w", err)
	}
	lua := 0
	for _, rule := range processed {
		if rule.Enabled && rule.UsesLua() {
			lua++
		}
	}
	if lua > 0 {
		warnings = append(warnings, fmt.Sprintf("%d enabled rules use lua; nodes reject them unless lua is allowed locally", lua))
	}
	var buf bytes.Buffer
	if err := ruleset.Write(&buf, processed); err != nil {
		return nil, nil, err
	}
	files[bundle.PathRules] = buf.Bytes()
	for p, data := range ruleset.DatasetFiles(processed) {
		files[path.Join(path.Dir(bundle.PathRules), p)] = data
	}
	if len(classification) > 0 {
		files[bundle.PathClassification] = classification
	}
	if len(reference) > 0 {
		files[bundle.PathReference] = reference
	}
	if len(layered.Threshold) > 0 {
		files[bundle.PathThreshold] = layered.Threshold
	}
	yml, err := yamlmerge.Encode(layered.Overlay)
	if err != nil {
		return nil, nil, err
	}
	files[bundle.PathControllerYAML] = yml

	built, err := bundle.Build(bundle.Manifest{
		NodeID:       nodeID,
		RulesCommit:  rulesCommit,
		ConfigCommit: configCommit,
		RuleStats: bundle.RuleStats{
			Total: stats.Total, Enabled: stats.Enabled, Disabled: stats.Disabled,
			Dropped: stats.Dropped, Modified: stats.Modified, FlowbitsEnabled: stats.FlowbitsEnabled,
		},
	}, files, r.cfg.Key)
	if err != nil {
		return nil, nil, err
	}
	return &Result{
		ID: built.ID, Size: int64(len(built.Archive)), RulesCommit: rulesCommit, ConfigCommit: configCommit,
		Manifest: built.Manifest, ControllerYAML: yml, Warnings: warnings,
	}, built.Archive, nil
}

// loadRules parses the rule files selected by src at commit, the way
// suricata-update loads its sources. Files are named "{provider}/{file}".
func (r *Renderer) loadRules(ctx context.Context, commit string, src configrepo.Sources) (rules []*ruleset.Rule, deps map[string][]byte, classification, reference []byte, err error) {
	if commit == "" {
		return nil, nil, nil, nil, nil
	}
	top, err := r.cfg.Rules.ListTree(commit, "", false)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	want := map[string]bool{}
	for _, p := range src.Providers {
		want[p] = true
	}
	var providers []string
	for _, e := range top {
		if e.Dir && (len(want) == 0 || want[e.Path]) {
			providers = append(providers, e.Path)
		}
	}
	sort.Strings(providers)
	var sources []ruleset.SourceFile
	classSeen := map[string]bool{}
	refSeen := map[string]bool{}
	for _, p := range providers {
		if err := ctx.Err(); err != nil {
			return nil, nil, nil, nil, err
		}
		files, err := r.cfg.Rules.ReadDir(commit, p)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		names := make([]string, 0, len(files))
		for name := range files {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			full := p + "/" + name
			if excluded(full, src.Exclude) {
				continue
			}
			switch path.Base(name) {
			case "classification.config":
				classification = mergeConfigLines(classification, files[name], classSeen, "config classification:")
				continue
			case "reference.config":
				reference = mergeConfigLines(reference, files[name], refSeen, "config reference:")
				continue
			}
			sources = append(sources, ruleset.SourceFile{Name: full, Content: files[name]})
		}
	}
	rules, deps, err = ruleset.ParseFiles(sources, ruleset.LoadOptions{Ignore: ruleset.DefaultIgnore})
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return rules, deps, classification, reference, nil
}

func excluded(p string, globs []string) bool {
	for _, g := range globs {
		if ok, _ := path.Match(g, p); ok {
			return true
		}
	}
	return false
}

// mergeConfigLines appends "config <kind>: name,..." lines whose name was not
// seen yet (the first provider wins).
func mergeConfigLines(dst, src []byte, seen map[string]bool, prefix string) []byte {
	sc := bufio.NewScanner(bytes.NewReader(src))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		name, _, _ := strings.Cut(strings.TrimSpace(strings.TrimPrefix(line, prefix)), ",")
		name = strings.TrimSpace(name)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		dst = append(dst, line...)
		dst = append(dst, '\n')
	}
	return dst
}

// ValidateConf checks disable/enable/drop/modify lines.
func ValidateConf(file string, lines []string) error {
	cfg := ruleset.Config{}
	switch file {
	case configrepo.FileDisable:
		cfg.Disable = lines
	case configrepo.FileEnable:
		cfg.Enable = lines
	case configrepo.FileDrop:
		cfg.Drop = lines
	case configrepo.FileModify:
		cfg.Modify = lines
	default:
		return nil
	}
	return ruleset.ValidateConfig(cfg)
}

func (r *Renderer) path(id string) (string, error) {
	if len(id) != 64 {
		return "", errors.New("render: invalid bundle id")
	}
	if _, err := hex.DecodeString(id); err != nil {
		return "", errors.New("render: invalid bundle id")
	}
	return filepath.Join(r.cfg.CacheDir, id+".tar.zst"), nil
}

func (r *Renderer) exists(id string) bool {
	p, err := r.path(id)
	if err != nil {
		return false
	}
	_, err = os.Stat(p)
	return err == nil
}

func (r *Renderer) store(id string, archive []byte) error {
	p, err := r.path(id)
	if err != nil {
		return err
	}
	if _, err := os.Stat(p); err == nil {
		return nil
	}
	tmp := p + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return err
	}
	if _, err := f.Write(archive); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// Open opens a cached bundle archive.
func (r *Renderer) Open(id string) (io.ReadSeekCloser, int64, error) {
	p, err := r.path(id)
	if err != nil {
		return nil, 0, err
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, 0, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, err
	}
	return f, st.Size(), nil
}

// GC deletes cached archives that are not in keep and were not used in the
// last minAge.
func (r *Renderer) GC(keep map[string]bool, minAge time.Duration) int {
	entries, err := os.ReadDir(r.cfg.CacheDir)
	if err != nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, e := range entries {
		id, ok := strings.CutSuffix(e.Name(), ".tar.zst")
		if !ok || keep[id] {
			continue
		}
		if t, ok := r.used[id]; ok && time.Since(t) < minAge {
			continue
		}
		if fi, err := e.Info(); err == nil && time.Since(fi.ModTime()) < minAge {
			continue
		}
		if os.Remove(filepath.Join(r.cfg.CacheDir, e.Name())) == nil {
			n++
			delete(r.used, id)
			for k, res := range r.index {
				if res.ID == id {
					delete(r.index, k)
				}
			}
		}
	}
	return n
}
