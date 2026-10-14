// Package bundle defines the archive the controller renders for a node:
// a zstd-compressed tar holding a manifest, its signature and the rendered
// rules/config files.
//
// The bundle id is the sha256 of manifest.json, and the manifest lists the
// sha256 of every file, so the id addresses the content independently of
// the archive encoding. The manifest is signed with the controller host key.
package bundle

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"github.com/klauspost/compress/zstd"
)

// Well-known paths inside a bundle.
const (
	FileManifest  = "manifest.json"
	FileSignature = "manifest.sig"

	PathRules          = "rules/suricata.rules"
	PathClassification = "rules/classification.config"
	PathReference      = "rules/reference.config"
	PathThreshold      = "rules/threshold.config"
	PathControllerYAML = "config/controller.yaml"
)

// FormatVersion is the manifest format version.
const FormatVersion = 1

// FileEntry describes one file of the bundle.
type FileEntry struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// RuleStats summarizes rule processing.
type RuleStats struct {
	Total           int `json:"total"`
	Enabled         int `json:"enabled"`
	Disabled        int `json:"disabled"`
	Dropped         int `json:"dropped"`
	Modified        int `json:"modified"`
	FlowbitsEnabled int `json:"flowbits_enabled"`
}

// Manifest describes a bundle.
type Manifest struct {
	Version      int         `json:"version"`
	NodeID       string      `json:"node_id"`
	RulesCommit  string      `json:"rules_commit"`
	ConfigCommit string      `json:"config_commit"`
	RuleStats    RuleStats   `json:"rule_stats"`
	Files        []FileEntry `json:"files"`
}

// Built is the result of Build.
type Built struct {
	ID       string
	Manifest *Manifest
	Archive  []byte
}

// Build creates a bundle from files (path -> content). The manifest's Files
// list is filled in by Build.
func Build(m Manifest, files map[string][]byte, key ed25519.PrivateKey) (*Built, error) {
	m.Version = FormatVersion
	m.Files = nil
	paths := make([]string, 0, len(files))
	for p := range files {
		if err := checkPath(p); err != nil {
			return nil, err
		}
		if p == FileManifest || p == FileSignature {
			return nil, fmt.Errorf("bundle: reserved path %q", p)
		}
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		sum := sha256.Sum256(files[p])
		m.Files = append(m.Files, FileEntry{Path: p, Size: int64(len(files[p])), SHA256: hex.EncodeToString(sum[:])})
	}
	manifest, err := json.MarshalIndent(&m, "", "  ")
	if err != nil {
		return nil, err
	}
	id := sha256.Sum256(manifest)
	sig := ed25519.Sign(key, manifest)

	var buf bytes.Buffer
	zw, err := zstd.NewWriter(&buf, zstd.WithEncoderLevel(zstd.SpeedDefault), zstd.WithEncoderConcurrency(1))
	if err != nil {
		return nil, err
	}
	tw := tar.NewWriter(zw)
	write := func(name string, data []byte) error {
		hdr := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(data)), ModTime: time.Unix(0, 0), Typeflag: tar.TypeReg, Format: tar.FormatPAX}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		_, err := tw.Write(data)
		return err
	}
	if err := write(FileManifest, manifest); err != nil {
		return nil, err
	}
	if err := write(FileSignature, sig); err != nil {
		return nil, err
	}
	for _, p := range paths {
		if err := write(p, files[p]); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	mc := m
	return &Built{ID: hex.EncodeToString(id[:]), Manifest: &mc, Archive: buf.Bytes()}, nil
}

// datasetRe matches dataset files as written by suricata-update.
var datasetRe = regexp.MustCompile(`^rules/datasets/[0-9a-f]{32}$`)

// checkPath allows only the files a bundle is supposed to contain, so a
// bundle cannot drop arbitrary files (e.g. a plugin) onto the node.
func checkPath(p string) error {
	switch p {
	case PathRules, PathClassification, PathReference, PathThreshold, PathControllerYAML:
		return nil
	}
	if datasetRe.MatchString(p) {
		return nil
	}
	return fmt.Errorf("bundle: path %q is not allowed", p)
}

// Limits bound what Read accepts.
type Limits struct {
	MaxFiles      int
	MaxTotalBytes int64
}

// DefaultLimits are generous enough for full ET Pro rulesets with datasets.
var DefaultLimits = Limits{MaxFiles: 4096, MaxTotalBytes: 512 << 20}

// Bundle is a verified bundle.
type Bundle struct {
	ID       string
	Manifest *Manifest
	Files    map[string][]byte
}

// Read decodes and verifies an archive: the manifest must hash to wantID
// (if non-empty), be signed by key, and every file must match the manifest.
func Read(r io.Reader, wantID string, key ed25519.PublicKey, lim Limits) (*Bundle, error) {
	if lim.MaxFiles == 0 {
		lim = DefaultLimits
	}
	zr, err := zstd.NewReader(r, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(uint64(lim.MaxTotalBytes)+(16<<20)))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	// Backstop on the decompressed stream (file data plus tar headers).
	tr := tar.NewReader(io.LimitReader(zr, lim.MaxTotalBytes+int64(lim.MaxFiles+2)*4096+(1<<20)))
	var (
		manifestRaw, sig []byte
		files            = map[string][]byte{}
		total            int64
		entries          int
	)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("bundle: read archive: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("bundle: unexpected entry type for %q", hdr.Name)
		}
		if entries++; entries > lim.MaxFiles+2 {
			return nil, errors.New("bundle: too many files")
		}
		if hdr.Size < 0 || hdr.Size > lim.MaxTotalBytes-total {
			return nil, errors.New("bundle: archive too large")
		}
		total += hdr.Size
		if hdr.Name != FileManifest && hdr.Name != FileSignature {
			if err := checkPath(hdr.Name); err != nil {
				return nil, err
			}
		}
		data, err := io.ReadAll(io.LimitReader(tr, hdr.Size))
		if err != nil {
			return nil, err
		}
		switch hdr.Name {
		case FileManifest:
			if manifestRaw != nil {
				return nil, errors.New("bundle: duplicate manifest")
			}
			manifestRaw = data
		case FileSignature:
			if sig != nil {
				return nil, errors.New("bundle: duplicate signature")
			}
			sig = data
		default:
			if _, dup := files[hdr.Name]; dup {
				return nil, fmt.Errorf("bundle: duplicate entry %q", hdr.Name)
			}
			files[hdr.Name] = data
		}
	}
	if manifestRaw == nil || sig == nil {
		return nil, errors.New("bundle: missing manifest or signature")
	}
	sum := sha256.Sum256(manifestRaw)
	id := hex.EncodeToString(sum[:])
	if wantID != "" && id != wantID {
		return nil, fmt.Errorf("bundle: id mismatch: got %s, want %s", id, wantID)
	}
	if !ed25519.Verify(key, manifestRaw, sig) {
		return nil, errors.New("bundle: invalid manifest signature")
	}
	var m Manifest
	if err := json.Unmarshal(manifestRaw, &m); err != nil {
		return nil, fmt.Errorf("bundle: decode manifest: %w", err)
	}
	if m.Version != FormatVersion {
		return nil, fmt.Errorf("bundle: unsupported format version %d", m.Version)
	}
	if len(m.Files) != len(files) {
		return nil, errors.New("bundle: file list does not match manifest")
	}
	listed := map[string]bool{}
	for _, f := range m.Files {
		if listed[f.Path] {
			return nil, fmt.Errorf("bundle: manifest lists %q twice", f.Path)
		}
		listed[f.Path] = true
		data, ok := files[f.Path]
		if !ok {
			return nil, fmt.Errorf("bundle: missing file %q", f.Path)
		}
		s := sha256.Sum256(data)
		if hex.EncodeToString(s[:]) != f.SHA256 || int64(len(data)) != f.Size {
			return nil, fmt.Errorf("bundle: checksum mismatch for %q", f.Path)
		}
	}
	return &Bundle{ID: id, Manifest: &m, Files: files}, nil
}

// WriteTo writes the bundle files (and manifest.json) under dir.
func (b *Bundle) WriteTo(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	manifest, err := json.MarshalIndent(b.Manifest, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, FileManifest), manifest, 0o644); err != nil {
		return err
	}
	for p, data := range b.Files {
		if err := checkPath(p); err != nil {
			return err
		}
		dst := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(dst, data, 0o644); err != nil {
			return err
		}
	}
	return nil
}
