// Package rules manages rule providers: each provider owns one top-level
// directory of the rules repository ("/{provider}/{rule files}"). Fetching
// providers (ET Open, URL) download rules periodically and commit them.
package rules

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/jc-lab/suricontroller/controller/store"
)

// Provider types.
const (
	TypeETOpen = "et-open"
	TypeLocal  = "local"
	TypeURL    = "url"
)

// DefaultSuricataVersion selects the ET Open ruleset build.
const DefaultSuricataVersion = "8.0.5"

// maxArchiveSize bounds downloads.
const maxArchiveSize = 256 << 20

var md5Re = regexp.MustCompile(`^[0-9a-f]{32}$`)

// ErrNotModified is returned by a Fetcher when upstream did not change.
var ErrNotModified = errors.New("rules: not modified")

// FetchResult holds the files of a provider directory.
type FetchResult struct {
	// Files keyed by path relative to the provider directory.
	Files map[string][]byte
	// Checksum of the upstream artifact, stored to detect changes.
	Checksum string
}

// Fetcher downloads the files of a provider.
type Fetcher interface {
	Fetch(ctx context.Context, p *store.Provider) (*FetchResult, error)
}

// TypeInfo describes a provider type.
type TypeInfo struct {
	Name            string
	Fetcher         Fetcher // nil for providers edited in place (local)
	DefaultInterval time.Duration
	DefaultOptions  map[string]string
}

// ETOpen fetches the Emerging Threats Open ruleset.
type ETOpen struct {
	Client *http.Client
}

// ETOpenURL returns the download URL for a Suricata version.
func ETOpenURL(version string) string {
	return fmt.Sprintf("https://rules.emergingthreats.net/open/suricata-%s/emerging.rules.tar.gz", version)
}

// Fetch implements Fetcher. It compares the published md5 with the stored
// checksum before downloading the archive.
func (f *ETOpen) Fetch(ctx context.Context, p *store.Provider) (*FetchResult, error) {
	url := p.Options["url"]
	if url == "" {
		v := p.Options["suricata_version"]
		if v == "" {
			v = DefaultSuricataVersion
		}
		url = ETOpenURL(v)
	}
	md5sum, err := getText(ctx, f.Client, url+".md5", 1024)
	if err != nil {
		return nil, fmt.Errorf("fetch md5: %w", err)
	}
	fields := strings.Fields(md5sum)
	if len(fields) == 0 || !md5Re.MatchString(strings.ToLower(fields[0])) {
		return nil, fmt.Errorf("invalid md5 file from %s.md5", url)
	}
	md5sum = strings.ToLower(fields[0])
	if md5sum == p.Checksum {
		return nil, ErrNotModified
	}
	data, err := get(ctx, f.Client, url, maxArchiveSize)
	if err != nil {
		return nil, err
	}
	sum := md5.Sum(data)
	if got := hex.EncodeToString(sum[:]); got != md5sum {
		return nil, fmt.Errorf("md5 mismatch: got %s, published %s", got, md5sum)
	}
	files, err := extractRules(data)
	if err != nil {
		return nil, err
	}
	return &FetchResult{Files: files, Checksum: md5sum}, nil
}

// URL fetches a .rules file or a .tar.gz/.tgz archive of rules.
type URL struct {
	Client *http.Client
}

// Fetch implements Fetcher.
func (f *URL) Fetch(ctx context.Context, p *store.Provider) (*FetchResult, error) {
	url := p.Options["url"]
	if url == "" {
		return nil, errors.New("option url is required")
	}
	data, err := get(ctx, f.Client, url, maxArchiveSize)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	checksum := hex.EncodeToString(sum[:])
	if checksum == p.Checksum {
		return nil, ErrNotModified
	}
	name := path.Base(strings.SplitN(url, "?", 2)[0])
	var files map[string][]byte
	switch {
	case strings.HasSuffix(name, ".tar.gz") || strings.HasSuffix(name, ".tgz"):
		if files, err = extractRules(data); err != nil {
			return nil, err
		}
	case strings.HasSuffix(name, ".rules"):
		files = map[string][]byte{name: data}
	default:
		return nil, fmt.Errorf("unsupported file type %q (want .rules, .tar.gz or .tgz)", name)
	}
	return &FetchResult{Files: files, Checksum: checksum}, nil
}

func get(ctx context.Context, c *http.Client, url string, limit int64) ([]byte, error) {
	if c == nil {
		c = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "suricontroller")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("GET %s: response larger than %d bytes", url, limit)
	}
	return data, nil
}

func getText(ctx context.Context, c *http.Client, url string, limit int64) (string, error) {
	b, err := get(ctx, c, url, limit)
	return string(b), err
}

// keepFile reports whether an archive member is kept in the provider dir.
func keepFile(name string) bool {
	for _, ext := range []string{".rules", ".config", ".txt"} {
		if strings.HasSuffix(name, ext) {
			return true
		}
	}
	return false
}

// extractRules extracts rule-related files from a tar.gz, flattening paths
// to their base names (as suricata-update does).
func extractRules(data []byte) (map[string][]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("gunzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	files := map[string][]byte{}
	var total int64
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("untar: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		name := path.Base(hdr.Name)
		if !keepFile(name) || strings.HasPrefix(name, ".") {
			continue
		}
		total += hdr.Size
		if total > 4*maxArchiveSize {
			return nil, errors.New("archive expands too much")
		}
		b, err := io.ReadAll(io.LimitReader(tr, hdr.Size))
		if err != nil {
			return nil, err
		}
		files[name] = b
	}
	if len(files) == 0 {
		return nil, errors.New("archive contains no rule files")
	}
	return files, nil
}
