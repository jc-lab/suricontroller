package logs

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/klauspost/compress/zstd"

	agentv1 "github.com/jc-lab/suricontroller/gen/suricontroller/agent/v1"
	"github.com/jc-lab/suricontroller/pkg/nodeid"
)

// TypeName returns the short name used in file names ("eve", "suricata"...).
func TypeName(t agentv1.LogType) string {
	switch t {
	case agentv1.LogType_LOG_TYPE_EVE:
		return "eve"
	case agentv1.LogType_LOG_TYPE_SURICATA:
		return "suricata"
	case agentv1.LogType_LOG_TYPE_FAST:
		return "fast"
	case agentv1.LogType_LOG_TYPE_STATS:
		return "stats"
	case agentv1.LogType_LOG_TYPE_AGENT:
		return "agent"
	}
	return ""
}

// ParseTypeName is the inverse of TypeName.
func ParseTypeName(s string) agentv1.LogType {
	for _, t := range []agentv1.LogType{agentv1.LogType_LOG_TYPE_EVE, agentv1.LogType_LOG_TYPE_SURICATA,
		agentv1.LogType_LOG_TYPE_FAST, agentv1.LogType_LOG_TYPE_STATS, agentv1.LogType_LOG_TYPE_AGENT} {
		if TypeName(t) == s {
			return t
		}
	}
	return agentv1.LogType_LOG_TYPE_UNSPECIFIED
}

// Retention controls segment rotation and deletion.
type Retention struct {
	// Daily rotates segments per day instead of per hour.
	Daily           bool
	MaxSegmentBytes int64
	MaxAge          time.Duration
	MaxBytesPerNode int64
	MaxTotalBytes   int64
	Compress        bool
}

// DefaultRetention keeps hourly zstd-compressed segments for 7 days and at
// most 1 GiB per node.
var DefaultRetention = Retention{MaxSegmentBytes: 64 << 20, MaxAge: 7 * 24 * time.Hour, MaxBytesPerNode: 1 << 30, Compress: true}

// FileInfo describes a stored log segment.
type FileInfo struct {
	NodeID     string
	Type       agentv1.LogType
	Path       string // relative to the node directory: "{type}/{file}"
	Size       int64
	ModTime    time.Time
	Compressed bool
	Open       bool
}

// FileSink stores logs as {dir}/{node}/{type}/{type}-{period}[.n].log
// segments, compressing closed segments with zstd.
type FileSink struct {
	dir string
	log *slog.Logger
	now func() time.Time

	mu        sync.Mutex
	retention Retention
	open      map[string]*segment // key: node/type
	compress  sync.WaitGroup
}

type segment struct {
	f      *os.File
	w      *bufio.Writer
	path   string
	period string
	size   int64
}

// NewFileSink creates a sink rooted at dir.
func NewFileSink(dir string, r Retention, logger *slog.Logger) (*FileSink, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}
	s := &FileSink{dir: dir, log: logger.With("component", "logsink"), now: time.Now, retention: r, open: map[string]*segment{}}
	s.compressLeftovers()
	return s, nil
}

// SetRetention changes the retention policy.
func (s *FileSink) SetRetention(r Retention) {
	s.mu.Lock()
	s.retention = r
	s.mu.Unlock()
}

func (s *FileSink) period(t time.Time, daily bool) string {
	t = t.UTC()
	if daily {
		return t.Format("20060102")
	}
	return t.Format("20060102T15")
}

// Write appends records (one per line) to the node's current segment.
func (s *FileSink) Write(_ context.Context, nodeID string, t agentv1.LogType, records [][]byte) error {
	if err := nodeid.Validate(nodeID); err != nil {
		return err
	}
	name := TypeName(t)
	if name == "" {
		return fmt.Errorf("logsink: unknown log type %v", t)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := nodeID + "/" + name
	seg := s.open[key]
	period := s.period(s.now(), s.retention.Daily)
	if seg != nil && (seg.period != period || (s.retention.MaxSegmentBytes > 0 && seg.size >= s.retention.MaxSegmentBytes)) {
		s.closeSegment(key, seg)
		seg = nil
	}
	if seg == nil {
		var err error
		if seg, err = s.openSegment(nodeID, name, period); err != nil {
			return err
		}
		s.open[key] = seg
	}
	err := func() error {
		for _, r := range records {
			n, err := seg.w.Write(r)
			seg.size += int64(n)
			if err != nil {
				return err
			}
			if len(r) == 0 || r[len(r)-1] != '\n' {
				if err := seg.w.WriteByte('\n'); err != nil {
					return err
				}
				seg.size++
			}
		}
		return seg.w.Flush()
	}()
	if err != nil {
		// bufio errors are sticky: drop the segment so the next write
		// reopens the file (e.g. after the disk was freed).
		_ = seg.f.Close()
		delete(s.open, key)
	}
	return err
}

func (s *FileSink) openSegment(nodeID, name, period string) (*segment, error) {
	dir := filepath.Join(s.dir, nodeID, name)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	// Find the first free part number for this period.
	for part := 0; ; part++ {
		base := name + "-" + period
		if part > 0 {
			base += fmt.Sprintf(".%d", part)
		}
		p := filepath.Join(dir, base+".log")
		if _, err := os.Stat(p + ".zst"); err == nil {
			continue
		}
		fi, err := os.Stat(p)
		if err == nil && s.retention.MaxSegmentBytes > 0 && fi.Size() >= s.retention.MaxSegmentBytes {
			continue
		}
		f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
		if err != nil {
			return nil, err
		}
		var size int64
		if fi != nil {
			size = fi.Size()
		}
		return &segment{f: f, w: bufio.NewWriterSize(f, 64<<10), path: p, period: period, size: size}, nil
	}
}

func (s *FileSink) closeSegment(key string, seg *segment) {
	_ = seg.w.Flush()
	_ = seg.f.Close()
	delete(s.open, key)
	if s.retention.Compress {
		s.compress.Add(1)
		go func() {
			defer s.compress.Done()
			compressSem <- struct{}{}
			defer func() { <-compressSem }()
			if err := compressFile(seg.path); err != nil {
				s.log.Warn("compress segment", "path", seg.path, "err", err)
			}
		}()
	}
}

// compressSem bounds concurrent segment compressions (memory).
var compressSem = make(chan struct{}, 2)

// RotateIdle closes segments whose period ended.
func (s *FileSink) RotateIdle() {
	s.mu.Lock()
	defer s.mu.Unlock()
	period := s.period(s.now(), s.retention.Daily)
	for key, seg := range s.open {
		if seg.period != period {
			s.closeSegment(key, seg)
		}
	}
}

func compressFile(path string) error {
	in, err := os.Open(path)
	if err != nil {
		return err
	}
	defer in.Close()
	fi, err := in.Stat()
	if err != nil {
		return err
	}
	tmp := path + ".zst.tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return err
	}
	zw, err := zstd.NewWriter(out, zstd.WithEncoderConcurrency(1))
	if err != nil {
		out.Close()
		return err
	}
	if _, err := io.Copy(zw, in); err != nil {
		zw.Close()
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := zw.Close(); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	// Keep the segment's mtime: retention by age relies on it.
	_ = os.Chtimes(tmp, fi.ModTime(), fi.ModTime())
	if err := os.Rename(tmp, path+".zst"); err != nil {
		return err
	}
	return os.Remove(path)
}

// compressLeftovers compresses closed segments left uncompressed by a
// previous run (all .log files are closed at startup).
func (s *FileSink) compressLeftovers() {
	if !s.retention.Compress {
		return
	}
	files, err := s.List("", agentv1.LogType_LOG_TYPE_UNSPECIFIED)
	if err != nil {
		return
	}
	now := s.period(s.now(), s.retention.Daily)
	for _, f := range files {
		if f.Compressed || strings.Contains(f.Path, "-"+now) {
			continue
		}
		p := filepath.Join(s.dir, f.NodeID, filepath.FromSlash(f.Path))
		if err := compressFile(p); err != nil {
			s.log.Warn("compress leftover segment", "path", p, "err", err)
		}
	}
}

// List returns stored segments, optionally filtered by node and type,
// sorted by node, type and name.
func (s *FileSink) List(nodeID string, t agentv1.LogType) ([]FileInfo, error) {
	s.mu.Lock()
	openPaths := map[string]bool{}
	for _, seg := range s.open {
		openPaths[seg.path] = true
	}
	s.mu.Unlock()
	var out []FileInfo
	nodes := []string{nodeID}
	if nodeID == "" {
		entries, err := os.ReadDir(s.dir)
		if err != nil {
			return nil, err
		}
		nodes = nodes[:0]
		for _, e := range entries {
			if e.IsDir() && nodeid.Validate(e.Name()) == nil {
				nodes = append(nodes, e.Name())
			}
		}
	} else if err := nodeid.Validate(nodeID); err != nil {
		return nil, err
	}
	for _, n := range nodes {
		types, err := os.ReadDir(filepath.Join(s.dir, n))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, td := range types {
			lt := ParseTypeName(td.Name())
			if !td.IsDir() || lt == agentv1.LogType_LOG_TYPE_UNSPECIFIED {
				continue
			}
			if t != agentv1.LogType_LOG_TYPE_UNSPECIFIED && t != lt {
				continue
			}
			files, err := os.ReadDir(filepath.Join(s.dir, n, td.Name()))
			if err != nil {
				return nil, err
			}
			for _, f := range files {
				name := f.Name()
				if f.IsDir() || (!strings.HasSuffix(name, ".log") && !strings.HasSuffix(name, ".log.zst")) {
					continue
				}
				fi, err := f.Info()
				if err != nil {
					continue
				}
				full := filepath.Join(s.dir, n, td.Name(), name)
				out = append(out, FileInfo{
					NodeID: n, Type: lt, Path: td.Name() + "/" + name, Size: fi.Size(), ModTime: fi.ModTime(),
					Compressed: strings.HasSuffix(name, ".zst"), Open: openPaths[full],
				})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].NodeID != out[j].NodeID {
			return out[i].NodeID < out[j].NodeID
		}
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		pi, ni := segmentOrder(out[i].Path)
		pj, nj := segmentOrder(out[j].Path)
		if pi != pj {
			return pi < pj
		}
		return ni < nj
	})
	return out, nil
}

// segmentOrder extracts the period and part number of a segment path
// ("eve/eve-20261014T10.2.log.zst" -> "20261014T10", 2) for chronological
// sorting; part numbers must compare numerically.
func segmentOrder(p string) (string, int) {
	name := p[strings.LastIndexByte(p, '/')+1:]
	name = strings.TrimSuffix(strings.TrimSuffix(name, ".zst"), ".log")
	_, rest, _ := strings.Cut(name, "-")
	period, part, ok := strings.Cut(rest, ".")
	if !ok {
		return period, 0
	}
	n, _ := strconv.Atoi(part)
	return period, n
}

// Open opens a stored segment for reading, decompressing .zst segments.
func (s *FileSink) Open(nodeID, relPath string) (io.ReadCloser, error) {
	if err := nodeid.Validate(nodeID); err != nil {
		return nil, err
	}
	typ, name, ok := strings.Cut(relPath, "/")
	if !ok || ParseTypeName(typ) == agentv1.LogType_LOG_TYPE_UNSPECIFIED || strings.ContainsAny(name, "/\\") || strings.HasPrefix(name, ".") {
		return nil, fs.ErrNotExist
	}
	f, err := os.Open(filepath.Join(s.dir, nodeID, typ, name))
	if err != nil {
		return nil, err
	}
	if !strings.HasSuffix(name, ".zst") {
		return f, nil
	}
	zr, err := zstd.NewReader(f, zstd.WithDecoderConcurrency(1))
	if err != nil {
		f.Close()
		return nil, err
	}
	return &zstdFile{zr: zr, f: f}, nil
}

type zstdFile struct {
	zr *zstd.Decoder
	f  *os.File
}

func (z *zstdFile) Read(p []byte) (int, error) { return z.zr.Read(p) }
func (z *zstdFile) Close() error {
	z.zr.Close()
	return z.f.Close()
}

// TailLines returns up to n of the most recent lines of a node's log type.
func (s *FileSink) TailLines(nodeID string, t agentv1.LogType, n int, filter string) ([]string, error) {
	files, err := s.List(nodeID, t)
	if err != nil {
		return nil, err
	}
	var lines []string
	// Newest segments first, scanning at most the 48 most recent ones.
	for i := len(files) - 1; i >= 0 && i >= len(files)-48 && len(lines) < n; i-- {
		chunk, err := s.readLines(files[i], filter)
		if err != nil {
			return nil, err
		}
		need := n - len(lines)
		if len(chunk) > need {
			chunk = chunk[len(chunk)-need:]
		}
		lines = append(chunk, lines...)
	}
	return lines, nil
}

// readLines reads the lines of a segment, limited to its last 8 MiB of
// uncompressed data.
func (s *FileSink) readLines(fi FileInfo, filter string) ([]string, error) {
	const window = 8 << 20
	var data []byte
	if fi.Compressed {
		rc, err := s.Open(fi.NodeID, fi.Path)
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		ring, err := lastBytes(rc, window)
		if err != nil {
			return nil, err
		}
		data = ring
	} else {
		f, err := os.Open(filepath.Join(s.dir, fi.NodeID, filepath.FromSlash(fi.Path)))
		if err != nil {
			return nil, err
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil {
			return nil, err
		}
		off := max(st.Size()-window, 0)
		data = make([]byte, st.Size()-off)
		if _, err := f.ReadAt(data, off); err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		if off > 0 {
			if i := bytes.IndexByte(data, '\n'); i >= 0 {
				data = data[i+1:]
			}
		}
	}
	var out []string
	for _, l := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		if l == "" || (filter != "" && !strings.Contains(l, filter)) {
			continue
		}
		out = append(out, l)
	}
	return out, nil
}

// lastBytes returns the last n bytes of r, starting at a line boundary.
func lastBytes(r io.Reader, n int) ([]byte, error) {
	buf := make([]byte, 0, n)
	chunk := make([]byte, 64<<10)
	truncated := false
	for {
		k, err := r.Read(chunk)
		buf = append(buf, chunk[:k]...)
		if len(buf) > n {
			buf = append(buf[:0], buf[len(buf)-n:]...)
			truncated = true
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	if truncated {
		if i := bytes.IndexByte(buf, '\n'); i >= 0 {
			buf = buf[i+1:]
		}
	}
	return buf, nil
}

// Enforce applies the retention policy, deleting the oldest closed segments
// first. It returns the number of deleted segments.
func (s *FileSink) Enforce() (int, error) {
	s.mu.Lock()
	r := s.retention
	s.mu.Unlock()
	files, err := s.List("", agentv1.LogType_LOG_TYPE_UNSPECIFIED)
	if err != nil {
		return 0, err
	}
	now := s.now()
	deleted := 0
	remove := func(f *FileInfo) {
		if err := os.Remove(filepath.Join(s.dir, f.NodeID, filepath.FromSlash(f.Path))); err == nil {
			deleted++
		}
		f.Size = 0
		f.Open = true // mark as gone
	}
	// Oldest first across all nodes.
	sort.Slice(files, func(i, j int) bool { return files[i].ModTime.Before(files[j].ModTime) })
	perNode := map[string]int64{}
	var total int64
	for i := range files {
		f := &files[i]
		if !f.Open && r.MaxAge > 0 && now.Sub(f.ModTime) > r.MaxAge {
			remove(f)
			continue
		}
		perNode[f.NodeID] += f.Size
		total += f.Size
	}
	if r.MaxBytesPerNode > 0 {
		for i := range files {
			f := &files[i]
			if f.Open || perNode[f.NodeID] <= r.MaxBytesPerNode {
				continue
			}
			perNode[f.NodeID] -= f.Size
			total -= f.Size
			remove(f)
		}
	}
	if r.MaxTotalBytes > 0 {
		for i := range files {
			f := &files[i]
			if total <= r.MaxTotalBytes {
				break
			}
			if f.Open {
				continue
			}
			total -= f.Size
			remove(f)
		}
	}
	return deleted, nil
}

// DeleteNode removes all logs of a node.
func (s *FileSink) DeleteNode(nodeID string) error {
	if err := nodeid.Validate(nodeID); err != nil {
		return err
	}
	s.mu.Lock()
	for key, seg := range s.open {
		if strings.HasPrefix(key, nodeID+"/") {
			_ = seg.f.Close()
			delete(s.open, key)
		}
	}
	s.mu.Unlock()
	return os.RemoveAll(filepath.Join(s.dir, nodeID))
}

// Close flushes and closes all segments.
func (s *FileSink) Close() error {
	s.mu.Lock()
	for key, seg := range s.open {
		_ = seg.w.Flush()
		_ = seg.f.Close()
		delete(s.open, key)
	}
	s.mu.Unlock()
	s.compress.Wait()
	return nil
}
