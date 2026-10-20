// Package collector reads the logs Suricata writes on the node and ships
// the records selected by the controller's collection policy. Log files
// are owned by the node user (other collectors such as Elastic Agent may
// read them too); the collector only tails them, tracking inode and offset
// across restarts and rotations. Records go through a byte-bounded memory
// queue that drops the oldest records when full.
//
// File positions are saved only up to lines that were delivered (Commit),
// so after a restart the collector reads again every line that was queued
// or in flight but not acknowledged.
package collector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/klauspost/compress/zstd"

	agentv1 "github.com/jc-lab/suricontroller/gen/suricontroller/agent/v1"
	"github.com/jc-lab/suricontroller/pkg/ringqueue"
	"github.com/jc-lab/suricontroller/pkg/wire"
)

// Config configures a Collector.
type Config struct {
	QueueMaxBytes int64
	// StartAtEnd starts newly discovered files at their end.
	StartAtEnd bool
	// OffsetsFile persists tail positions.
	OffsetsFile string
	Extra       []Source
	// Rotation, when MaxSize > 0, renames files above MaxSize, keeps Keep
	// rotated files and asks the instance to reopen its logs.
	RotateMaxSize int64
	RotateKeep    int
	// Reopen asks an instance to reopen its log files (SIGHUP).
	Reopen func(instance string) error
	Logger *slog.Logger
}

type record struct {
	typ      agentv1.LogType
	instance string
	Record
}

// Record is one collected log line.
type Record struct {
	Line []byte
	// Path, Inode and Offset locate a line read from a file; Path is empty
	// for engine process output and the agent's own log. Offset is the
	// position of the line's first byte, so the triple identifies the line
	// across agent restarts.
	Path   string
	Inode  uint64
	Offset int64
	// end is the position after the line's newline.
	end int64
}

// Batch is a group of records of one log type and instance.
type Batch struct {
	Type     agentv1.LogType
	Instance string
	Records  []Record
	// Dropped is the number of records the queue dropped since the
	// previous batch.
	Dropped uint64
}

// Collector tails logs and ships them.
type Collector struct {
	cfg   Config
	log   *slog.Logger
	queue *ringqueue.Queue[record]

	// pollMu serializes polling with source changes; tailers are only
	// touched while it is held.
	pollMu sync.Mutex

	mu        sync.Mutex
	policy    *agentv1.LogCollectionPolicy
	sources   []Source
	tailers   map[string]*tailer
	engineLog map[string]bool // instances whose engine log comes from process output
	// offsets are the positions persisted in OffsetsFile.
	offsets map[string]offset
	// committed is the end of the last delivered line of each file and
	// outstanding the number of its lines queued or in flight.
	committed   map[string]offset
	outstanding map[string]int
	sent        uint64
	lastDrop    uint64
}

type offset struct {
	Inode  uint64 `json:"inode"`
	Offset int64  `json:"offset"`
}

// New creates a collector.
func New(cfg Config) *Collector {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.QueueMaxBytes <= 0 {
		cfg.QueueMaxBytes = 16 << 20
	}
	c := &Collector{
		cfg:         cfg,
		log:         cfg.Logger.With("component", "collector"),
		queue:       ringqueue.New(cfg.QueueMaxBytes, func(r record) int { return len(r.Line) + 32 }),
		tailers:     map[string]*tailer{},
		engineLog:   map[string]bool{},
		offsets:     map[string]offset{},
		committed:   map[string]offset{},
		outstanding: map[string]int{},
	}
	// A dropped line is given up: it no longer holds back the saved
	// position of its file. (It runs with the queue locked; c.mu is never
	// held while pushing.)
	c.queue.SetOnDrop(func(r record) {
		if r.Path != "" {
			c.mu.Lock()
			c.outstanding[r.Path]--
			c.mu.Unlock()
		}
	})
	if b, err := os.ReadFile(cfg.OffsetsFile); err == nil {
		_ = json.Unmarshal(b, &c.offsets)
	}
	return c
}

// SetPolicy sets the collection policy.
func (c *Collector) SetPolicy(p *agentv1.LogCollectionPolicy) {
	c.mu.Lock()
	c.policy = p
	c.mu.Unlock()
}

// SetInstances replaces the sources with those of the running instances.
func (c *Collector) SetInstances(instances []Instance) {
	var srcs []Source
	for _, inst := range instances {
		srcs = append(srcs, Discover(inst)...)
	}
	srcs = append(srcs, c.cfg.Extra...)
	c.pollMu.Lock()
	defer c.pollMu.Unlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sources = srcs
	want := map[string]Source{}
	c.engineLog = map[string]bool{}
	for _, s := range srcs {
		if s.Path == "" {
			c.engineLog[s.Instance] = true
			continue
		}
		want[s.Path] = s
	}
	for p, t := range c.tailers {
		if _, ok := want[p]; !ok {
			t.close()
			delete(c.tailers, p)
		}
	}
	for p, s := range want {
		if t, ok := c.tailers[p]; ok {
			t.src = s
			continue
		}
		c.tailers[p] = &tailer{src: s}
	}
}

// Sources returns the collectable logs for Hello/Status.
func (c *Collector) Sources() []*agentv1.LogSource {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []*agentv1.LogSource
	for _, s := range c.sources {
		out = append(out, &agentv1.LogSource{Type: s.Type, Instance: s.Instance, Path: s.Path, EveTypes: s.EveTypes})
	}
	return out
}

// Stats returns queue statistics.
func (c *Collector) Stats() *agentv1.LogQueueStats {
	st := c.queue.Stats()
	c.mu.Lock()
	defer c.mu.Unlock()
	return &agentv1.LogQueueStats{Bytes: uint64(st.Bytes), CapacityBytes: uint64(st.Capacity), DroppedRecords: st.Dropped, SentRecords: c.sent}
}

// allowed reports whether a log type is collected at all.
func (c *Collector) allowed(t agentv1.LogType) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	p := c.policy
	return p != nil && p.Enabled && slices.Contains(p.Types, t)
}

// wantLine applies the eve event type filter.
func (c *Collector) wantLine(t agentv1.LogType, line []byte) bool {
	if t != agentv1.LogType_LOG_TYPE_EVE {
		return true
	}
	c.mu.Lock()
	p := c.policy
	c.mu.Unlock()
	if p == nil || p.EveAllTypes {
		return true
	}
	return slices.Contains(p.EveTypes, eventType(line))
}

// eventType extracts the event_type field of an eve record without full
// JSON decoding.
func eventType(line []byte) string {
	const key = `"event_type":`
	i := bytes.Index(line, []byte(key))
	if i < 0 {
		return ""
	}
	rest := bytes.TrimLeft(line[i+len(key):], " ")
	if len(rest) == 0 || rest[0] != '"' {
		return ""
	}
	end := bytes.IndexByte(rest[1:], '"')
	if end < 0 {
		return ""
	}
	return string(rest[1 : 1+end])
}

func (c *Collector) push(t agentv1.LogType, instance string, r Record) {
	if !c.wantLine(t, r.Line) {
		return
	}
	if r.Path != "" {
		c.mu.Lock()
		c.outstanding[r.Path]++
		c.mu.Unlock()
	}
	c.queue.Push(record{typ: t, instance: instance, Record: r})
}

// PushEngineLine handles a line of engine process output.
func (c *Collector) PushEngineLine(instance, line string) {
	c.mu.Lock()
	use := c.engineLog[instance]
	c.mu.Unlock()
	if use && c.allowed(agentv1.LogType_LOG_TYPE_SURICATA) {
		c.push(agentv1.LogType_LOG_TYPE_SURICATA, instance, Record{Line: []byte(line)})
	}
}

// AgentLogWriter returns a writer that collects the agent's own log lines.
func (c *Collector) AgentLogWriter() io.Writer { return agentLog{c} }

type agentLog struct{ c *Collector }

func (a agentLog) Write(p []byte) (int, error) {
	if a.c.allowed(agentv1.LogType_LOG_TYPE_AGENT) {
		for _, l := range bytes.Split(bytes.TrimRight(p, "\n"), []byte("\n")) {
			if len(l) > 0 {
				a.c.queue.Push(record{typ: agentv1.LogType_LOG_TYPE_AGENT, Record: Record{Line: append([]byte(nil), l...)}})
			}
		}
	}
	return len(p), nil
}

// Run tails the sources until ctx is cancelled.
func (c *Collector) Run(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	save := time.NewTicker(5 * time.Second)
	defer save.Stop()
	defer c.saveOffsets()
	for {
		select {
		case <-ctx.Done():
			return
		case <-save.C:
			c.saveOffsets()
		case <-t.C:
			c.pollAll()
		}
	}
}

func (c *Collector) pollAll() {
	c.pollMu.Lock()
	defer c.pollMu.Unlock()
	c.mu.Lock()
	tailers := make([]*tailer, 0, len(c.tailers))
	for _, t := range c.tailers {
		tailers = append(tailers, t)
	}
	c.mu.Unlock()
	for _, t := range tailers {
		c.rotateIfNeeded(t)
		if err := t.poll(c); err != nil && !errors.Is(err, os.ErrNotExist) {
			c.log.Debug("tail", "path", t.src.Path, "err", err)
		}
	}
}

func (c *Collector) saveOffsets() {
	if c.cfg.OffsetsFile == "" {
		return
	}
	c.pollMu.Lock()
	defer c.pollMu.Unlock()
	c.mu.Lock()
	for p, t := range c.tailers {
		if t.f == nil {
			continue
		}
		if c.outstanding[p] <= 0 {
			// Nothing pending: everything up to the start of the
			// unfinished last line is done (delivered, filtered or
			// skipped).
			c.offsets[p] = offset{Inode: t.inode, Offset: t.pos - int64(len(t.partial))}
		} else if cp, ok := c.committed[p]; ok {
			c.offsets[p] = cp
		}
	}
	b, _ := json.Marshal(c.offsets)
	c.mu.Unlock()
	tmp := c.cfg.OffsetsFile + ".tmp"
	if err := os.MkdirAll(filepath.Dir(tmp), 0o755); err != nil {
		return
	}
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, c.cfg.OffsetsFile)
	}
}

// rotateIfNeeded renames an oversized log file (path -> path.1 -> ...) and
// asks the instance to reopen it.
func (c *Collector) rotateIfNeeded(t *tailer) {
	if c.cfg.RotateMaxSize <= 0 || t.src.Instance == "" || c.cfg.Reopen == nil {
		return
	}
	fi, err := os.Stat(t.src.Path)
	if err != nil || fi.Size() < c.cfg.RotateMaxSize {
		return
	}
	keep := max(c.cfg.RotateKeep, 1)
	_ = os.Remove(t.src.Path + "." + itoa(keep))
	for i := keep - 1; i >= 1; i-- {
		_ = os.Rename(t.src.Path+"."+itoa(i), t.src.Path+"."+itoa(i+1))
	}
	if err := os.Rename(t.src.Path, t.src.Path+".1"); err != nil {
		return
	}
	if err := c.cfg.Reopen(t.src.Instance); err != nil {
		c.log.Warn("reopen logs after rotation", "instance", t.src.Instance, "err", err)
	}
}

func itoa(i int) string { return strconv.Itoa(i) }

// tailer follows one file.
type tailer struct {
	src     Source
	f       *os.File
	inode   uint64
	pos     int64
	partial []byte
}

func (t *tailer) close() {
	if t.f != nil {
		t.f.Close()
		t.f = nil
	}
}

func inodeOf(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Ino
	}
	return 0
}

const maxReadPerPoll = 4 << 20

func (t *tailer) poll(c *Collector) error {
	if t.f == nil {
		f, err := os.Open(t.src.Path)
		if err != nil {
			return err
		}
		fi, err := f.Stat()
		if err != nil {
			f.Close()
			return err
		}
		t.f, t.inode, t.partial = f, inodeOf(fi), nil
		c.mu.Lock()
		saved, ok := c.offsets[t.src.Path]
		c.mu.Unlock()
		switch {
		case ok && saved.Inode == t.inode && saved.Offset <= fi.Size():
			t.pos = saved.Offset
		case ok || !c.cfg.StartAtEnd:
			// A rotated file (saved inode differs) is read from the start.
			t.pos = 0
		default:
			t.pos = fi.Size()
		}
	}
	if err := t.read(c); err != nil {
		return err
	}
	// Detect rotation: the path now names another file.
	fi, err := os.Stat(t.src.Path)
	if err == nil && inodeOf(fi) != t.inode {
		// Drain the old file completely before switching.
		for {
			before := t.pos
			if err := t.read(c); err != nil || t.pos == before {
				break
			}
		}
		t.close()
		c.mu.Lock()
		c.offsets[t.src.Path] = offset{Inode: inodeOf(fi), Offset: 0}
		c.mu.Unlock()
		return nil
	}
	if err == nil {
		if cur, _ := t.f.Stat(); cur != nil && cur.Size() < t.pos {
			t.pos, t.partial = 0, nil // truncated
		}
	}
	return nil
}

func (t *tailer) read(c *Collector) error {
	fi, err := t.f.Stat()
	if err != nil {
		return err
	}
	if fi.Size() <= t.pos {
		return nil
	}
	if !c.allowed(t.src.Type) {
		t.pos, t.partial = fi.Size(), nil // skip unwanted data cheaply
		return nil
	}
	n := min(fi.Size()-t.pos, maxReadPerPoll)
	buf := make([]byte, n)
	got, err := t.f.ReadAt(buf, t.pos)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	buf = buf[:got]
	start := t.pos - int64(len(t.partial)) // file position of data[0]
	t.pos += int64(got)
	data := append(t.partial, buf...)
	for {
		i := bytes.IndexByte(data, '\n')
		if i < 0 {
			break
		}
		if i > 0 {
			c.push(t.src.Type, t.src.Instance, Record{Line: data[:i], Path: t.src.Path, Inode: t.inode, Offset: start, end: start + int64(i) + 1})
		}
		data = data[i+1:]
		start += int64(i) + 1
	}
	if len(data) > 1<<20 {
		c.push(t.src.Type, t.src.Instance, Record{Line: data, Path: t.src.Path, Inode: t.inode, Offset: start, end: start + int64(len(data))})
		data = nil
	}
	t.partial = append([]byte(nil), data...)
	return nil
}

// Next waits for queued records and returns them grouped by log type and
// instance, at most maxRecords records and about maxBytes bytes in total.
func (c *Collector) Next(ctx context.Context, maxRecords int, maxBytes int64) ([]*Batch, error) {
	recs, err := c.queue.PopBatch(ctx, maxRecords, maxBytes)
	if err != nil {
		return nil, err
	}
	type key struct {
		t agentv1.LogType
		i string
	}
	groups := map[key]*Batch{}
	var out []*Batch
	for _, r := range recs {
		k := key{r.typ, r.instance}
		b, ok := groups[k]
		if !ok {
			b = &Batch{Type: r.typ, Instance: r.instance}
			groups[k] = b
			out = append(out, b)
		}
		b.Records = append(b.Records, r.Record)
	}
	st := c.queue.Stats()
	c.mu.Lock()
	out[0].Dropped = st.Dropped - c.lastDrop
	c.lastDrop = st.Dropped
	c.mu.Unlock()
	return out, nil
}

// Commit marks the records of b as delivered: the saved file positions may
// advance past them. Commit batches in the order Next returned them; lines
// of batches never committed are read again after an agent restart.
func (c *Collector) Commit(b *Batch) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sent += uint64(len(b.Records))
	for _, r := range b.Records {
		if r.Path == "" {
			continue
		}
		c.outstanding[r.Path]--
		if cp, ok := c.committed[r.Path]; !ok || cp.Inode != r.Inode || cp.Offset < r.end {
			c.committed[r.Path] = offset{Inode: r.Inode, Offset: r.end}
		}
	}
}

// Ship sends queued records over a log stream until the stream fails or
// ctx is cancelled. A record counts as delivered once it is written to the
// stream.
func (c *Collector) Ship(ctx context.Context, ms *wire.MsgStream) error {
	enc, err := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1), zstd.WithEncoderLevel(zstd.SpeedFastest))
	if err != nil {
		return err
	}
	defer enc.Close()
	var seq uint64
	stop := context.AfterFunc(ctx, func() { ms.Close() })
	defer stop()
	for {
		batches, err := c.Next(ctx, 2000, 512<<10)
		if err != nil {
			return err
		}
		for _, b := range batches {
			seq++
			if err := ms.Send(&agentv1.LogBatch{
				Seq: seq, Type: b.Type, Instance: b.Instance, ZstdRecords: enc.EncodeAll(JoinLines(b.Records), nil),
				RecordCount: uint32(len(b.Records)), DroppedSinceLast: b.Dropped,
			}); err != nil {
				return err
			}
			c.Commit(b)
		}
	}
}

// JoinLines returns the lines of recs, each followed by a newline.
func JoinLines(recs []Record) []byte {
	n := 0
	for _, r := range recs {
		n += len(r.Line) + 1
	}
	out := make([]byte, 0, n)
	for _, r := range recs {
		out = append(out, r.Line...)
		out = append(out, '\n')
	}
	return out
}
