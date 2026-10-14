// Package logs ingests logs shipped by agents: batches go through a
// byte-bounded drop-oldest memory queue into a Sink (by default per-node
// files with rotation and retention). It also owns the log collection
// policies sent to agents.
package logs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/jc-lab/suricontroller/controller/store"
	agentv1 "github.com/jc-lab/suricontroller/gen/suricontroller/agent/v1"
	"github.com/jc-lab/suricontroller/pkg/ringqueue"
)

// Sink stores ingested records. Records are single log lines without the
// trailing newline.
type Sink interface {
	Write(ctx context.Context, nodeID string, t agentv1.LogType, records [][]byte) error
	Close() error
}

// Setting keys in the store.
const (
	settingGlobalPolicy = "logs.collection.global"
	settingRetention    = "logs.retention"
	settingQueueBytes   = "logs.ingest_queue_max_bytes"
)

// DefaultQueueBytes is the default ingest queue capacity.
const DefaultQueueBytes = 64 << 20

// maxBatchBytes bounds the decompressed size of one agent batch.
const maxBatchBytes = 16 << 20

// DefaultPolicy collects alerts and the engine log.
func DefaultPolicy() *agentv1.LogCollectionPolicy {
	return &agentv1.LogCollectionPolicy{
		Enabled:     true,
		Types:       []agentv1.LogType{agentv1.LogType_LOG_TYPE_EVE, agentv1.LogType_LOG_TYPE_SURICATA},
		EveTypes:    []string{"alert", "anomaly", "drop"},
		EveAllTypes: false,
	}
}

type item struct {
	nodeID  string
	typ     agentv1.LogType
	records [][]byte
	size    int
}

// Config configures a Service.
type Config struct {
	Store store.Store
	// Sink receives records. If nil, a FileSink is created in Dir.
	Sink   Sink
	Dir    string
	Logger *slog.Logger
	// OnPolicyChange is called when the global collection policy changes.
	OnPolicyChange func()
}

// NodeStats counts ingested data per node.
type NodeStats struct {
	Records      uint64
	Bytes        uint64
	AgentDropped uint64
}

// Service ingests and stores logs.
type Service struct {
	cfg   Config
	log   *slog.Logger
	sink  Sink
	files *FileSink // non-nil when the default sink is used
	queue *ringqueue.Queue[*item]
	dec   *zstd.Decoder

	mu       sync.Mutex
	written  uint64
	perNode  map[string]*NodeStats
	subs     map[*subscriber]struct{}
	writeErr error
}

type subscriber struct {
	nodeID string
	typ    agentv1.LogType
	ch     chan [][]byte
}

// New creates the service.
func New(ctx context.Context, cfg Config) (*Service, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	s := &Service{cfg: cfg, log: cfg.Logger.With("component", "logs"), perNode: map[string]*NodeStats{}, subs: map[*subscriber]struct{}{}}
	ret, err := s.Retention(ctx)
	if err != nil {
		return nil, err
	}
	if cfg.Sink != nil {
		s.sink = cfg.Sink
	} else {
		fs, err := NewFileSink(cfg.Dir, ret, cfg.Logger)
		if err != nil {
			return nil, err
		}
		s.sink, s.files = fs, fs
	}
	capacity := int64(DefaultQueueBytes)
	var v int64
	if ok, err := cfg.Store.GetSetting(ctx, settingQueueBytes, &v); err != nil {
		return nil, err
	} else if ok && v > 0 {
		capacity = v
	}
	s.queue = ringqueue.New(capacity, func(it *item) int { return it.size })
	if s.dec, err = zstd.NewReader(nil, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(maxBatchBytes)); err != nil {
		return nil, err
	}
	return s, nil
}

// Files returns the default file sink, or nil when a custom sink is used.
func (s *Service) Files() *FileSink { return s.files }

// Ingest decodes an agent batch and queues it. It never blocks on storage.
func (s *Service) Ingest(nodeID string, b *agentv1.LogBatch) error {
	raw, err := s.dec.DecodeAll(b.ZstdRecords, nil)
	if err != nil {
		return fmt.Errorf("logs: decode batch: %w", err)
	}
	if len(raw) > maxBatchBytes {
		return errors.New("logs: batch too large")
	}
	var records [][]byte
	for len(raw) > 0 {
		i := bytes.IndexByte(raw, '\n')
		var line []byte
		if i < 0 {
			line, raw = raw, nil
		} else {
			line, raw = raw[:i], raw[i+1:]
		}
		if len(line) > 0 {
			records = append(records, line)
		}
	}
	s.mu.Lock()
	st := s.stats(nodeID)
	st.AgentDropped += b.DroppedSinceLast
	s.mu.Unlock()
	if len(records) == 0 {
		return nil
	}
	size := 0
	for _, r := range records {
		size += len(r) + 1
	}
	s.queue.Push(&item{nodeID: nodeID, typ: b.Type, records: records, size: size})
	return nil
}

func (s *Service) stats(nodeID string) *NodeStats {
	st := s.perNode[nodeID]
	if st == nil {
		st = &NodeStats{}
		s.perNode[nodeID] = st
	}
	return st
}

// Run writes queued records to the sink and enforces retention until ctx is
// cancelled.
func (s *Service) Run(ctx context.Context) {
	go s.janitor(ctx)
	for {
		items, err := s.queue.PopBatch(ctx, 256, 4<<20)
		if err != nil {
			return
		}
		for _, it := range items {
			if err := s.sink.Write(ctx, it.nodeID, it.typ, it.records); err != nil {
				s.mu.Lock()
				first := s.writeErr == nil
				s.writeErr = err
				s.mu.Unlock()
				if first {
					s.log.Error("write logs", "node", it.nodeID, "err", err)
				}
				continue
			}
			s.mu.Lock()
			s.writeErr = nil
			s.written += uint64(len(it.records))
			st := s.stats(it.nodeID)
			st.Records += uint64(len(it.records))
			st.Bytes += uint64(it.size)
			for sub := range s.subs {
				if sub.nodeID == it.nodeID && sub.typ == it.typ {
					select {
					case sub.ch <- it.records:
					default: // slow follower: drop
					}
				}
			}
			s.mu.Unlock()
		}
	}
}

func (s *Service) janitor(ctx context.Context) {
	if s.files == nil {
		return
	}
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for i := 0; ; i++ {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		s.files.RotateIdle()
		if i%5 == 0 {
			if n, err := s.files.Enforce(); err != nil {
				s.log.Warn("enforce retention", "err", err)
			} else if n > 0 {
				s.log.Info("deleted log segments by retention policy", "count", n)
			}
		}
	}
}

// Close closes the queue and the sink.
func (s *Service) Close() error {
	s.queue.Close()
	s.dec.Close()
	return s.sink.Close()
}

// IngestStats is a snapshot of ingest counters.
type IngestStats struct {
	Queue   ringqueue.Stats
	Written uint64
	Nodes   map[string]NodeStats
}

// Stats returns ingest counters.
func (s *Service) Stats() IngestStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := IngestStats{Queue: s.queue.Stats(), Written: s.written, Nodes: map[string]NodeStats{}}
	for k, v := range s.perNode {
		out.Nodes[k] = *v
	}
	return out
}

// QueueCapacity returns the ingest queue capacity in bytes.
func (s *Service) QueueCapacity() int64 { return s.queue.Stats().Capacity }

// SetQueueCapacity changes and persists the ingest queue capacity.
func (s *Service) SetQueueCapacity(ctx context.Context, bytes int64) error {
	if bytes < 1<<20 {
		return errors.New("logs: queue capacity must be at least 1 MiB")
	}
	if err := s.cfg.Store.PutSetting(ctx, settingQueueBytes, bytes); err != nil {
		return err
	}
	s.queue.SetCapacity(bytes)
	return nil
}

// GlobalPolicy returns the global collection policy.
func (s *Service) GlobalPolicy(ctx context.Context) (*agentv1.LogCollectionPolicy, error) {
	p := &agentv1.LogCollectionPolicy{}
	ok, err := s.cfg.Store.GetSetting(ctx, settingGlobalPolicy, p)
	if err != nil {
		return nil, err
	}
	if !ok {
		return DefaultPolicy(), nil
	}
	return p, nil
}

// SetGlobalPolicy stores the global collection policy.
func (s *Service) SetGlobalPolicy(ctx context.Context, p *agentv1.LogCollectionPolicy) error {
	if err := s.cfg.Store.PutSetting(ctx, settingGlobalPolicy, p); err != nil {
		return err
	}
	if s.cfg.OnPolicyChange != nil {
		s.cfg.OnPolicyChange()
	}
	return nil
}

// retentionSetting is the persisted form of Retention.
type retentionSetting struct {
	Daily           bool  `json:"daily"`
	MaxSegmentBytes int64 `json:"max_segment_bytes"`
	MaxAgeHours     int64 `json:"max_age_hours"`
	MaxBytesPerNode int64 `json:"max_bytes_per_node"`
	MaxTotalBytes   int64 `json:"max_total_bytes"`
	Compress        bool  `json:"compress"`
}

// Retention returns the retention policy.
func (s *Service) Retention(ctx context.Context) (Retention, error) {
	var rs retentionSetting
	ok, err := s.cfg.Store.GetSetting(ctx, settingRetention, &rs)
	if err != nil || !ok {
		return DefaultRetention, err
	}
	return Retention{
		Daily: rs.Daily, MaxSegmentBytes: rs.MaxSegmentBytes, MaxAge: time.Duration(rs.MaxAgeHours) * time.Hour,
		MaxBytesPerNode: rs.MaxBytesPerNode, MaxTotalBytes: rs.MaxTotalBytes, Compress: rs.Compress,
	}, nil
}

// SetRetention stores and applies the retention policy.
func (s *Service) SetRetention(ctx context.Context, r Retention) error {
	rs := retentionSetting{
		Daily: r.Daily, MaxSegmentBytes: r.MaxSegmentBytes, MaxAgeHours: int64(r.MaxAge / time.Hour),
		MaxBytesPerNode: r.MaxBytesPerNode, MaxTotalBytes: r.MaxTotalBytes, Compress: r.Compress,
	}
	if err := s.cfg.Store.PutSetting(ctx, settingRetention, rs); err != nil {
		return err
	}
	if s.files != nil {
		s.files.SetRetention(r)
	}
	return nil
}

// Follow subscribes to new records of a node's log type. The returned
// channel is closed when ctx is done.
func (s *Service) Follow(ctx context.Context, nodeID string, t agentv1.LogType) <-chan [][]byte {
	sub := &subscriber{nodeID: nodeID, typ: t, ch: make(chan [][]byte, 64)}
	s.mu.Lock()
	s.subs[sub] = struct{}{}
	s.mu.Unlock()
	out := make(chan [][]byte)
	go func() {
		defer close(out)
		defer func() {
			s.mu.Lock()
			delete(s.subs, sub)
			s.mu.Unlock()
		}()
		for {
			select {
			case <-ctx.Done():
				return
			case recs := <-sub.ch:
				select {
				case out <- recs:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return out
}

// OpenFile opens a stored segment of the default file sink.
func (s *Service) OpenFile(nodeID, relPath string) (io.ReadCloser, error) {
	if s.files == nil {
		return nil, errors.New("logs: custom sink does not support reading")
	}
	return s.files.Open(nodeID, relPath)
}
