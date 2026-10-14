package logs

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/jc-lab/suricontroller/controller/store/sqlite"
	agentv1 "github.com/jc-lab/suricontroller/gen/suricontroller/agent/v1"
)

func batch(t *testing.T, typ agentv1.LogType, lines ...string) *agentv1.LogBatch {
	t.Helper()
	enc, _ := zstd.NewWriter(nil)
	defer enc.Close()
	raw := strings.Join(lines, "\n") + "\n"
	return &agentv1.LogBatch{Type: typ, ZstdRecords: enc.EncodeAll([]byte(raw), nil), RecordCount: uint32(len(lines))}
}

func TestIngestWriteTail(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dir := t.TempDir()
	st, _ := sqlite.Open(filepath.Join(dir, "db"))
	defer st.Close()
	s, err := New(ctx, Config{Store: st, Dir: filepath.Join(dir, "logs")})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Run(ctx)

	follow := s.Follow(ctx, "router-01", agentv1.LogType_LOG_TYPE_EVE)
	if err := s.Ingest("router-01", batch(t, agentv1.LogType_LOG_TYPE_EVE, `{"event_type":"alert","n":1}`, `{"event_type":"alert","n":2}`)); err != nil {
		t.Fatal(err)
	}
	select {
	case recs := <-follow:
		if len(recs) != 2 {
			t.Fatalf("followed %d records", len(recs))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("follow timeout")
	}
	if err := s.Ingest("router-01", batch(t, agentv1.LogType_LOG_TYPE_EVE, `{"event_type":"dns","n":3}`)); err != nil {
		t.Fatal(err)
	}
	waitWritten(t, s, 3)

	lines, err := s.Files().TailLines("router-01", agentv1.LogType_LOG_TYPE_EVE, 2, "")
	if err != nil || len(lines) != 2 || !strings.Contains(lines[1], `"n":3`) {
		t.Fatalf("tail = %v %v", lines, err)
	}
	lines, _ = s.Files().TailLines("router-01", agentv1.LogType_LOG_TYPE_EVE, 10, "alert")
	if len(lines) != 2 {
		t.Fatalf("filtered tail = %v", lines)
	}
	files, _ := s.Files().List("router-01", agentv1.LogType_LOG_TYPE_UNSPECIFIED)
	if len(files) != 1 || !files[0].Open || files[0].Type != agentv1.LogType_LOG_TYPE_EVE {
		t.Fatalf("files = %+v", files)
	}
	if st := s.Stats(); st.Nodes["router-01"].Records != 3 {
		t.Fatalf("stats = %+v", st)
	}
}

func waitWritten(t *testing.T, s *Service, n uint64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for s.Stats().Written < n {
		if time.Now().After(deadline) {
			t.Fatalf("written = %d, want %d", s.Stats().Written, n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestRotationCompressionRetention(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 10, 14, 10, 30, 0, 0, time.UTC)
	fs, err := NewFileSink(dir, Retention{MaxSegmentBytes: 100, Compress: true, MaxBytesPerNode: 250}, nil)
	if err != nil {
		t.Fatal(err)
	}
	fs.now = func() time.Time { return now }
	ctx := context.Background()
	line := []byte(strings.Repeat("x", 59)) // 60 bytes with newline
	for i := range 4 {
		if err := fs.Write(ctx, "n1", agentv1.LogType_LOG_TYPE_EVE, [][]byte{line}); err != nil {
			t.Fatal(err)
		}
		_ = i
	}
	// 4 writes of 60 bytes with a 100 byte segment limit -> 2 segments.
	now = now.Add(time.Hour)
	fs.RotateIdle()
	fs.compress.Wait()
	files, _ := fs.List("n1", agentv1.LogType_LOG_TYPE_EVE)
	if len(files) != 2 || !files[0].Compressed || !files[1].Compressed {
		t.Fatalf("files = %+v", files)
	}
	rc, err := fs.Open("n1", files[0].Path)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(rc)
	rc.Close()
	if len(data) != 120 {
		t.Fatalf("decompressed %d bytes", len(data))
	}

	// Age-based deletion.
	old := filepath.Join(dir, "n1", "eve", files[0].Path[len("eve/"):])
	os.Chtimes(old, now.Add(-30*24*time.Hour), now.Add(-30*24*time.Hour))
	fs.SetRetention(Retention{MaxAge: 24 * time.Hour, Compress: true})
	n, err := fs.Enforce()
	if err != nil || n != 1 {
		t.Fatalf("enforce deleted %d, err %v", n, err)
	}

	// Size-based deletion keeps the newest data.
	for i := range 10 {
		now = now.Add(time.Hour)
		fs.Write(ctx, "n2", agentv1.LogType_LOG_TYPE_EVE, [][]byte{[]byte(fmt.Sprintf("%03d-%s", i, strings.Repeat("y", 200)))})
	}
	fs.RotateIdle()
	fs.compress.Wait()
	for i, f := range mustList(t, fs, "n2") {
		os.Chtimes(filepath.Join(dir, "n2", f.Path), now.Add(time.Duration(i)*time.Minute), now.Add(time.Duration(i)*time.Minute))
	}
	fs.SetRetention(Retention{MaxBytesPerNode: 1, Compress: true})
	fs.Enforce()
	left := mustList(t, fs, "n2")
	if len(left) != 1 {
		t.Fatalf("left = %+v", left)
	}
	lines, _ := fs.TailLines("n2", agentv1.LogType_LOG_TYPE_EVE, 5, "")
	if len(lines) != 1 || !strings.HasPrefix(lines[0], "009-") {
		t.Fatalf("newest data not kept: %v", lines)
	}
	fs.Close()
}

func mustList(t *testing.T, fs *FileSink, node string) []FileInfo {
	t.Helper()
	files, err := fs.List(node, agentv1.LogType_LOG_TYPE_UNSPECIFIED)
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func TestPolicyAndSettings(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, _ := sqlite.Open(filepath.Join(dir, "db"))
	defer st.Close()
	changed := 0
	s, err := New(ctx, Config{Store: st, Dir: filepath.Join(dir, "logs"), OnPolicyChange: func() { changed++ }})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	p, _ := s.GlobalPolicy(ctx)
	if !p.Enabled || len(p.Types) == 0 {
		t.Fatal("default policy")
	}
	if err := s.SetGlobalPolicy(ctx, &agentv1.LogCollectionPolicy{Enabled: false}); err != nil {
		t.Fatal(err)
	}
	p, _ = s.GlobalPolicy(ctx)
	if p.Enabled || changed != 1 {
		t.Fatal("policy not stored")
	}
	if err := s.SetQueueCapacity(ctx, 2<<20); err != nil || s.QueueCapacity() != 2<<20 {
		t.Fatal("queue capacity")
	}
	if err := s.SetRetention(ctx, Retention{Daily: true, MaxAge: 48 * time.Hour}); err != nil {
		t.Fatal(err)
	}
	r, _ := s.Retention(ctx)
	if !r.Daily || r.MaxAge != 48*time.Hour {
		t.Fatalf("retention = %+v", r)
	}
}

func TestSegmentOrder(t *testing.T) {
	paths := []string{"eve/eve-20261014T10.10.log.zst", "eve/eve-20261014T10.log.zst", "eve/eve-20261014T10.2.log", "eve/eve-20261014T09.log.zst"}
	sort.Slice(paths, func(i, j int) bool {
		pi, ni := segmentOrder(paths[i])
		pj, nj := segmentOrder(paths[j])
		if pi != pj {
			return pi < pj
		}
		return ni < nj
	})
	want := []string{"eve/eve-20261014T09.log.zst", "eve/eve-20261014T10.log.zst", "eve/eve-20261014T10.2.log", "eve/eve-20261014T10.10.log.zst"}
	if strings.Join(paths, ",") != strings.Join(want, ",") {
		t.Fatalf("order = %v", paths)
	}
}
