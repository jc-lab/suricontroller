package rules

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/md5"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jc-lab/suricontroller/controller/gitrepo"
	"github.com/jc-lab/suricontroller/controller/store"
	"github.com/jc-lab/suricontroller/controller/store/sqlite"
)

func tarGz(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, content := range files {
		tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg})
		tw.Write([]byte(content))
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

type fakeET struct {
	archive  atomic.Value // []byte
	archiveN atomic.Int32
}

func (f *fakeET) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	data := f.archive.Load().([]byte)
	switch {
	case strings.HasSuffix(r.URL.Path, ".md5"):
		sum := md5.Sum(data)
		w.Write([]byte(hex.EncodeToString(sum[:]) + "\n"))
	case strings.HasSuffix(r.URL.Path, ".tar.gz"):
		f.archiveN.Add(1)
		w.Write(data)
	default:
		http.NotFound(w, r)
	}
}

func TestETOpenSync(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, err := sqlite.Open(filepath.Join(dir, "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	repo, err := gitrepo.Open(filepath.Join(dir, "rules.git"))
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeET{}
	fake.archive.Store(tarGz(t, map[string]string{
		"rules/emerging-dns.rules":    "alert dns any any -> any any (msg:\"a\"; sid:1;)\n",
		"rules/classification.config": "config classification: x,y,1\n",
		"rules/sid-msg.map":           "ignored",
	}))
	srv := httptest.NewServer(fake)
	defer srv.Close()

	var commits []string
	s := New(Config{Store: st, Repo: repo, OnCommit: func(c string) { commits = append(commits, c) }})
	if err := s.Init(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Update(ctx, "et-open", nil, nil, map[string]string{"url": srv.URL + "/open/suricata-8.0.5/emerging.rules.tar.gz"}); err != nil {
		t.Fatal(err)
	}
	c1, err := s.Sync(ctx, "et-open")
	if err != nil || c1 == "" {
		t.Fatalf("first sync: %q %v", c1, err)
	}
	files, _ := repo.ReadDir(c1, "et-open")
	if len(files) != 2 || files["emerging-dns.rules"] == nil || files["sid-msg.map"] != nil {
		t.Fatalf("files = %v", keys(files))
	}
	// Unchanged upstream: md5 matches, archive not downloaded again.
	c2, err := s.Sync(ctx, "et-open")
	if err != nil || c2 != "" || fake.archiveN.Load() != 1 {
		t.Fatalf("second sync: %q %v downloads=%d", c2, err, fake.archiveN.Load())
	}
	fake.archive.Store(tarGz(t, map[string]string{"rules/emerging-dns.rules": "changed\n"}))
	c3, err := s.Sync(ctx, "et-open")
	if err != nil || c3 == "" || c3 == c1 {
		t.Fatalf("third sync: %q %v", c3, err)
	}
	files, _ = repo.ReadDir(c3, "et-open")
	if len(files) != 1 {
		t.Fatalf("removed file still present: %v", keys(files))
	}
	if len(commits) != 2 {
		t.Fatalf("OnCommit calls = %d", len(commits))
	}
	p, _ := st.GetProvider(ctx, "et-open")
	if p.LastError != "" || p.LastCommit != c3 || p.LastSuccessAt.IsZero() {
		t.Fatalf("provider state = %+v", p)
	}
	if managed, _ := s.IsManagedPath(ctx, "et-open/x.rules"); !managed {
		t.Fatal("et-open should be managed")
	}
	if managed, _ := s.IsManagedPath(ctx, "local/local.rules"); managed {
		t.Fatal("local should not be managed")
	}

	// Failures are recorded.
	srv.Close()
	if _, err := s.Sync(ctx, "et-open"); err == nil {
		t.Fatal("expected error")
	}
	p, _ = st.GetProvider(ctx, "et-open")
	if p.LastError == "" {
		t.Fatal("error not recorded")
	}
}

func TestRunDueRespectsInterval(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, _ := sqlite.Open(filepath.Join(dir, "db"))
	defer st.Close()
	repo, _ := gitrepo.Open(filepath.Join(dir, "rules.git"))
	var n atomic.Int32
	s := New(Config{Store: st, Repo: repo, Types: []TypeInfo{{Name: "fake", Fetcher: fetcherFunc(func(ctx context.Context, p *store.Provider) (*FetchResult, error) {
		n.Add(1)
		return &FetchResult{Files: map[string][]byte{"a.rules": []byte("x")}}, nil
	}), DefaultInterval: time.Hour}}})
	st.PutProvider(ctx, &store.Provider{Name: "p", Type: "fake", Enabled: true, Interval: time.Hour})
	st.PutProvider(ctx, &store.Provider{Name: "off", Type: "fake", Enabled: false})
	now := time.Now()
	s.now = func() time.Time { return now }
	s.runDue(ctx)
	s.runDue(ctx)
	if n.Load() != 1 {
		t.Fatalf("fetches = %d, want 1", n.Load())
	}
	now = now.Add(61 * time.Minute)
	s.runDue(ctx)
	if n.Load() != 2 {
		t.Fatalf("fetches = %d, want 2", n.Load())
	}
}

type fetcherFunc func(ctx context.Context, p *store.Provider) (*FetchResult, error)

func (f fetcherFunc) Fetch(ctx context.Context, p *store.Provider) (*FetchResult, error) {
	return f(ctx, p)
}

func keys(m map[string][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestETOpenBadMD5(t *testing.T) {
	for _, body := range []string{"", "   \n", "not-a-hash"} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
		_, err := (&ETOpen{}).Fetch(context.Background(), &store.Provider{Options: map[string]string{"url": srv.URL + "/x.tar.gz"}})
		srv.Close()
		if err == nil {
			t.Errorf("md5 %q accepted", body)
		}
	}
}
