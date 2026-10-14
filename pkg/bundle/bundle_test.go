package bundle

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
)

func files() map[string][]byte {
	return map[string][]byte{
		PathRules:          []byte("alert ip any any -> any any (msg:\"x\"; sid:1;)\n"),
		PathControllerYAML: []byte("%YAML 1.1\n---\ndetect: {}\n"),
	}
}

func TestBuildReadDeterministic(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	m := Manifest{NodeID: "router-01", RulesCommit: "aaa", ConfigCommit: "bbb", RuleStats: RuleStats{Total: 1, Enabled: 1}}
	b1, err := Build(m, files(), priv)
	if err != nil {
		t.Fatal(err)
	}
	b2, _ := Build(m, files(), priv)
	if b1.ID != b2.ID || !bytes.Equal(b1.Archive, b2.Archive) {
		t.Fatal("build is not deterministic")
	}
	got, err := Read(bytes.NewReader(b1.Archive), b1.ID, pub, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Manifest.NodeID != "router-01" || string(got.Files[PathRules]) != string(files()[PathRules]) {
		t.Fatalf("unexpected bundle %+v", got.Manifest)
	}
	dir := t.TempDir()
	if err := got.WriteTo(dir); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "config", "controller.yaml")); !strings.Contains(string(b), "detect") {
		t.Fatal("WriteTo")
	}

	// Different content -> different id.
	f := files()
	f[PathRules] = []byte("changed")
	b3, _ := Build(m, f, priv)
	if b3.ID == b1.ID {
		t.Fatal("id did not change with content")
	}
}

func TestReadRejects(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	b, _ := Build(Manifest{NodeID: "n"}, files(), priv)
	if _, err := Read(bytes.NewReader(b.Archive), "deadbeef", pub, Limits{}); err == nil {
		t.Fatal("wrong id accepted")
	}
	if _, err := Read(bytes.NewReader(b.Archive), b.ID, otherPub, Limits{}); err == nil {
		t.Fatal("wrong key accepted")
	}
	if _, err := Read(bytes.NewReader(b.Archive), b.ID, pub, Limits{MaxFiles: 1, MaxTotalBytes: 1 << 20}); err == nil {
		t.Fatal("file limit not enforced")
	}
	if _, err := Read(bytes.NewReader(b.Archive), b.ID, pub, Limits{MaxFiles: 10, MaxTotalBytes: 10}); err == nil {
		t.Fatal("size limit not enforced")
	}
	if _, err := Read(bytes.NewReader(b.Archive[:len(b.Archive)/2]), b.ID, pub, Limits{}); err == nil {
		t.Fatal("truncated archive accepted")
	}
	if _, err := Build(Manifest{}, map[string][]byte{"../evil": nil}, priv); err == nil {
		t.Fatal("path traversal accepted")
	}
}

func TestOnlyAllowedPaths(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	for _, p := range []string{"datasets/x.so", "rules/evil.so", "config/other.yaml", "rules/datasets/0123", "rules/datasets/" + strings.Repeat("a", 32) + "/x"} {
		if _, err := Build(Manifest{}, map[string][]byte{p: []byte("x")}, priv); err == nil {
			t.Errorf("path %q accepted", p)
		}
	}
	if _, err := Build(Manifest{}, map[string][]byte{"rules/datasets/" + strings.Repeat("a", 32): []byte("x")}, priv); err != nil {
		t.Fatal(err)
	}
}

func TestReadRejectsOversizedEntries(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	var buf bytes.Buffer
	zw, _ := zstd.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	tw.WriteHeader(&tar.Header{Name: PathRules, Mode: 0o644, Size: 1, Typeflag: tar.TypeReg})
	tw.Write([]byte("x"))
	// A huge declared size must be rejected before reading.
	tw.WriteHeader(&tar.Header{Name: PathReference, Mode: 0o644, Size: 1 << 40, Typeflag: tar.TypeReg})
	tw.Flush()
	zw.Close()
	if _, err := Read(bytes.NewReader(buf.Bytes()), "", pub, Limits{MaxFiles: 10, MaxTotalBytes: 1 << 20}); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("err = %v", err)
	}
}
