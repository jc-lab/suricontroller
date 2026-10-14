package ruleset

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestET compares Process with suricata-update on the full ET Open ruleset.
// It is opt-in: set RULESET_ET_DIR to a directory holding
// emerging.rules.tar.gz and the golden outputs generated for it by
// "testdata/gen-golden.sh --et DIR".
func TestET(t *testing.T) {
	dir := os.Getenv("RULESET_ET_DIR")
	if dir == "" {
		t.Skip("RULESET_ET_DIR not set")
	}
	files := loadTarGz(t, filepath.Join(dir, "emerging.rules.tar.gz"))
	cases, err := os.ReadDir("testdata/et-cases")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		if !c.IsDir() {
			continue
		}
		t.Run(c.Name(), func(t *testing.T) {
			compareGolden(t, files, confFromDir(t, filepath.Join("testdata/et-cases", c.Name())),
				filepath.Join(dir, "golden", c.Name()))
		})
	}
}

// loadTarGz reads the regular files of a (gzipped) tarball the way
// suricata-update's extract_tar does.
func loadTarGz(t *testing.T, path string) []SourceFile {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(zr)
	byName := map[string]int{}
	var files []SourceFile
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		name := strings.TrimLeft(h.Name, "/")
		if i, ok := byName[name]; ok {
			files[i].Content = data
			continue
		}
		byName[name] = len(files)
		files = append(files, SourceFile{Name: name, Content: data})
	}
	return files
}
