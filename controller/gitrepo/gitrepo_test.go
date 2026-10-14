package gitrepo

import (
	"errors"
	"os/exec"
	"strings"
	"sync"
	"testing"
)

var bot = Signature{Name: "tester", Email: "t@example.com"}

func TestCommitReadAndConflicts(t *testing.T) {
	g, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if h, _ := g.Head(); h != "" {
		t.Fatalf("empty repo head = %q", h)
	}
	if logs, err := g.Log("", 10, ""); err != nil || len(logs) != 0 {
		t.Fatalf("empty log = %v %v", logs, err)
	}

	c1, err := g.Commit("", []Change{
		{Path: "common/disable.conf", Content: []byte("1:100\n")},
		{Path: "common/suricata.yaml", Content: []byte("vars: {}\n")},
		{Path: "nodes/router-01/enable.conf", Content: []byte("1:200\n")},
	}, "initial", bot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.Commit("", []Change{{Path: "common/disable.conf", Content: []byte("1:100\n")}}, "noop", bot); !errors.Is(err, ErrNoChanges) {
		t.Fatalf("noop commit: %v", err)
	}
	c2, err := g.Commit(c1, []Change{
		{Path: "common/disable.conf", Content: []byte("1:100\n1:101\n")},
		{Path: "nodes/router-01/enable.conf", Delete: true},
	}, "second", bot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.Commit(c1, []Change{{Path: "x", Content: []byte("y")}}, "stale", bot); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale base: %v", err)
	}

	b, err := g.ReadFile(c1, "common/disable.conf")
	if err != nil || string(b) != "1:100\n" {
		t.Fatalf("read c1: %q %v", b, err)
	}
	b, err = g.ReadFile("", "common/disable.conf")
	if err != nil || string(b) != "1:100\n1:101\n" {
		t.Fatalf("read head: %q %v", b, err)
	}
	if _, err := g.ReadFile(c2, "nodes/router-01/enable.conf"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted file: %v", err)
	}
	entries, err := g.ListTree(c2, "", false)
	if err != nil {
		t.Fatal(err)
	}
	// nodes/router-01 became empty and must be pruned.
	if len(entries) != 1 || entries[0].Path != "common" || !entries[0].Dir {
		t.Fatalf("root entries = %+v", entries)
	}
	all, _ := g.ListTree(c1, "", true)
	if len(all) != 3 {
		t.Fatalf("recursive = %+v", all)
	}

	logs, err := g.Log("", 10, "")
	if err != nil || len(logs) != 2 || logs[0].ID != c2 || logs[1].ID != c1 || logs[0].Author != "tester" {
		t.Fatalf("log = %+v %v", logs, err)
	}
	logs, _ = g.Log("", 10, "nodes")
	if len(logs) != 2 {
		t.Fatalf("path log = %+v", logs)
	}
	short, err := g.Resolve(c1[:8])
	if err != nil || short != c1 {
		t.Fatalf("resolve short: %v %v", short, err)
	}
	if ok, _ := g.IsAncestor(c1, c2); !ok {
		t.Fatal("c1 should be ancestor of c2")
	}
	if ok, _ := g.IsAncestor(c2, c1); ok {
		t.Fatal("c2 is not ancestor of c1")
	}

	info, stats, err := g.GetCommit(c2)
	if err != nil || info.Message != "second" || len(stats) != 2 {
		t.Fatalf("get commit = %+v %+v %v", info, stats, err)
	}
	diff, _, truncated, err := g.Diff("", c2, "common", 0)
	if err != nil || truncated || !strings.Contains(diff, "+1:101") || strings.Contains(diff, "enable.conf") {
		t.Fatalf("diff = %q %v", diff, err)
	}
}

func TestInvalidPaths(t *testing.T) {
	g, _ := Open(t.TempDir())
	for _, p := range []string{"../x", "/abs", "a//b", "a/./b", ".git/config", "a/.GIT/x", "", "a\\b"} {
		if _, err := g.Commit("", []Change{{Path: p, Content: []byte("x")}}, "bad", bot); !errors.Is(err, ErrInvalidPath) {
			t.Errorf("%q: err = %v", p, err)
		}
	}
}

func TestReplaceDirAndRepack(t *testing.T) {
	dir := t.TempDir()
	g, _ := Open(dir)
	_, err := g.ReplaceDir("et-open", map[string][]byte{"a.rules": []byte("a"), "b.rules": []byte("b")}, "sync 1", bot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.Commit("", []Change{{Path: "local/local.rules", Content: []byte("l")}}, "local", bot); err != nil {
		t.Fatal(err)
	}
	if _, err := g.ReplaceDir("et-open", map[string][]byte{"a.rules": []byte("a"), "b.rules": []byte("b")}, "sync 2", bot); !errors.Is(err, ErrNoChanges) {
		t.Fatalf("unchanged sync: %v", err)
	}
	c3, err := g.ReplaceDir("et-open", map[string][]byte{"a.rules": []byte("a2"), "c.rules": []byte("c")}, "sync 3", bot)
	if err != nil {
		t.Fatal(err)
	}
	files, err := g.ReadDir(c3, "et-open")
	if err != nil || len(files) != 2 || string(files["a.rules"]) != "a2" || string(files["c.rules"]) != "c" {
		t.Fatalf("files = %v %v", files, err)
	}
	if b, _ := g.ReadFile(c3, "local/local.rules"); string(b) != "l" {
		t.Fatal("other provider dir changed")
	}
	if err := g.Repack(); err != nil {
		t.Fatal(err)
	}
	g2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if b, err := g2.ReadFile("", "et-open/a.rules"); err != nil || string(b) != "a2" {
		t.Fatalf("after repack: %q %v", b, err)
	}
	if logs, _ := g2.Log("", 10, ""); len(logs) != 3 {
		t.Fatalf("history after repack: %d", len(logs))
	}
}

func TestGitFsck(t *testing.T) {
	gitBin, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	g, _ := Open(dir)
	// Names chosen so that git's "directory sorts with trailing slash" rule matters.
	if _, err := g.Commit("", []Change{
		{Path: "a.b", Content: []byte("1")},
		{Path: "a/x", Content: []byte("2")},
		{Path: "a-b", Content: []byte("3")},
		{Path: "a0", Content: []byte("4")},
	}, "c1", bot); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Commit("", []Change{{Path: "a/y/z", Content: []byte("5")}}, "c2", bot); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(gitBin, "--git-dir", dir, "fsck", "--strict").CombinedOutput()
	if err != nil {
		t.Fatalf("git fsck: %v\n%s", err, out)
	}
	out, err = exec.Command(gitBin, "--git-dir", dir, "show", "HEAD:a/y/z").CombinedOutput()
	if err != nil || string(out) != "5" {
		t.Fatalf("git show: %v %q", err, out)
	}
}

func TestRepackKeepsRepoUsable(t *testing.T) {
	dir := t.TempDir()
	g, _ := Open(dir)
	for i := range 3 {
		if _, err := g.Commit("", []Change{{Path: "a/f.rules", Content: []byte(strings.Repeat("x", i+1))}}, "c", bot); err != nil {
			t.Fatal(err)
		}
		// Two repacks in a row: the second one deletes the pack the first
		// created, which used to leave a stale in-memory index.
		if err := g.Repack(); err != nil {
			t.Fatalf("repack %d: %v", i, err)
		}
		if err := g.Repack(); err != nil {
			t.Fatalf("second repack %d: %v", i, err)
		}
		for range 20 {
			if _, err := g.ReadDir("", "a"); err != nil {
				t.Fatalf("read after repack: %v", err)
			}
		}
	}
	if logs, err := g.Log("", 10, ""); err != nil || len(logs) != 3 {
		t.Fatalf("log after repack: %d %v", len(logs), err)
	}
}

func TestDeleteLastFileAndDirConflicts(t *testing.T) {
	g, _ := Open(t.TempDir())
	if _, err := g.Commit("", []Change{{Path: "local/a.rules", Content: []byte("a")}}, "add", bot); err != nil {
		t.Fatal(err)
	}
	empty, err := g.Commit("", []Change{{Path: "local/a.rules", Delete: true}}, "delete", bot)
	if err != nil {
		t.Fatal(err)
	}
	if entries, err := g.ListTree(empty, "", true); err != nil || len(entries) != 0 {
		t.Fatalf("empty tree: %v %v", entries, err)
	}
	if err := g.Repack(); err != nil {
		t.Fatalf("repack with empty tree: %v", err)
	}
	if _, err := g.Commit("", []Change{{Path: "local/b.rules", Content: []byte("b")}}, "add again", bot); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Commit("", []Change{{Path: "local", Content: []byte("x")}}, "file over dir", bot); !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("file over dir: %v", err)
	}
}

func TestConcurrentReads(t *testing.T) {
	dir := t.TempDir()
	g, _ := Open(dir)
	g.Commit("", []Change{{Path: "a/x", Content: []byte("1")}, {Path: "b/y", Content: []byte("2")}}, "c", bot)
	g.Repack()
	g2, _ := Open(dir)
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 20 {
				if _, err := g2.ReadDir("", "a"); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
}
