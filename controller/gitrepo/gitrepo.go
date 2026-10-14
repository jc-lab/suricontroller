// Package gitrepo wraps a bare go-git repository with a single branch.
//
// Writes never use a worktree: a commit is built by applying a change set to
// the tree of a base commit and the branch is moved with compare-and-swap.
// All operations are serialized: go-git's object storage builds its pack
// index lazily and is not safe for concurrent use.
package gitrepo

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/storer"
	"github.com/go-git/go-git/v5/storage"
)

// Branch is the only branch used.
const Branch = plumbing.ReferenceName("refs/heads/main")

var (
	// ErrConflict means the branch moved since the given base commit.
	ErrConflict = errors.New("gitrepo: branch moved since base commit")
	// ErrNoChanges means a commit would not change the tree.
	ErrNoChanges = errors.New("gitrepo: no changes")
	// ErrNotFound means a commit, path or file does not exist.
	ErrNotFound = errors.New("gitrepo: not found")
	// ErrInvalidPath means a path is not acceptable in the repository.
	ErrInvalidPath = errors.New("gitrepo: invalid path")
)

// Signature identifies a commit author.
type Signature struct {
	Name  string
	Email string
}

// Change is one file modification.
type Change struct {
	Path    string
	Content []byte
	Delete  bool
}

// CommitInfo describes a commit.
type CommitInfo struct {
	ID      string
	Message string
	Author  string
	Email   string
	Time    time.Time
	Parents []string
}

// TreeEntry is a file or directory in a tree.
type TreeEntry struct {
	Path string
	Dir  bool
	Size int64
}

// FileStat summarizes the change of one file between two commits.
type FileStat struct {
	Path      string
	Action    string // added | modified | deleted
	Additions int
	Deletions int
}

// Repo is a bare repository.
type Repo struct {
	mu  sync.Mutex
	dir string
	r   *git.Repository
}

// Open opens the bare repository at dir, initializing it if needed.
func Open(dir string) (*Repo, error) {
	r, err := git.PlainOpen(dir)
	if errors.Is(err, git.ErrRepositoryNotExists) {
		r, err = git.PlainInit(dir, true)
		if err != nil {
			return nil, err
		}
		if err := r.Storer.SetReference(plumbing.NewSymbolicReference(plumbing.HEAD, Branch)); err != nil {
			return nil, err
		}
	}
	if err != nil {
		return nil, err
	}
	return &Repo{dir: dir, r: r}, nil
}

// CleanPath validates and normalizes a repository path.
func CleanPath(p string) (string, error) {
	if p == "" || strings.ContainsRune(p, 0) || strings.Contains(p, "\\") {
		return "", ErrInvalidPath
	}
	if strings.HasPrefix(p, "/") {
		return "", ErrInvalidPath
	}
	c := path.Clean(p)
	if c != p && c+"/" != p {
		return "", ErrInvalidPath
	}
	for _, part := range strings.Split(c, "/") {
		if part == "" || part == "." || part == ".." || strings.EqualFold(part, ".git") {
			return "", ErrInvalidPath
		}
	}
	return c, nil
}

// Head returns the branch head, or "" for an empty repository.
func (g *Repo) Head() (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	h, err := g.head()
	if err != nil || h.IsZero() {
		return "", err
	}
	return h.String(), nil
}

func (g *Repo) head() (plumbing.Hash, error) {
	ref, err := g.r.Storer.Reference(Branch)
	if errors.Is(err, plumbing.ErrReferenceNotFound) {
		return plumbing.ZeroHash, nil
	}
	if err != nil {
		return plumbing.ZeroHash, err
	}
	return ref.Hash(), nil
}

// Resolve resolves a full or abbreviated commit id; "" or "HEAD" resolves to
// the branch head.
func (g *Repo) Resolve(rev string) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	c, err := g.commit(rev)
	if err != nil {
		return "", err
	}
	return c.Hash.String(), nil
}

func (g *Repo) commit(rev string) (*object.Commit, error) {
	var h plumbing.Hash
	if rev == "" || rev == "HEAD" {
		hh, err := g.head()
		if err != nil {
			return nil, err
		}
		if hh.IsZero() {
			return nil, ErrNotFound
		}
		h = hh
	} else {
		if len(rev) < 4 || len(rev) > 40 || strings.Trim(strings.ToLower(rev), "0123456789abcdef") != "" {
			return nil, ErrNotFound
		}
		if len(rev) == 40 {
			h = plumbing.NewHash(rev)
		} else {
			ph, err := g.r.ResolveRevision(plumbing.Revision(rev))
			if err != nil {
				return nil, ErrNotFound
			}
			h = *ph
		}
	}
	c, err := g.r.CommitObject(h)
	if errors.Is(err, plumbing.ErrObjectNotFound) {
		return nil, ErrNotFound
	}
	return c, err
}

// Commit applies changes on top of base and moves the branch. An empty base
// means the current head (no conflict check). It returns ErrConflict if base
// is not the current head and ErrNoChanges if the tree would not change.
func (g *Repo) Commit(base string, changes []Change, msg string, author Signature) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	head, parentTree, err := g.prepare(base)
	if err != nil {
		return "", err
	}
	ops := map[string]*Change{}
	for i := range changes {
		c := &changes[i]
		p, err := CleanPath(c.Path)
		if err != nil {
			return "", fmt.Errorf("%w: %q", ErrInvalidPath, c.Path)
		}
		ops[p] = c
	}
	newTree, err := g.applyTree(parentTree, ops)
	if err != nil {
		return "", err
	}
	return g.finishCommit(head, parentTree, newTree, msg, author)
}

// ReplaceDir makes dir contain exactly files (paths relative to dir), in a
// commit on top of the current head. It returns ErrNoChanges if dir already
// matches.
func (g *Repo) ReplaceDir(dir string, files map[string][]byte, msg string, author Signature) (string, error) {
	dir, err := CleanPath(dir)
	if err != nil {
		return "", err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	head, parentTree, err := g.prepare("")
	if err != nil {
		return "", err
	}
	ops := map[string]*Change{}
	// Delete files that disappeared.
	if !parentTree.IsZero() {
		t, err := g.r.TreeObject(parentTree)
		if err != nil {
			return "", err
		}
		if sub, err := t.Tree(dir); err == nil {
			err := sub.Files().ForEach(func(f *object.File) error {
				if _, ok := files[f.Name]; !ok {
					ops[dir+"/"+f.Name] = &Change{Delete: true}
				}
				return nil
			})
			if err != nil {
				return "", err
			}
		}
	}
	for name, content := range files {
		p, err := CleanPath(dir + "/" + name)
		if err != nil {
			return "", fmt.Errorf("%w: %q", ErrInvalidPath, name)
		}
		ops[p] = &Change{Content: content}
	}
	newTree, err := g.applyTree(parentTree, ops)
	if err != nil {
		return "", err
	}
	return g.finishCommit(head, parentTree, newTree, msg, author)
}

func (g *Repo) prepare(base string) (head, tree plumbing.Hash, err error) {
	head, err = g.head()
	if err != nil {
		return
	}
	if base != "" && base != head.String() {
		err = ErrConflict
		return
	}
	if !head.IsZero() {
		var c *object.Commit
		if c, err = g.r.CommitObject(head); err != nil {
			return
		}
		tree = c.TreeHash
	}
	return
}

func (g *Repo) finishCommit(head, parentTree, newTree plumbing.Hash, msg string, author Signature) (string, error) {
	if newTree.IsZero() {
		// Every file was deleted: commit git's canonical empty tree.
		obj := g.r.Storer.NewEncodedObject()
		if err := (&object.Tree{}).Encode(obj); err != nil {
			return "", err
		}
		h, err := g.r.Storer.SetEncodedObject(obj)
		if err != nil {
			return "", err
		}
		newTree = h
	}
	if newTree == parentTree {
		return "", ErrNoChanges
	}
	if author.Name == "" {
		author.Name = "suricontroller"
	}
	if author.Email == "" {
		author.Email = "suricontroller@localhost"
	}
	sig := object.Signature{Name: author.Name, Email: author.Email, When: time.Now()}
	c := &object.Commit{Author: sig, Committer: sig, Message: msg, TreeHash: newTree}
	if !head.IsZero() {
		c.ParentHashes = []plumbing.Hash{head}
	}
	obj := g.r.Storer.NewEncodedObject()
	if err := c.Encode(obj); err != nil {
		return "", err
	}
	h, err := g.r.Storer.SetEncodedObject(obj)
	if err != nil {
		return "", err
	}
	var old *plumbing.Reference
	if !head.IsZero() {
		old = plumbing.NewHashReference(Branch, head)
	}
	if err := g.r.Storer.CheckAndSetReference(plumbing.NewHashReference(Branch, h), old); err != nil {
		if errors.Is(err, storage.ErrReferenceHasChanged) {
			return "", ErrConflict
		}
		return "", err
	}
	return h.String(), nil
}

// applyTree returns the hash of the tree obtained by applying ops (keyed by
// path relative to this tree) to the tree base (zero for empty). The zero
// hash is returned when the result is empty.
func (g *Repo) applyTree(base plumbing.Hash, ops map[string]*Change) (plumbing.Hash, error) {
	entries := map[string]object.TreeEntry{}
	if !base.IsZero() {
		t, err := g.r.TreeObject(base)
		if err != nil {
			return plumbing.ZeroHash, err
		}
		for _, e := range t.Entries {
			entries[e.Name] = e
		}
	}
	// Group operations by their first path component.
	direct := map[string]*Change{}
	nested := map[string]map[string]*Change{}
	for p, c := range ops {
		first, rest, ok := strings.Cut(p, "/")
		if !ok {
			direct[first] = c
			continue
		}
		if nested[first] == nil {
			nested[first] = map[string]*Change{}
		}
		nested[first][rest] = c
	}
	for name, c := range direct {
		if c.Delete {
			if e, ok := entries[name]; ok && e.Mode != filemode.Dir {
				delete(entries, name)
			}
			continue
		}
		if e, ok := entries[name]; ok && e.Mode == filemode.Dir {
			return plumbing.ZeroHash, fmt.Errorf("%w: %q is a directory", ErrInvalidPath, name)
		}
		h, err := g.writeBlob(c.Content)
		if err != nil {
			return plumbing.ZeroHash, err
		}
		entries[name] = object.TreeEntry{Name: name, Mode: filemode.Regular, Hash: h}
	}
	for name, sub := range nested {
		var subBase plumbing.Hash
		if e, ok := entries[name]; ok {
			if e.Mode != filemode.Dir {
				return plumbing.ZeroHash, fmt.Errorf("%w: %q is a file", ErrInvalidPath, name)
			}
			subBase = e.Hash
		}
		h, err := g.applyTree(subBase, sub)
		if err != nil {
			return plumbing.ZeroHash, err
		}
		if h.IsZero() {
			delete(entries, name)
		} else {
			entries[name] = object.TreeEntry{Name: name, Mode: filemode.Dir, Hash: h}
		}
	}
	if len(entries) == 0 {
		return plumbing.ZeroHash, nil
	}
	t := &object.Tree{}
	for _, e := range entries {
		t.Entries = append(t.Entries, e)
	}
	sort.Sort(object.TreeEntrySorter(t.Entries))
	obj := g.r.Storer.NewEncodedObject()
	if err := t.Encode(obj); err != nil {
		return plumbing.ZeroHash, err
	}
	return g.r.Storer.SetEncodedObject(obj)
}

func (g *Repo) writeBlob(content []byte) (plumbing.Hash, error) {
	obj := g.r.Storer.NewEncodedObject()
	obj.SetType(plumbing.BlobObject)
	obj.SetSize(int64(len(content)))
	w, err := obj.Writer()
	if err != nil {
		return plumbing.ZeroHash, err
	}
	if _, err := w.Write(content); err != nil {
		w.Close()
		return plumbing.ZeroHash, err
	}
	if err := w.Close(); err != nil {
		return plumbing.ZeroHash, err
	}
	return g.r.Storer.SetEncodedObject(obj)
}

// ReadFile returns the content of a file at a commit.
func (g *Repo) ReadFile(rev, p string) ([]byte, error) {
	p, err := CleanPath(p)
	if err != nil {
		return nil, err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	c, err := g.commit(rev)
	if err != nil {
		return nil, err
	}
	f, err := c.File(p)
	if err != nil {
		return nil, ErrNotFound
	}
	r, err := f.Reader()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

// ListTree lists the entries under dir ("" for the root) at a commit.
func (g *Repo) ListTree(rev, dir string, recursive bool) ([]TreeEntry, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	c, err := g.commit(rev)
	if err != nil {
		return nil, err
	}
	t, err := c.Tree()
	if err != nil {
		return nil, err
	}
	prefix := ""
	if dir != "" {
		if dir, err = CleanPath(dir); err != nil {
			return nil, err
		}
		if t, err = t.Tree(dir); err != nil {
			return nil, ErrNotFound
		}
		prefix = dir + "/"
	}
	var out []TreeEntry
	if !recursive {
		for _, e := range t.Entries {
			te := TreeEntry{Path: prefix + e.Name, Dir: e.Mode == filemode.Dir}
			if !te.Dir {
				if sz, err := g.r.Storer.EncodedObjectSize(e.Hash); err == nil {
					te.Size = sz
				}
			}
			out = append(out, te)
		}
		return out, nil
	}
	err = t.Files().ForEach(func(f *object.File) error {
		out = append(out, TreeEntry{Path: prefix + f.Name, Size: f.Size})
		return nil
	})
	return out, err
}

// ReadDir returns all files under dir at a commit, keyed by path relative to
// dir. A missing dir yields an empty map.
func (g *Repo) ReadDir(rev, dir string) (map[string][]byte, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	c, err := g.commit(rev)
	if err != nil {
		return nil, err
	}
	t, err := c.Tree()
	if err != nil {
		return nil, err
	}
	out := map[string][]byte{}
	if dir != "" {
		if dir, err = CleanPath(dir); err != nil {
			return nil, err
		}
		if t, err = t.Tree(dir); err != nil {
			return out, nil
		}
	}
	err = t.Files().ForEach(func(f *object.File) error {
		r, err := f.Reader()
		if err != nil {
			return err
		}
		defer r.Close()
		b, err := io.ReadAll(r)
		if err != nil {
			return err
		}
		out[f.Name] = b
		return nil
	})
	return out, err
}

func toInfo(c *object.Commit) CommitInfo {
	info := CommitInfo{
		ID:      c.Hash.String(),
		Message: c.Message,
		Author:  c.Author.Name,
		Email:   c.Author.Email,
		Time:    c.Author.When,
	}
	for _, p := range c.ParentHashes {
		info.Parents = append(info.Parents, p.String())
	}
	return info
}

// Log lists up to limit commits starting at from ("" = head), optionally
// restricted to commits touching pathPrefix.
func (g *Repo) Log(from string, limit int, pathPrefix string) ([]CommitInfo, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	start, err := g.commit(from)
	if errors.Is(err, ErrNotFound) && (from == "" || from == "HEAD") {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 50
	}
	opts := &git.LogOptions{From: start.Hash, Order: git.LogOrderCommitterTime}
	if pathPrefix != "" {
		pathPrefix = strings.TrimSuffix(pathPrefix, "/")
		opts.PathFilter = func(p string) bool { return p == pathPrefix || strings.HasPrefix(p, pathPrefix+"/") }
	}
	it, err := g.r.Log(opts)
	if err != nil {
		return nil, err
	}
	defer it.Close()
	var out []CommitInfo
	err = it.ForEach(func(c *object.Commit) error {
		out = append(out, toInfo(c))
		if len(out) >= limit {
			return storer.ErrStop
		}
		return nil
	})
	return out, err
}

// IsAncestor reports whether commit a is an ancestor of (or equal to) b.
func (g *Repo) IsAncestor(a, b string) (bool, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	ca, err := g.commit(a)
	if err != nil {
		return false, err
	}
	cb, err := g.commit(b)
	if err != nil {
		return false, err
	}
	if ca.Hash == cb.Hash {
		return true, nil
	}
	return ca.IsAncestor(cb)
}

// GetCommit returns a commit and the files it changed relative to its first
// parent.
func (g *Repo) GetCommit(rev string) (*CommitInfo, []FileStat, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	c, err := g.commit(rev)
	if err != nil {
		return nil, nil, err
	}
	var parent *object.Commit
	if len(c.ParentHashes) > 0 {
		if parent, err = g.r.CommitObject(c.ParentHashes[0]); err != nil {
			return nil, nil, err
		}
	}
	_, stats, err := g.diff(parent, c, "", 0)
	if err != nil {
		return nil, nil, err
	}
	info := toInfo(c)
	return &info, stats, nil
}

// Diff returns a unified diff between two commits (from "" = parent of to),
// restricted to pathPrefix, truncated to maxBytes (0 = 4 MiB). The bool
// result reports truncation.
func (g *Repo) Diff(from, to, pathPrefix string, maxBytes int) (string, []FileStat, bool, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	ct, err := g.commit(to)
	if err != nil {
		return "", nil, false, err
	}
	var cf *object.Commit
	if from != "" {
		if cf, err = g.commit(from); err != nil {
			return "", nil, false, err
		}
	} else if len(ct.ParentHashes) > 0 {
		if cf, err = g.r.CommitObject(ct.ParentHashes[0]); err != nil {
			return "", nil, false, err
		}
	}
	if maxBytes <= 0 {
		maxBytes = 4 << 20
	}
	patch, stats, err := g.diff(cf, ct, pathPrefix, maxBytes)
	if err != nil {
		return "", nil, false, err
	}
	truncated := len(patch) > maxBytes
	if truncated {
		patch = patch[:maxBytes]
	}
	return patch, stats, truncated, nil
}

// diff computes the change between two commits (from may be nil). When
// maxBytes is 0 no patch text is produced.
func (g *Repo) diff(from, to *object.Commit, pathPrefix string, maxBytes int) (string, []FileStat, error) {
	var fromTree *object.Tree
	if from != nil {
		t, err := from.Tree()
		if err != nil {
			return "", nil, err
		}
		fromTree = t
	}
	toTree, err := to.Tree()
	if err != nil {
		return "", nil, err
	}
	changes, err := object.DiffTree(fromTree, toTree)
	if err != nil {
		return "", nil, err
	}
	if pathPrefix != "" {
		pathPrefix = strings.TrimSuffix(pathPrefix, "/")
		var filtered object.Changes
		for _, ch := range changes {
			name := changeName(ch)
			if name == pathPrefix || strings.HasPrefix(name, pathPrefix+"/") {
				filtered = append(filtered, ch)
			}
		}
		changes = filtered
	}
	patch, err := changes.Patch()
	if err != nil {
		return "", nil, err
	}
	var stats []FileStat
	for i, st := range patch.Stats() {
		action, _ := changes[i].Action()
		stats = append(stats, FileStat{Path: st.Name, Action: actionName(action), Additions: st.Addition, Deletions: st.Deletion})
	}
	if maxBytes == 0 {
		return "", stats, nil
	}
	var buf bytes.Buffer
	if err := patch.Encode(&limitedWriter{w: &buf, n: maxBytes + 1}); err != nil && !errors.Is(err, errLimit) {
		return "", nil, err
	}
	return buf.String(), stats, nil
}

func changeName(ch *object.Change) string {
	if ch.To.Name != "" {
		return ch.To.Name
	}
	return ch.From.Name
}

func actionName(a interface{ String() string }) string {
	switch a.String() {
	case "Insert":
		return "added"
	case "Delete":
		return "deleted"
	default:
		return "modified"
	}
}

var errLimit = errors.New("limit reached")

type limitedWriter struct {
	w io.Writer
	n int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if l.n <= 0 {
		return 0, errLimit
	}
	if len(p) > l.n {
		p = p[:l.n]
	}
	n, err := l.w.Write(p)
	l.n -= n
	if err == nil && l.n <= 0 {
		err = errLimit
	}
	return n, err
}

// Repack packs all reachable objects. Loose objects left over afterwards
// are unreachable (e.g. written for a commit that turned out to change
// nothing) and are deleted.
func (g *Repo) Repack() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if err := g.r.RepackObjects(&git.RepackConfig{}); err != nil {
		_ = g.reopen()
		return err
	}
	los, ok := g.r.Storer.(storer.LooseObjectStorer)
	if !ok {
		return nil
	}
	var loose []plumbing.Hash
	if err := los.ForEachObjectHash(func(h plumbing.Hash) error {
		loose = append(loose, h)
		return nil
	}); err != nil {
		return err
	}
	for _, h := range loose {
		if err := los.DeleteLooseObject(h); err != nil {
			return err
		}
	}
	return g.reopen()
}

// reopen discards go-git's in-memory pack index, which still references the
// packs a repack deleted. Callers hold mu.
func (g *Repo) reopen() error {
	r, err := git.PlainOpen(g.dir)
	if err != nil {
		return err
	}
	g.r = r
	return nil
}
