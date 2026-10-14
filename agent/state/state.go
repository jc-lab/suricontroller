// Package state persists what the agent applied, so it can restore the
// last known good configuration at boot without the controller.
//
// Layout under the state directory:
//
//	state.json            applied state and log policy
//	bundles/{id}.tar.zst  downloaded bundles
//	releases/{id}/        extracted bundles
//	active -> releases/{id}  stable path used by running instances
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"

	"google.golang.org/protobuf/encoding/protojson"

	agentv1 "github.com/jc-lab/suricontroller/gen/suricontroller/agent/v1"
)

// State is the persisted agent state.
type State struct {
	Applied   *agentv1.AppliedState
	LogPolicy *agentv1.LogCollectionPolicy
}

type stateFile struct {
	Applied   json.RawMessage `json:"applied,omitempty"`
	LogPolicy json.RawMessage `json:"log_policy,omitempty"`
}

// Store manages the state directory.
type Store struct {
	dir string
	mu  sync.Mutex
}

// Open prepares the state directory.
func Open(dir string) (*Store, error) {
	// The active symlink target must be absolute.
	dir, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	for _, d := range []string{dir, filepath.Join(dir, "bundles"), filepath.Join(dir, "releases"), filepath.Join(dir, "empty")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, err
		}
	}
	return &Store{dir: dir}, nil
}

// Dir returns the state directory.
func (s *Store) Dir() string { return s.dir }

// Load reads state.json; a missing file yields an empty state.
func (s *Store) Load() (*State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := os.ReadFile(filepath.Join(s.dir, "state.json"))
	if errors.Is(err, os.ErrNotExist) {
		return &State{}, nil
	}
	if err != nil {
		return nil, err
	}
	var f stateFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("state: %w", err)
	}
	st := &State{}
	opts := protojson.UnmarshalOptions{DiscardUnknown: true}
	if len(f.Applied) > 0 {
		st.Applied = &agentv1.AppliedState{}
		if err := opts.Unmarshal(f.Applied, st.Applied); err != nil {
			return nil, err
		}
	}
	if len(f.LogPolicy) > 0 {
		st.LogPolicy = &agentv1.LogCollectionPolicy{}
		if err := opts.Unmarshal(f.LogPolicy, st.LogPolicy); err != nil {
			return nil, err
		}
	}
	return st, nil
}

// Save writes state.json atomically.
func (s *Store) Save(st *State) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var f stateFile
	var err error
	if st.Applied != nil {
		if f.Applied, err = protojson.Marshal(st.Applied); err != nil {
			return err
		}
	}
	if st.LogPolicy != nil {
		if f.LogPolicy, err = protojson.Marshal(st.LogPolicy); err != nil {
			return err
		}
	}
	b, err := json.MarshalIndent(&f, "", "  ")
	if err != nil {
		return err
	}
	return WriteFileAtomic(filepath.Join(s.dir, "state.json"), b, 0o600)
}

// WriteFileAtomic writes via a temporary file and rename.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

var idRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ValidID reports whether id is a well-formed bundle id (hex sha256). Ids
// come from the controller and are used in paths, so they must be checked
// before use.
func ValidID(id string) bool { return idRe.MatchString(id) }

// BundlePath is where a downloaded bundle is stored.
func (s *Store) BundlePath(id string) string {
	return filepath.Join(s.dir, "bundles", id+".tar.zst")
}

// ReleaseDir is where a bundle is extracted.
func (s *Store) ReleaseDir(id string) string {
	return filepath.Join(s.dir, "releases", id)
}

// HasRelease reports whether a bundle was extracted.
func (s *Store) HasRelease(id string) bool {
	if !ValidID(id) {
		return false
	}
	fi, err := os.Stat(s.ReleaseDir(id))
	return err == nil && fi.IsDir()
}

// ActiveDir is the stable path of the active release.
func (s *Store) ActiveDir() string { return filepath.Join(s.dir, "active") }

// ActiveID returns the id of the active release, or "".
func (s *Store) ActiveID() string {
	target, err := os.Readlink(s.ActiveDir())
	if err != nil {
		return ""
	}
	if filepath.Base(filepath.Dir(target)) != "releases" {
		return ""
	}
	return filepath.Base(target)
}

// Activate atomically points the active link at a release ("" = an empty
// directory).
func (s *Store) Activate(id string) error {
	target := filepath.Join(s.dir, "empty")
	if id != "" {
		if !ValidID(id) || !s.HasRelease(id) {
			return fmt.Errorf("state: release %s does not exist", id)
		}
		target = s.ReleaseDir(id)
	}
	tmp := s.ActiveDir() + ".tmp"
	_ = os.Remove(tmp)
	if err := os.Symlink(target, tmp); err != nil {
		return err
	}
	return os.Rename(tmp, s.ActiveDir())
}

// Prune removes bundles and releases not listed in keep.
func (s *Store) Prune(keep ...string) {
	k := map[string]bool{}
	for _, id := range keep {
		if id != "" {
			k[id] = true
		}
	}
	if entries, err := os.ReadDir(filepath.Join(s.dir, "releases")); err == nil {
		for _, e := range entries {
			if !k[e.Name()] {
				_ = os.RemoveAll(filepath.Join(s.dir, "releases", e.Name()))
			}
		}
	}
	if entries, err := os.ReadDir(filepath.Join(s.dir, "bundles")); err == nil {
		for _, e := range entries {
			id := e.Name()
			if ext := filepath.Ext(id); ext == ".part" {
				continue
			}
			if len(id) > len(".tar.zst") && !k[id[:len(id)-len(".tar.zst")]] {
				_ = os.Remove(filepath.Join(s.dir, "bundles", id))
			}
		}
	}
}

// Releases lists extracted release ids, sorted by modification time (oldest
// first).
func (s *Store) Releases() []string {
	entries, err := os.ReadDir(filepath.Join(s.dir, "releases"))
	if err != nil {
		return nil
	}
	type rel struct {
		id  string
		mod int64
	}
	var rels []rel
	for _, e := range entries {
		if fi, err := e.Info(); err == nil && e.IsDir() {
			rels = append(rels, rel{e.Name(), fi.ModTime().UnixNano()})
		}
	}
	sort.Slice(rels, func(i, j int) bool { return rels[i].mod < rels[j].mod })
	out := make([]string, len(rels))
	for i, r := range rels {
		out[i] = r.id
	}
	return out
}
