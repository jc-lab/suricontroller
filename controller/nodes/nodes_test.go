package nodes

import (
	"context"
	"errors"
	"testing"

	"github.com/jc-lab/suricontroller/controller/store"
	"github.com/jc-lab/suricontroller/controller/store/sqlite"
	"github.com/jc-lab/suricontroller/pkg/sshkey"
)

// sharedStore answers key lookups itself, like a store shared with another
// program.
type sharedStore struct {
	*sqlite.Store
	lookups int
}

func (s *sharedStore) LookupNodeByX25519(ctx context.Context, key []byte) (string, bool, error) {
	s.lookups++
	ns, err := s.ListNodes(ctx)
	if err != nil {
		return "", false, err
	}
	for _, n := range ns {
		pk, err := sshkey.ParsePublicKey(n.PublicKey)
		if err != nil {
			continue
		}
		if x, _ := pk.X25519(); string(x) == string(key) {
			return n.ID, n.Enabled, nil
		}
	}
	return "", false, store.ErrNotFound
}

func openSQLite(t *testing.T) *sqlite.Store {
	t.Helper()
	st, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func newKey(t *testing.T, id string) (*sshkey.PrivateKey, []byte, string) {
	t.Helper()
	k, err := sshkey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	x, err := k.Public(id).X25519()
	if err != nil {
		t.Fatal(err)
	}
	return k, x, k.Public(id).String()
}

func TestIndexModeWithSQLite(t *testing.T) {
	ctx := context.Background()
	svc, err := New(ctx, openSQLite(t))
	if err != nil {
		t.Fatal(err)
	}
	if svc.Delegated() {
		t.Fatal("sqlite store must use the in-memory index")
	}
	_, x, line := newKey(t, "router-01")
	if _, _, err := svc.LookupNodeByX25519(ctx, x); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("lookup before add: %v", err)
	}
	if _, err := svc.Add(ctx, line, ""); err != nil {
		t.Fatal(err)
	}
	id, enabled, err := svc.LookupNodeByX25519(ctx, x)
	if err != nil || id != "router-01" || !enabled {
		t.Fatalf("lookup = %q %v %v", id, enabled, err)
	}
	off := false
	if _, err := svc.Update(ctx, "router-01", &off, nil); err != nil {
		t.Fatal(err)
	}
	if _, enabled, _ := svc.LookupNodeByX25519(ctx, x); enabled {
		t.Fatal("index not updated after disable")
	}
	if _, err := svc.Add(ctx, line, ""); !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("duplicate add: %v", err)
	}
}

func TestDelegatedModeSeesExternalChanges(t *testing.T) {
	ctx := context.Background()
	st := &sharedStore{Store: openSQLite(t)}
	svc, err := New(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	if !svc.Delegated() {
		t.Fatal("store implementing lookups must be used directly")
	}
	_, x, line := newKey(t, "router-02")
	pk, _ := sshkey.ParsePublicKey(line)
	// Another program registers the node directly in the shared store.
	if err := st.CreateNode(ctx, &store.Node{ID: "router-02", PublicKey: line, Fingerprint: pk.Fingerprint(), Enabled: true}); err != nil {
		t.Fatal(err)
	}
	id, enabled, err := svc.LookupNodeByX25519(ctx, x)
	if err != nil || id != "router-02" || !enabled {
		t.Fatalf("lookup = %q %v %v", id, enabled, err)
	}
	// ...and disables it.
	if _, err := st.UpdateNode(ctx, "router-02", func(n *store.Node) error { n.Enabled = false; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, enabled, _ := svc.LookupNodeByX25519(ctx, x); enabled {
		t.Fatal("external disable not visible")
	}
	if _, err := svc.Add(ctx, line, ""); !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("duplicate add: %v", err)
	}
}
