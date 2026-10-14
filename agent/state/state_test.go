package state

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	agentv1 "github.com/jc-lab/suricontroller/gen/suricontroller/agent/v1"
)

func TestSaveLoad(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	st, err := s.Load()
	if err != nil || st.Applied != nil {
		t.Fatalf("empty state = %+v %v", st, err)
	}
	want := &State{
		Applied:   &agentv1.AppliedState{Generation: 4, Bundle: &agentv1.BundleRef{BundleId: "abc"}, InterfaceModes: map[string]agentv1.InterfaceMode{"eth0": agentv1.InterfaceMode_INTERFACE_MODE_IPS}},
		LogPolicy: &agentv1.LogCollectionPolicy{Enabled: true},
	}
	if err := s.Save(want); err != nil {
		t.Fatal(err)
	}
	got, err := s.Load()
	if err != nil || got.Applied.Generation != 4 || got.Applied.InterfaceModes["eth0"] != agentv1.InterfaceMode_INTERFACE_MODE_IPS || !got.LogPolicy.Enabled {
		t.Fatalf("got %+v %v", got, err)
	}
}

func TestActivateAndPrune(t *testing.T) {
	s, _ := Open(t.TempDir())
	id := func(c string) string { return strings.Repeat(c, 64) }
	a, b, c := id("a"), id("b"), id("c")
	if s.ActiveID() != "" {
		t.Fatal("active before activate")
	}
	if err := s.Activate("missing"); err == nil {
		t.Fatal("activating a missing release must fail")
	}
	for _, id := range []string{a, b, c} {
		os.MkdirAll(filepath.Join(s.ReleaseDir(id), "rules"), 0o755)
		os.WriteFile(filepath.Join(s.ReleaseDir(id), "rules", "suricata.rules"), []byte(id), 0o644)
		os.WriteFile(s.BundlePath(id), []byte(id), 0o644)
	}
	if err := s.Activate(a); err != nil {
		t.Fatal(err)
	}
	if err := s.Activate(b); err != nil {
		t.Fatal(err)
	}
	if s.ActiveID() != b {
		t.Fatalf("active = %q", s.ActiveID())
	}
	content, _ := os.ReadFile(filepath.Join(s.ActiveDir(), "rules", "suricata.rules"))
	if string(content) != b {
		t.Fatal("active link content")
	}
	if s.HasRelease("../" + b) {
		t.Fatal("traversal id accepted")
	}
	s.Prune(b, c)
	if s.HasRelease(a) || !s.HasRelease(b) || !s.HasRelease(c) {
		t.Fatal("prune releases")
	}
	if _, err := os.Stat(s.BundlePath(a)); err == nil {
		t.Fatal("prune bundles")
	}
	if err := s.Activate(""); err != nil || s.ActiveID() != "" {
		t.Fatal("activate empty")
	}
}
