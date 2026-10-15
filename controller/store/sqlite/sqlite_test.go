package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jc-lab/suricontroller/controller/store"
	agentv1 "github.com/jc-lab/suricontroller/gen/suricontroller/agent/v1"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestNodes(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	now := time.UnixMilli(time.Now().UnixMilli())
	n := &store.Node{ID: "router-01", PublicKey: "ssh-ed25519 AAAA router-01", Fingerprint: "SHA256:x", Enabled: true, CreatedAt: now, UpdatedAt: now}
	if err := s.CreateNode(ctx, n); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateNode(ctx, n); !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("duplicate create: %v", err)
	}
	got, err := s.UpdateNode(ctx, "router-01", func(n *store.Node) error {
		n.Hello = &agentv1.Hello{NodeId: "router-01", AgentVersion: "1.0"}
		n.InterfaceModes = map[string]agentv1.InterfaceMode{"br-lan": agentv1.InterfaceMode_INTERFACE_MODE_IPS}
		n.EndpointModes = map[string]agentv1.EndpointMode{"websecure": agentv1.EndpointMode_ENDPOINT_MODE_DETECT}
		n.Desired = &agentv1.DesiredState{Generation: 3}
		n.LastSeenAt = now
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Desired.Generation != 3 {
		t.Fatal("update result")
	}
	got, err = s.GetNode(ctx, "router-01")
	if err != nil {
		t.Fatal(err)
	}
	if got.Hello.GetAgentVersion() != "1.0" || got.InterfaceModes["br-lan"] != agentv1.InterfaceMode_INTERFACE_MODE_IPS ||
		got.EndpointModes["websecure"] != agentv1.EndpointMode_ENDPOINT_MODE_DETECT ||
		got.Desired.GetGeneration() != 3 || !got.LastSeenAt.Equal(now) || got.LogPolicy != nil {
		t.Fatalf("unexpected node %+v", got)
	}

	// Failed update leaves the node unchanged.
	_, err = s.UpdateNode(ctx, "router-01", func(n *store.Node) error {
		n.Description = "changed"
		return errors.New("abort")
	})
	if err == nil {
		t.Fatal("expected abort error")
	}
	got, _ = s.GetNode(ctx, "router-01")
	if got.Description != "" {
		t.Fatal("aborted update was saved")
	}

	if err := s.AppendApplyHistory(ctx, &store.ApplyHistoryEntry{NodeID: "router-01", Report: &agentv1.ApplyReport{Generation: 1}, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := s.AppendApplyHistory(ctx, &store.ApplyHistoryEntry{NodeID: "router-01", Report: &agentv1.ApplyReport{Generation: 2}, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := s.PruneApplyHistory(ctx, 1); err != nil {
		t.Fatal(err)
	}
	hist, err := s.ListApplyHistory(ctx, "router-01", 10)
	if err != nil || len(hist) != 1 || hist[0].Report.Generation != 2 {
		t.Fatalf("history = %v, %v", hist, err)
	}

	if err := s.DeleteNode(ctx, "router-01"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetNode(ctx, "router-01"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("get after delete: %v", err)
	}
	hist, _ = s.ListApplyHistory(ctx, "router-01", 10)
	if len(hist) != 0 {
		t.Fatal("history not cascaded")
	}
}

func TestPoliciesProvidersSettings(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	if _, err := s.GetDeployPolicy(ctx, "rules"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	if err := s.PutDeployPolicy(ctx, &store.DeployPolicy{Kind: "rules", Mode: "pinned", PinnedCommit: "abc", EffectiveCommit: "abc"}); err != nil {
		t.Fatal(err)
	}
	p, err := s.GetDeployPolicy(ctx, "rules")
	if err != nil || p.Mode != "pinned" || p.EffectiveCommit != "abc" {
		t.Fatalf("policy = %+v %v", p, err)
	}

	if err := s.PutProvider(ctx, &store.Provider{Name: "et-open", Type: "et-open", Enabled: true, Interval: time.Hour, Options: map[string]string{"suricata_version": "8.0.5"}}); err != nil {
		t.Fatal(err)
	}
	pr, err := s.GetProvider(ctx, "et-open")
	if err != nil || pr.Interval != time.Hour || pr.Options["suricata_version"] != "8.0.5" {
		t.Fatalf("provider = %+v %v", pr, err)
	}

	pol := &agentv1.LogCollectionPolicy{Enabled: true, Types: []agentv1.LogType{agentv1.LogType_LOG_TYPE_EVE}}
	if err := s.PutSetting(ctx, "log_policy", pol); err != nil {
		t.Fatal(err)
	}
	var got agentv1.LogCollectionPolicy
	ok, err := s.GetSetting(ctx, "log_policy", &got)
	if !ok || err != nil || !got.Enabled || len(got.Types) != 1 {
		t.Fatalf("setting = %v %v %v", &got, ok, err)
	}
	var n int
	if ok, _ := s.GetSetting(ctx, "missing", &n); ok {
		t.Fatal("missing setting reported as set")
	}
}

func TestReopenKeepsData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutSetting(context.Background(), "k", 42); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var v int
	if ok, err := s.GetSetting(context.Background(), "k", &v); !ok || err != nil || v != 42 {
		t.Fatalf("v=%d ok=%v err=%v", v, ok, err)
	}
}

// A version 1 database (before tap endpoint modes) is migrated in place.
func TestMigrateFromVersion1(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v1.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	v1 := strings.Replace(schema, ",\n    endpoint_modes  TEXT\n", "\n", 1)
	if v1 == schema {
		t.Fatal("could not derive the version 1 schema")
	}
	if _, err := db.Exec(v1 + "; PRAGMA user_version = 1;"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO nodes (id, public_key, fingerprint, enabled, created_at, updated_at) VALUES ('n1', 'k', 'f', 1, 0, 0)`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	if _, err := s.UpdateNode(ctx, "n1", func(n *store.Node) error {
		n.EndpointModes = map[string]agentv1.EndpointMode{"api": agentv1.EndpointMode_ENDPOINT_MODE_PREVENT}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	n, err := s.GetNode(ctx, "n1")
	if err != nil || n.EndpointModes["api"] != agentv1.EndpointMode_ENDPOINT_MODE_PREVENT {
		t.Fatalf("after migration: %+v %v", n, err)
	}
}
