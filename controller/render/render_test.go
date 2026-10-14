package render

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/jc-lab/suricontroller/controller/gitrepo"
	"github.com/jc-lab/suricontroller/pkg/bundle"
)

func setup(t *testing.T) (*Renderer, *gitrepo.Repo, *gitrepo.Repo, ed25519.PublicKey) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	rules, _ := gitrepo.Open(t.TempDir())
	cfg, _ := gitrepo.Open(t.TempDir())
	r, err := New(Config{Rules: rules, Config: cfg, Key: priv, CacheDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	return r, rules, cfg, pub
}

func commit(t *testing.T, repo *gitrepo.Repo, files map[string]string) string {
	t.Helper()
	var ch []gitrepo.Change
	for p, c := range files {
		ch = append(ch, gitrepo.Change{Path: p, Content: []byte(c)})
	}
	id, err := repo.Commit("", ch, "test", gitrepo.Signature{})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestRenderSelectionAndMerge(t *testing.T) {
	ctx := context.Background()
	r, rules, cfg, pub := setup(t)
	rc := commit(t, rules, map[string]string{
		"et-open/emerging-dns.rules":     `alert dns any any -> any any (msg:"dns"; sid:2000001; rev:1;)` + "\n",
		"et-open/emerging-games.rules":   `alert ip any any -> any any (msg:"games"; sid:2000002; rev:1;)` + "\n",
		"et-open/emerging-deleted.rules": `alert ip any any -> any any (msg:"deleted"; sid:2000003; rev:1;)` + "\n",
		"et-open/classification.config":  "config classification: trojan-activity,A Network Trojan was detected,1\n",
		"et-open/reference.config":       "config reference: url http://\n",
		"local/local.rules": `alert http any any -> any any (msg:"ds"; dataset:isset,bad-hosts,type string,load bad.lst; sid:9000001; rev:1;)` + "\n" +
			`alert tcp any any -> any any (msg:"local"; sid:9000002; rev:1;)` + "\n",
		"local/bad.lst":               "ZXZpbC5leGFtcGxl\n",
		"local/classification.config": "config classification: trojan-activity,duplicate,9\nconfig classification: local-class,Local,2\n",
	})
	cc := commit(t, cfg, map[string]string{
		"common/sources.yaml":   "exclude: [et-open/emerging-games.rules]\n",
		"common/drop.conf":      "group:emerging-dns.rules\n",
		"common/suricata.yaml":  "detect:\n  profile: high\n",
		"nodes/n1/disable.conf": "9000002\n",
	})

	res, err := r.Render(ctx, rc, cc, "n1")
	if err != nil {
		t.Fatal(err)
	}
	rc2, _, err := r.Open(res.ID)
	if err != nil {
		t.Fatal(err)
	}
	b, err := bundle.Read(rc2, res.ID, pub, bundle.Limits{})
	rc2.Close()
	if err != nil {
		t.Fatal(err)
	}
	out := string(b.Files[bundle.PathRules])
	if strings.Contains(out, "games") || strings.Contains(out, "deleted") {
		t.Fatalf("excluded/ignored files rendered:\n%s", out)
	}
	if !strings.Contains(out, `drop dns any any -> any any (msg:"dns"; sid:2000001; rev:1;)`) {
		t.Fatalf("drop.conf not applied:\n%s", out)
	}
	if !strings.Contains(out, "# alert tcp any any -> any any (msg:\"local\"") {
		t.Fatalf("node disable.conf not applied:\n%s", out)
	}
	if !strings.Contains(out, "load datasets/") {
		t.Fatalf("dataset not rewritten:\n%s", out)
	}
	var datasets int
	for p := range b.Files {
		if strings.HasPrefix(p, "rules/datasets/") {
			datasets++
		}
	}
	if datasets != 1 {
		t.Fatalf("dataset files = %d", datasets)
	}
	class := string(b.Files[bundle.PathClassification])
	if strings.Count(class, "trojan-activity") != 1 || !strings.Contains(class, "A Network Trojan") || !strings.Contains(class, "local-class") {
		t.Fatalf("classification merge:\n%s", class)
	}
	if !strings.Contains(string(b.Files[bundle.PathControllerYAML]), "profile: high") {
		t.Fatal("overlay missing")
	}
	st := res.Manifest.RuleStats
	if st.Dropped != 1 || st.Enabled != 2 {
		t.Fatalf("stats = %+v", st)
	}

	// Cached and deterministic: same id, other nodes differ.
	again, _ := r.Render(ctx, rc, cc, "n1")
	other, _ := r.Render(ctx, rc, cc, "n2")
	if again.ID != res.ID || other.ID == res.ID {
		t.Fatal("cache / per-node rendering")
	}
	// Bundles not kept are garbage collected.
	if n := r.GC(map[string]bool{res.ID: true}, 0); n != 1 {
		t.Fatalf("gc removed %d", n)
	}
	if _, _, err := r.Open(other.ID); err == nil {
		t.Fatal("collected bundle still present")
	}
	if _, _, err := r.Open("../../etc/passwd"); err == nil {
		t.Fatal("path traversal in bundle id")
	}
}

func TestRenderErrors(t *testing.T) {
	ctx := context.Background()
	r, rules, cfg, _ := setup(t)
	rc := commit(t, rules, map[string]string{"local/a.rules": `alert ip any any -> any any (msg:"a"; sid:1; rev:1;)` + "\n"})
	bad := commit(t, cfg, map[string]string{"common/disable.conf": "re:(unclosed\n"})
	if _, err := r.Render(ctx, rc, bad, "n1"); err == nil {
		t.Fatal("invalid conf rendered")
	}
	// Empty repositories render an empty bundle.
	res, err := r.Render(ctx, "", "", "n1")
	if err != nil || res.Manifest.RuleStats.Total != 0 {
		t.Fatalf("empty: %v %v", res, err)
	}
	if err := ValidateConf("disable.conf", []string{"1:1", "re:ok", "group:x.rules"}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateConf("modify.conf", []string{`1:1 "a" "b"`}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateConf("modify.conf", []string{`1:1 "(?<=x)a" "b"`}); err == nil {
		t.Fatal("unsupported regex accepted")
	}
}
