package configrepo

import (
	"reflect"
	"testing"

	"github.com/jc-lab/suricontroller/controller/gitrepo"
	"github.com/jc-lab/suricontroller/pkg/yamlmerge"
)

func TestValidatePath(t *testing.T) {
	for _, p := range []string{"common/suricata.yaml", "nodes/router-01/disable.conf", "common/threshold.config"} {
		if err := ValidatePath(p); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
	for _, p := range []string{"suricata.yaml", "common/other.txt", "nodes/Bad/disable.conf", "nodes/common/disable.conf", "nodes/a/b/disable.conf", "../common/disable.conf"} {
		if err := ValidatePath(p); err == nil {
			t.Errorf("%s: expected error", p)
		}
	}
}

func TestValidateFile(t *testing.T) {
	if err := ValidateFile("common/suricata.yaml", []byte("outputs: []\n"), nil); err == nil {
		t.Fatal("forbidden key accepted")
	}
	if err := ValidateFile("common/sources.yaml", []byte("providers: [et-open]\nbogus: 1\n"), nil); err == nil {
		t.Fatal("unknown sources field accepted")
	}
	if err := ValidateFile("common/sources.yaml", []byte(""), nil); err != nil {
		t.Fatalf("empty sources: %v", err)
	}
}

func TestLoadLayers(t *testing.T) {
	repo, err := gitrepo.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c, err := repo.Commit("", []gitrepo.Change{
		{Path: "common/suricata.yaml", Content: []byte("vars:\n  address-groups:\n    HOME_NET: '[10.0.0.0/8]'\n    EXTERNAL_NET: '!$HOME_NET'\n")},
		{Path: "common/disable.conf", Content: []byte("1:100\n1:101\n")},
		{Path: "common/drop.conf", Content: []byte("group:emerging-exploit.rules\n")},
		{Path: "common/sources.yaml", Content: []byte("providers: [et-open, local]\n")},
		{Path: "nodes/router-01/suricata.yaml", Content: []byte("vars:\n  address-groups:\n    HOME_NET: '[192.168.1.0/24]'\n")},
		{Path: "nodes/router-01/disable.conf", Content: []byte("1:200\n")},
		{Path: "nodes/router-01/drop.conf", Content: []byte(ReplaceMarker + "\n1:300\n")},
		{Path: "nodes/router-01/sources.yaml", Content: []byte("providers: [local]\n")},
	}, "init", gitrepo.Signature{})
	if err != nil {
		t.Fatal(err)
	}

	l, err := Load(repo, c, "router-01")
	if err != nil {
		t.Fatal(err)
	}
	if v := yamlmerge.GetString(l.Overlay, "vars", "address-groups", "HOME_NET"); v != "[192.168.1.0/24]" {
		t.Fatalf("HOME_NET = %q", v)
	}
	if v := yamlmerge.GetString(l.Overlay, "vars", "address-groups", "EXTERNAL_NET"); v != "!$HOME_NET" {
		t.Fatalf("EXTERNAL_NET = %q", v)
	}
	if !reflect.DeepEqual(l.Disable, []string{"1:100", "1:101", "1:200"}) {
		t.Fatalf("disable = %v", l.Disable)
	}
	if !reflect.DeepEqual(l.Drop, []string{ReplaceMarker, "1:300"}) {
		t.Fatalf("drop = %v", l.Drop)
	}
	if !reflect.DeepEqual(l.Sources.Providers, []string{"local"}) {
		t.Fatalf("sources = %v", l.Sources)
	}

	other, err := Load(repo, c, "router-02")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(other.Disable, []string{"1:100", "1:101"}) || len(other.Sources.Providers) != 2 {
		t.Fatalf("router-02 = %+v", other)
	}

	empty, err := Load(repo, "", "router-01")
	if err != nil || len(empty.Overlay.Content) != 0 {
		t.Fatalf("empty: %+v %v", empty, err)
	}
}
