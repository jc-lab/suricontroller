package yamlmerge

import (
	"reflect"
	"strings"
	"testing"
)

const base = `%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16]"
    EXTERNAL_NET: "!$HOME_NET"
af-packet:
  - interface: eth0
    cluster-id: 99
  - interface: default
outputs:
  - eve-log:
      enabled: yes
      filename: eve.json
`

func TestMergeSemantics(t *testing.T) {
	b, err := Parse([]byte(base))
	if err != nil {
		t.Fatal(err)
	}
	managed, _ := Parse([]byte(`
vars:
  address-groups:
    HOME_NET: "[10.0.0.0/8]"
detect:
  profile: medium
`))
	runtime, _ := Parse([]byte(`
af-packet:
  - interface: br-lan
`))
	shadow := Shadowed(b, managed, runtime)
	Merge(b, managed)
	Merge(b, runtime)

	if v := GetString(b, "vars", "address-groups", "HOME_NET"); v != "[10.0.0.0/8]" {
		t.Fatalf("HOME_NET = %q", v)
	}
	if v := GetString(b, "vars", "address-groups", "EXTERNAL_NET"); v != "!$HOME_NET" {
		t.Fatalf("EXTERNAL_NET lost: %q", v)
	}
	if n := Get(b, "af-packet"); len(n.Content) != 1 {
		t.Fatalf("sequence should be replaced, got %d items", len(n.Content))
	}
	if GetString(b, "detect", "profile") != "medium" {
		t.Fatal("new key not added")
	}
	want := []string{"af-packet", "vars.address-groups.HOME_NET"}
	if !reflect.DeepEqual(shadow, want) {
		t.Fatalf("shadowed = %v, want %v", shadow, want)
	}

	out, err := Encode(b)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(out), Header) {
		t.Fatal("missing header")
	}
	// Key order of the base document is preserved.
	if strings.Index(string(out), "vars:") > strings.Index(string(out), "af-packet:") {
		t.Fatalf("key order changed:\n%s", out)
	}
	again, err := Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	if GetString(again, "detect", "profile") != "medium" {
		t.Fatal("round trip")
	}
}

func TestSetDelete(t *testing.T) {
	root := NewMap()
	Set(root, Scalar("/var/log/suricata/ids"), "default-log-dir")
	Set(root, Scalar("yes"), "unix-command", "enabled")
	Set(root, Scalar("/run/x.sock"), "unix-command", "filename")
	if GetString(root, "unix-command", "filename") != "/run/x.sock" {
		t.Fatal("set nested")
	}
	if !Delete(root, "unix-command", "enabled") || Delete(root, "nope") {
		t.Fatal("delete")
	}
	if got := LeafPaths(root); !reflect.DeepEqual(got, []string{"default-log-dir", "unix-command.filename"}) {
		t.Fatalf("leaf paths = %v", got)
	}
	empty, err := Parse(nil)
	if err != nil || len(empty.Content) != 0 {
		t.Fatal("empty document")
	}
	if _, err := Parse([]byte("- a\n- b\n")); err == nil {
		t.Fatal("sequence root accepted")
	}
}
