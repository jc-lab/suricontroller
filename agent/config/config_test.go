package config

import (
	"strings"
	"testing"
)

const sample = `
node_id: router-01
controller:
  url: wss://suri.example.com/agent/v1/connect
  host_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMVAH+i3R0gfzddfDDMsjh+w4hZqRIeuOhIWDnVzosBL suri-controller"
  headers:
    CF-Access-Client-Id: abc
interfaces:
  - name: br-lan
  - name: eth1
    ips: false
ips:
  enabled: true
  queues: "0-3"
suricata:
  instances:
    ids: { log_dir: /data/logs/ids }
logs:
  queue_max_bytes: 8MiB
`

func TestParse(t *testing.T) {
	c, err := Parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	if !c.IPSAllowed("br-lan") || c.IPSAllowed("eth1") || c.IPSAllowed("eth9") {
		t.Fatal("IPSAllowed")
	}
	if lo, hi, _ := c.QueueRange(); lo != 0 || hi != 3 {
		t.Fatalf("queues %d-%d", lo, hi)
	}
	if c.LogDir(InstanceIDS) != "/data/logs/ids" || c.LogDir(InstanceIPS) != "/var/log/suricata/ips" {
		t.Fatal("log dirs")
	}
	if c.Logs.QueueMaxBytes != 8<<20 || !c.FailOpen() || c.Controller.Headers["CF-Access-Client-Id"] != "abc" {
		t.Fatalf("defaults/values: %+v", c.Logs)
	}
}

func TestValidateErrors(t *testing.T) {
	bad := strings.Replace(sample, "node_id: router-01", "node_id: Bad/ID", 1)
	bad = strings.Replace(bad, "wss://", "https://", 1)
	bad = strings.Replace(bad, `queues: "0-3"`, `queues: "3-1"`, 1)
	_, err := Parse([]byte(bad))
	if err == nil {
		t.Fatal("expected errors")
	}
	for _, want := range []string{"node_id", "controller.url", "ips.queues"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in %v", want, err)
		}
	}
	if _, err := Parse([]byte(sample + "\nunknown_key: 1\n")); err == nil {
		t.Fatal("unknown key accepted")
	}
}

func TestExternalController(t *testing.T) {
	noController := "node_id: router-01\n"
	if _, err := Parse([]byte(noController)); err == nil || !strings.Contains(err.Error(), "controller.url") {
		t.Fatalf("Parse without controller: %v", err)
	}
	c, err := ParseWith([]byte(noController), ParseOptions{ExternalController: true})
	if err != nil || !c.ExternalController {
		t.Fatalf("ParseWith: %v", err)
	}
	// A controller section that is there is still checked.
	partial := noController + "controller:\n  url: wss://suri.example.com/agent/v1/connect\n"
	if _, err := ParseWith([]byte(partial), ParseOptions{ExternalController: true}); err == nil || !strings.Contains(err.Error(), "controller.host_key") {
		t.Fatalf("ParseWith partial: %v", err)
	}
}

func TestByteSize(t *testing.T) {
	for in, want := range map[string]int64{"16MiB": 16 << 20, "64MB": 64e6, "1G": 1 << 30, "512": 512, "1.5KiB": 1536} {
		got, err := ParseByteSize(in)
		if err != nil || got != want {
			t.Errorf("%s: %d %v", in, got, err)
		}
	}
	if _, err := ParseByteSize("-1"); err == nil {
		t.Fatal("negative accepted")
	}
}
