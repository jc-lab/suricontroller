package collector

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/klauspost/compress/zstd"

	agentv1 "github.com/jc-lab/suricontroller/gen/suricontroller/agent/v1"
	"github.com/jc-lab/suricontroller/pkg/wire"
	"github.com/jc-lab/suricontroller/pkg/yamlmerge"
)

const effective = `
default-log-dir: %s
outputs:
  - fast:
      enabled: yes
      filename: fast.log
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert:
            payload: yes
        - dns
        - files
        - http:
            enabled: no
  - eve-log:
      enabled: yes
      filetype: redis
  - stats:
      enabled: no
logging:
  outputs:
    - console:
        enabled: yes
    - file:
        enabled: yes
        filename: /var/log/custom/suricata.log
`

func TestDiscover(t *testing.T) {
	root, _ := yamlmerge.Parse([]byte(fmt.Sprintf(effective, "/var/log/suricata/ids")))
	srcs := Discover(Instance{Name: "ids", Effective: root})
	if len(srcs) != 3 {
		t.Fatalf("sources = %+v", srcs)
	}
	if srcs[0].Type != agentv1.LogType_LOG_TYPE_FAST || srcs[0].Path != "/var/log/suricata/ids/fast.log" {
		t.Fatalf("fast = %+v", srcs[0])
	}
	if srcs[1].Path != "/var/log/suricata/ids/eve.json" || strings.Join(srcs[1].EveTypes, ",") != "alert,dns,fileinfo" {
		t.Fatalf("eve = %+v", srcs[1])
	}
	if srcs[2].Type != agentv1.LogType_LOG_TYPE_SURICATA || srcs[2].Path != "/var/log/custom/suricata.log" {
		t.Fatalf("engine log = %+v", srcs[2])
	}
	// Without a file logging output the process output is used.
	root2, _ := yamlmerge.Parse([]byte("default-log-dir: /x\n"))
	srcs = Discover(Instance{Name: "ips", Effective: root2})
	if len(srcs) != 1 || srcs[0].Path != "" || srcs[0].Instance != "ips" {
		t.Fatalf("process output source = %+v", srcs)
	}
}

func TestEventType(t *testing.T) {
	if eventType([]byte(`{"timestamp":"x","event_type":"alert","src_ip":"1"}`)) != "alert" {
		t.Fatal("alert")
	}
	if eventType([]byte(`{"event_type": "dns"}`)) != "dns" || eventType([]byte(`{}`)) != "" {
		t.Fatal("spacing / missing")
	}
}

func drain(c *Collector) []record {
	var out []record
	for c.queue.Stats().Len > 0 {
		recs, _ := c.queue.PopBatch(context.Background(), 1000, 1<<30)
		out = append(out, recs...)
	}
	return out
}

func TestTailFilterRotate(t *testing.T) {
	dir := t.TempDir()
	logDir := filepath.Join(dir, "ids")
	os.MkdirAll(logDir, 0o755)
	eve := filepath.Join(logDir, "eve.json")
	os.WriteFile(eve, []byte(`{"event_type":"alert","n":0}`+"\n"), 0o644) // before start: skipped (start at end)

	reopened := 0
	c := New(Config{StartAtEnd: true, OffsetsFile: filepath.Join(dir, "offsets.json"), RotateMaxSize: 200, RotateKeep: 2,
		Reopen: func(string) error { reopened++; return nil }})
	root, _ := yamlmerge.Parse([]byte(fmt.Sprintf(effective, logDir)))
	c.SetInstances([]Instance{{Name: "ids", Effective: root}})
	c.SetPolicy(&agentv1.LogCollectionPolicy{Enabled: true, Types: []agentv1.LogType{agentv1.LogType_LOG_TYPE_EVE}, EveTypes: []string{"alert"}})
	c.pollAll()

	f, _ := os.OpenFile(eve, os.O_APPEND|os.O_WRONLY, 0o644)
	fmt.Fprintln(f, `{"event_type":"alert","n":1}`)
	fmt.Fprintln(f, `{"event_type":"dns","n":2}`)
	fmt.Fprint(f, `{"event_type":"alert","n":3}`) // partial line
	c.pollAll()
	got := drain(c)
	if len(got) != 1 || !strings.Contains(string(got[0].line), `"n":1`) || got[0].instance != "ids" {
		t.Fatalf("records = %v", got)
	}
	fmt.Fprintln(f, ``)
	f.Close()
	c.pollAll()
	if got = drain(c); len(got) != 1 || !strings.Contains(string(got[0].line), `"n":3`) {
		t.Fatalf("partial line: %v", got)
	}

	// The file exceeds the rotation size: it is renamed and the instance
	// asked to reopen; records written before and after are all read.
	f, _ = os.OpenFile(eve, os.O_APPEND|os.O_WRONLY, 0o644)
	for i := 4; i < 10; i++ {
		fmt.Fprintf(f, `{"event_type":"alert","n":%d}`+"\n", i)
	}
	f.Close()
	c.pollAll()                                                            // rotates, then reads the old file to EOF
	os.WriteFile(eve, []byte(`{"event_type":"alert","n":10}`+"\n"), 0o644) // Suricata reopened
	c.pollAll()
	c.pollAll()
	got = drain(c)
	if reopened != 1 || len(got) != 7 || !strings.Contains(string(got[6].line), `"n":10`) {
		t.Fatalf("rotation: reopened=%d records=%d", reopened, len(got))
	}
	if _, err := os.Stat(eve + ".1"); err != nil {
		t.Fatal("rotated file missing")
	}

	// Offsets survive a restart.
	c.saveOffsets()
	f, _ = os.OpenFile(eve, os.O_APPEND|os.O_WRONLY, 0o644)
	fmt.Fprintln(f, `{"event_type":"alert","n":11}`)
	f.Close()
	c2 := New(Config{StartAtEnd: true, OffsetsFile: filepath.Join(dir, "offsets.json")})
	c2.SetInstances([]Instance{{Name: "ids", Effective: root}})
	c2.SetPolicy(&agentv1.LogCollectionPolicy{Enabled: true, Types: []agentv1.LogType{agentv1.LogType_LOG_TYPE_EVE}, EveAllTypes: true})
	c2.pollAll()
	if got = drain(c2); len(got) != 1 || !strings.Contains(string(got[0].line), `"n":11`) {
		t.Fatalf("resume: %v", got)
	}

	// Disabled types are skipped without queueing.
	c2.SetPolicy(&agentv1.LogCollectionPolicy{Enabled: true, Types: []agentv1.LogType{agentv1.LogType_LOG_TYPE_FAST}})
	f, _ = os.OpenFile(eve, os.O_APPEND|os.O_WRONLY, 0o644)
	fmt.Fprintln(f, `{"event_type":"alert","n":12}`)
	f.Close()
	c2.pollAll()
	if c2.queue.Stats().Len != 0 {
		t.Fatal("disabled type queued")
	}
}

func TestShip(t *testing.T) {
	a, b := net.Pipe()
	cs, _ := yamux.Client(a, wire.YamuxConfig())
	ss, _ := yamux.Server(b, wire.YamuxConfig())
	defer cs.Close()
	defer ss.Close()
	go func() {
		ms, _ := wire.OpenStream(cs, &agentv1.StreamHeader{Type: agentv1.StreamType_STREAM_TYPE_LOGS}, 0)
		c := New(Config{QueueMaxBytes: 1 << 20})
		c.SetPolicy(&agentv1.LogCollectionPolicy{Enabled: true, Types: []agentv1.LogType{agentv1.LogType_LOG_TYPE_EVE, agentv1.LogType_LOG_TYPE_SURICATA}, EveAllTypes: true})
		c.engineLog["ips"] = true
		c.push(agentv1.LogType_LOG_TYPE_EVE, "ids", []byte(`{"event_type":"alert"}`))
		c.push(agentv1.LogType_LOG_TYPE_EVE, "ids", []byte(`{"event_type":"dns"}`))
		c.PushEngineLine("ips", "i: suricata: started")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c.Ship(ctx, ms)
	}()
	ms, _, err := wire.AcceptStream(ss, 0)
	if err != nil {
		t.Fatal(err)
	}
	dec, _ := zstd.NewReader(nil)
	total := 0
	for total < 3 {
		var lb agentv1.LogBatch
		if err := ms.Recv(&lb); err != nil {
			t.Fatal(err)
		}
		raw, err := dec.DecodeAll(lb.ZstdRecords, nil)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Count(string(raw), "\n") != int(lb.RecordCount) {
			t.Fatalf("batch %+v content %q", &lb, raw)
		}
		total += int(lb.RecordCount)
	}
}
