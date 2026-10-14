package unixsock

import (
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"testing"
)

// fakeSuricata answers like Suricata's unix-command socket.
func fakeSuricata(t *testing.T, replies map[string]any) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "s.sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				dec, enc := json.NewDecoder(c), json.NewEncoder(c)
				var hello map[string]string
				if dec.Decode(&hello) != nil || hello["version"] == "" {
					return
				}
				enc.Encode(map[string]string{"return": "OK"})
				var req map[string]any
				if dec.Decode(&req) != nil {
					return
				}
				reply, ok := replies[req["command"].(string)]
				if !ok {
					enc.Encode(map[string]any{"return": "NOK", "message": "Unknown command"})
					return
				}
				enc.Encode(map[string]any{"return": "OK", "message": reply})
			}(c)
		}
	}()
	return path
}

func TestCommands(t *testing.T) {
	ctx := context.Background()
	c := &Client{Path: fakeSuricata(t, map[string]any{
		"reload-rules":  "done",
		"ruleset-stats": []map[string]int{{"id": 0, "rules_loaded": 42, "rules_failed": 1}},
		"uptime":        17,
		"dump-counters": map[string]any{"capture": map[string]any{"kernel_packets": 100, "kernel_drops": 2}, "decoder": map[string]any{"pkts": 98}},
	})}
	if err := c.ReloadRules(ctx); err != nil {
		t.Fatal(err)
	}
	st, err := c.RulesetStats(ctx)
	if err != nil || len(st) != 1 || st[0].RulesLoaded != 42 || st[0].RulesFailed != 1 {
		t.Fatalf("stats = %+v %v", st, err)
	}
	if up, err := c.Uptime(ctx); err != nil || up != 17 {
		t.Fatalf("uptime = %d %v", up, err)
	}
	cnt, err := c.Counters(ctx, []string{"capture.kernel_packets", "decoder.pkts", "missing.x"})
	if err != nil || cnt["capture.kernel_packets"] != 100 || cnt["decoder.pkts"] != 98 || len(cnt) != 2 {
		t.Fatalf("counters = %v %v", cnt, err)
	}
	if _, err := c.Command(ctx, "nope", nil); err == nil {
		t.Fatal("expected error")
	}
}
