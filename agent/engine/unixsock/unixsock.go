// Package unixsock is a client for Suricata's unix-command socket
// (the protocol used by suricatasc).
package unixsock

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"
)

// Error is a command failure reported by Suricata.
type Error struct {
	Command string
	Message string
}

func (e *Error) Error() string { return fmt.Sprintf("suricata %s: %s", e.Command, e.Message) }

// Client talks to one Suricata instance.
type Client struct {
	Path string
}

type response struct {
	Return  string          `json:"return"`
	Message json.RawMessage `json:"message"`
}

// Command runs a command and returns its "message" payload.
func (c *Client) Command(ctx context.Context, command string, args map[string]any) (json.RawMessage, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", c.Path)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(10 * time.Minute))
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	enc := json.NewEncoder(conn)
	dec := json.NewDecoder(conn)
	if err := enc.Encode(map[string]string{"version": "0.2"}); err != nil {
		return nil, err
	}
	var hello response
	if err := dec.Decode(&hello); err != nil {
		return nil, fmt.Errorf("unixsock: handshake: %w", err)
	}
	if hello.Return != "OK" {
		return nil, errors.New("unixsock: handshake rejected")
	}
	req := map[string]any{"command": command}
	if len(args) > 0 {
		req["arguments"] = args
	}
	if err := enc.Encode(req); err != nil {
		return nil, err
	}
	var resp response
	if err := dec.Decode(&resp); err != nil {
		return nil, fmt.Errorf("unixsock: %s: %w", command, err)
	}
	if resp.Return != "OK" {
		var msg string
		if json.Unmarshal(resp.Message, &msg) != nil {
			msg = string(resp.Message)
		}
		return nil, &Error{Command: command, Message: msg}
	}
	return resp.Message, nil
}

// ReloadRules reloads the ruleset and waits for completion.
func (c *Client) ReloadRules(ctx context.Context) error {
	_, err := c.Command(ctx, "reload-rules", nil)
	return err
}

// RulesetStats is one entry of ruleset-stats.
type RulesetStats struct {
	ID           int `json:"id"`
	RulesLoaded  int `json:"rules_loaded"`
	RulesFailed  int `json:"rules_failed"`
	RulesSkipped int `json:"rules_skipped"`
}

// RulesetStats returns per detect engine rule counts.
func (c *Client) RulesetStats(ctx context.Context) ([]RulesetStats, error) {
	raw, err := c.Command(ctx, "ruleset-stats", nil)
	if err != nil {
		return nil, err
	}
	var out []RulesetStats
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// FailedRule is an entry of ruleset-failed-rules.
type FailedRule struct {
	TenantID int    `json:"tenant_id"`
	Rule     string `json:"rule"`
	Filename string `json:"filename"`
	Line     int    `json:"line"`
}

// FailedRules returns rules that failed to load.
func (c *Client) FailedRules(ctx context.Context) ([]FailedRule, error) {
	raw, err := c.Command(ctx, "ruleset-failed-rules", nil)
	if err != nil {
		return nil, err
	}
	var out []FailedRule
	if err := json.Unmarshal(raw, &out); err != nil {
		// Suricata answers with a string when there are no failed rules.
		return nil, nil
	}
	return out, nil
}

// Uptime returns the engine uptime in seconds.
func (c *Client) Uptime(ctx context.Context) (int64, error) {
	raw, err := c.Command(ctx, "uptime", nil)
	if err != nil {
		return 0, err
	}
	var v int64
	err = json.Unmarshal(raw, &v)
	return v, err
}

// Counters returns selected counters from dump-counters, flattened to
// dotted names (e.g. "capture.kernel_packets").
func (c *Client) Counters(ctx context.Context, names []string) (map[string]uint64, error) {
	raw, err := c.Command(ctx, "dump-counters", nil)
	if err != nil {
		return nil, err
	}
	var tree map[string]any
	if err := json.Unmarshal(raw, &tree); err != nil {
		return nil, err
	}
	out := map[string]uint64{}
	for _, name := range names {
		if v, ok := lookup(tree, name); ok {
			out[name] = v
		}
	}
	return out, nil
}

func lookup(tree map[string]any, dotted string) (uint64, bool) {
	cur := any(tree)
	start := 0
	for i := 0; i <= len(dotted); i++ {
		if i < len(dotted) && dotted[i] != '.' {
			continue
		}
		m, ok := cur.(map[string]any)
		if !ok {
			return 0, false
		}
		if cur, ok = m[dotted[start:i]]; !ok {
			return 0, false
		}
		start = i + 1
	}
	f, ok := cur.(float64)
	if !ok || f < 0 {
		return 0, false
	}
	return uint64(f), true
}
