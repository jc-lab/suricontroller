package firewall

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

type recordExec struct {
	calls []string
	fail  map[string]bool
	tools map[string]bool
}

func (r *recordExec) Run(_ context.Context, name string, args []string, stdin []byte) ([]byte, error) {
	call := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, call)
	for prefix := range r.fail {
		if strings.HasPrefix(call, prefix) {
			return nil, fmt.Errorf("failed: %s", call)
		}
	}
	return nil, nil
}

func (r *recordExec) LookPath(name string) (string, error) {
	if r.tools[name] {
		return "/usr/sbin/" + name, nil
	}
	return "", exec.ErrNotFound
}

func TestNftScript(t *testing.T) {
	n := &Nftables{}
	s := n.Script(Plan{Interfaces: []string{"wan", "br-lan"}, QueueFirst: 0, QueueLast: 1, FailOpen: true})
	for _, want := range []string{
		"table inet suricontroller\ndelete table inet suricontroller\n",
		"type filter hook forward priority filter + 10; policy accept;",
		`iifname { "br-lan", "wan" } queue num 0-1 bypass,fanout`,
		`oifname { "br-lan", "wan" } queue num 0-1 bypass,fanout`,
		"hook input", "hook output",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script missing %q:\n%s", want, s)
		}
	}
	single := n.Script(Plan{Interfaces: []string{"eth0"}, QueueFirst: 3, QueueLast: 3})
	if !strings.Contains(single, `iifname { "eth0" } queue num 3`+"\n") {
		t.Fatalf("single queue fail-closed:\n%s", single)
	}
	if empty := n.Script(Plan{}); strings.Count(empty, "\n") != 2 {
		t.Fatalf("empty plan should only delete the table:\n%s", empty)
	}
}

func TestIptablesApply(t *testing.T) {
	ex := &recordExec{fail: map[string]bool{"iptables -w -C": true}, tools: map[string]bool{"iptables": true}}
	ipt := &Iptables{Exec: ex}
	if err := ipt.Apply(context.Background(), Plan{Interfaces: []string{"eth0"}, QueueFirst: 0, QueueLast: 3, FailOpen: true}); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(ex.calls, "\n")
	for _, want := range []string{
		"iptables -w -N SURICONTROLLER",
		"iptables -w -A SURICONTROLLER -i eth0 -j NFQUEUE --queue-balance 0:3 --queue-bypass",
		"iptables -w -A SURICONTROLLER -o eth0 -j NFQUEUE --queue-balance 0:3 --queue-bypass",
		"iptables -w -I FORWARD 1 -j SURICONTROLLER",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in\n%s", want, joined)
		}
	}
}

func TestAutoSelection(t *testing.T) {
	b, _ := New("auto", &recordExec{tools: map[string]bool{"iptables": true}})
	if b.Name() != "iptables" {
		t.Fatalf("got %s", b.Name())
	}
	b, _ = New("auto", &recordExec{tools: map[string]bool{"nft": true, "iptables": true}})
	if b.Name() != "nftables" {
		t.Fatalf("got %s", b.Name())
	}
	b, _ = New("auto", &recordExec{})
	if b.Name() != "none" {
		t.Fatalf("got %s", b.Name())
	}
}

func ExampleNftables_Script() {
	fmt.Print((&Nftables{}).Script(Plan{Interfaces: []string{"br-lan"}, QueueFirst: 0, QueueLast: 1, FailOpen: true}))
	// Output:
	// table inet suricontroller
	// delete table inet suricontroller
	// table inet suricontroller {
	// 	chain forward {
	// 		type filter hook forward priority filter + 10; policy accept;
	// 		iifname { "br-lan" } queue num 0-1 bypass,fanout
	// 		oifname { "br-lan" } queue num 0-1 bypass,fanout
	// 	}
	// 	chain input {
	// 		type filter hook input priority filter + 10; policy accept;
	// 		iifname { "br-lan" } queue num 0-1 bypass,fanout
	// 	}
	// 	chain output {
	// 		type filter hook output priority filter + 10; policy accept;
	// 		oifname { "br-lan" } queue num 0-1 bypass,fanout
	// 	}
	// }
}

type errExec struct {
	recordExec
	err map[string]string // call prefix -> error text
}

func (e *errExec) Run(ctx context.Context, name string, args []string, stdin []byte) ([]byte, error) {
	_, _ = e.recordExec.Run(ctx, name, args, stdin)
	call := name + " " + strings.Join(args, " ")
	for prefix, msg := range e.err {
		if strings.HasPrefix(call, prefix) {
			return nil, fmt.Errorf("%s: exit status 1: %s", call, msg)
		}
	}
	return nil, nil
}

// A kernel without nft_queue: the probe (nft -c) and Apply name the
// missing modules instead of nft's misleading "did you mean table fw4".
func TestQueueUnsupported(t *testing.T) {
	enoent := "/dev/stdin:3:12-25: Error: No such file or directory; did you mean table 'fw4' in family inet?"
	ex := &errExec{err: map[string]string{"nft -c": enoent, "nft -f": enoent}}
	n := &Nftables{Exec: ex}
	err := n.ProbeQueue(context.Background())
	if !errors.Is(err, ErrQueueUnsupported) || !strings.Contains(err.Error(), "kmod-nft-queue") {
		t.Fatalf("probe: %v", err)
	}
	err = n.Apply(context.Background(), Plan{Interfaces: []string{"br-lan"}})
	if !errors.Is(err, ErrQueueUnsupported) {
		t.Fatalf("apply: %v", err)
	}
	if err := n.Apply(context.Background(), Plan{}); errors.Is(err, ErrQueueUnsupported) {
		t.Fatalf("removing the table is not a queue problem: %v", err)
	}
	ok := &Nftables{Exec: &recordExec{}}
	if err := ok.ProbeQueue(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c := ok.Exec.(*recordExec).calls; len(c) != 1 || c[0] != "nft -c -f -" {
		t.Fatalf("probe must only check: %v", c)
	}

	ipt := &Iptables{Exec: &errExec{err: map[string]string{"iptables -w -A": "iptables: No chain/target/match by that name."}}}
	if err := ipt.ProbeQueue(context.Background()); !errors.Is(err, ErrQueueUnsupported) || !strings.Contains(err.Error(), "kmod-ipt-nfqueue") {
		t.Fatalf("iptables probe: %v", err)
	}
}
