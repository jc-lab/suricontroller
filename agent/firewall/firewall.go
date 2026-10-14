// Package firewall steers traffic of IPS-mode interfaces into NFQUEUE for
// the Suricata IPS instance. Rules live in a dedicated table/chain owned by
// the agent, independent of the host firewall (fw4, firewalld, ...).
package firewall

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/jc-lab/suricontroller/agent/platform"
)

// TableName is the nftables table / iptables chain owned by the agent.
const (
	TableName = "suricontroller"
	ChainName = "SURICONTROLLER"
)

// Plan describes the desired NFQUEUE steering.
type Plan struct {
	Interfaces []string
	QueueFirst uint16
	QueueLast  uint16
	// FailOpen lets packets pass when no process listens on the queue.
	FailOpen bool
}

// Empty reports whether nothing needs to be steered.
func (p Plan) Empty() bool { return len(p.Interfaces) == 0 }

func (p Plan) normalized() Plan {
	q := p
	q.Interfaces = append([]string(nil), p.Interfaces...)
	sort.Strings(q.Interfaces)
	return q
}

// Backend applies plans.
type Backend interface {
	Name() string
	// Apply makes the host match plan (an empty plan removes all rules).
	Apply(ctx context.Context, p Plan) error
	// Check reports whether the host still matches plan.
	Check(ctx context.Context, p Plan) (bool, error)
	// Remove deletes everything the agent installed.
	Remove(ctx context.Context) error
}

// New returns the backend by name ("auto" picks nftables, then iptables).
func New(name string, ex platform.Exec) (Backend, error) {
	switch name {
	case "nftables":
		return &Nftables{Exec: ex}, nil
	case "iptables":
		return &Iptables{Exec: ex}, nil
	case "none":
		return None{}, nil
	case "auto", "":
		if _, err := ex.LookPath("nft"); err == nil {
			return &Nftables{Exec: ex}, nil
		}
		if _, err := ex.LookPath("iptables"); err == nil {
			return &Iptables{Exec: ex}, nil
		}
		return None{}, nil
	}
	return nil, fmt.Errorf("firewall: unknown backend %q", name)
}

// None installs nothing; IPS mode then requires manual steering.
type None struct{}

// Name implements Backend.
func (None) Name() string { return "none" }

// Apply implements Backend.
func (None) Apply(context.Context, Plan) error { return nil }

// Check implements Backend.
func (None) Check(context.Context, Plan) (bool, error) { return true, nil }

// Remove implements Backend.
func (None) Remove(context.Context) error { return nil }

// Nftables uses a dedicated "inet suricontroller" table. Its base chains run
// after the default filter priority, so only traffic accepted by the host
// firewall (fw4) reaches Suricata.
type Nftables struct {
	Exec platform.Exec
}

// Name implements Backend.
func (*Nftables) Name() string { return "nftables" }

func nftSet(ifaces []string) string {
	q := make([]string, len(ifaces))
	for i, s := range ifaces {
		q[i] = `"` + s + `"`
	}
	return "{ " + strings.Join(q, ", ") + " }"
}

// Script returns the nft script for a plan. It recreates the table in one
// transaction, so applying is atomic and idempotent.
func (n *Nftables) Script(p Plan) string {
	p = p.normalized()
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s\ndelete table inet %s\n", TableName, TableName)
	if p.Empty() {
		return b.String()
	}
	queue := fmt.Sprintf("queue num %d", p.QueueFirst)
	if p.QueueLast > p.QueueFirst {
		queue = fmt.Sprintf("queue num %d-%d", p.QueueFirst, p.QueueLast)
	}
	var flags []string
	if p.FailOpen {
		flags = append(flags, "bypass")
	}
	if p.QueueLast > p.QueueFirst {
		flags = append(flags, "fanout")
	}
	if len(flags) > 0 {
		queue += " " + strings.Join(flags, ",")
	}
	set := nftSet(p.Interfaces)
	fmt.Fprintf(&b, "table inet %s {\n", TableName)
	fmt.Fprintf(&b, "\tchain forward {\n\t\ttype filter hook forward priority filter + 10; policy accept;\n\t\tiifname %s %s\n\t\toifname %s %s\n\t}\n", set, queue, set, queue)
	fmt.Fprintf(&b, "\tchain input {\n\t\ttype filter hook input priority filter + 10; policy accept;\n\t\tiifname %s %s\n\t}\n", set, queue)
	fmt.Fprintf(&b, "\tchain output {\n\t\ttype filter hook output priority filter + 10; policy accept;\n\t\toifname %s %s\n\t}\n", set, queue)
	b.WriteString("}\n")
	return b.String()
}

// Apply implements Backend.
func (n *Nftables) Apply(ctx context.Context, p Plan) error {
	_, err := n.Exec.Run(ctx, "nft", []string{"-f", "-"}, []byte(n.Script(p)))
	return err
}

// Check implements Backend: the table must exist and steer exactly the
// planned interfaces.
func (n *Nftables) Check(ctx context.Context, p Plan) (bool, error) {
	out, err := n.Exec.Run(ctx, "nft", []string{"list", "table", "inet", TableName}, nil)
	if err != nil {
		return p.Empty(), nil
	}
	if p.Empty() {
		return false, nil
	}
	text := string(out)
	for _, ifc := range p.Interfaces {
		if !strings.Contains(text, `"`+ifc+`"`) && !strings.Contains(text, " "+ifc+" ") {
			return false, nil
		}
	}
	return strings.Count(text, "queue") >= 4, nil
}

// Remove implements Backend.
func (n *Nftables) Remove(ctx context.Context) error {
	return n.Apply(ctx, Plan{})
}

// Iptables uses a SURICONTROLLER chain in the filter table of iptables and
// ip6tables, jumped to first from INPUT, FORWARD and OUTPUT.
type Iptables struct {
	Exec platform.Exec
}

// Name implements Backend.
func (*Iptables) Name() string { return "iptables" }

func (t *Iptables) tools() []string {
	out := []string{"iptables"}
	if _, err := t.Exec.LookPath("ip6tables"); err == nil {
		out = append(out, "ip6tables")
	}
	return out
}

func (t *Iptables) target(p Plan) []string {
	args := []string{"-j", "NFQUEUE"}
	if p.QueueLast > p.QueueFirst {
		args = append(args, "--queue-balance", fmt.Sprintf("%d:%d", p.QueueFirst, p.QueueLast))
	} else {
		args = append(args, "--queue-num", fmt.Sprint(p.QueueFirst))
	}
	if p.FailOpen {
		args = append(args, "--queue-bypass")
	}
	return args
}

// Apply implements Backend.
func (t *Iptables) Apply(ctx context.Context, p Plan) error {
	if p.Empty() {
		return t.Remove(ctx)
	}
	p = p.normalized()
	for _, tool := range t.tools() {
		run := func(args ...string) error {
			_, err := t.Exec.Run(ctx, tool, append([]string{"-w"}, args...), nil)
			return err
		}
		if run("-N", ChainName) != nil {
			if err := run("-F", ChainName); err != nil {
				return err
			}
		}
		for _, ifc := range p.Interfaces {
			for _, dir := range []string{"-i", "-o"} {
				if err := run(append([]string{"-A", ChainName, dir, ifc}, t.target(p)...)...); err != nil {
					return err
				}
			}
		}
		for _, hook := range []string{"INPUT", "FORWARD", "OUTPUT"} {
			if run("-C", hook, "-j", ChainName) != nil {
				if err := run("-I", hook, "1", "-j", ChainName); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// Check implements Backend.
func (t *Iptables) Check(ctx context.Context, p Plan) (bool, error) {
	out, err := t.Exec.Run(ctx, "iptables", []string{"-w", "-S", ChainName}, nil)
	if err != nil {
		return p.Empty(), nil
	}
	if p.Empty() {
		return false, nil
	}
	for _, ifc := range p.Interfaces {
		if !strings.Contains(string(out), "-i "+ifc+" ") {
			return false, nil
		}
	}
	for _, hook := range []string{"INPUT", "FORWARD", "OUTPUT"} {
		if _, err := t.Exec.Run(ctx, "iptables", []string{"-w", "-C", hook, "-j", ChainName}, nil); err != nil {
			return false, nil
		}
	}
	return true, nil
}

// Remove implements Backend.
func (t *Iptables) Remove(ctx context.Context) error {
	for _, tool := range t.tools() {
		for _, hook := range []string{"INPUT", "FORWARD", "OUTPUT"} {
			for {
				if _, err := t.Exec.Run(ctx, tool, []string{"-w", "-D", hook, "-j", ChainName}, nil); err != nil {
					break
				}
			}
		}
		_, _ = t.Exec.Run(ctx, tool, []string{"-w", "-F", ChainName}, nil)
		_, _ = t.Exec.Run(ctx, tool, []string{"-w", "-X", ChainName}, nil)
	}
	return nil
}
