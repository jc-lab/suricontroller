package reconcile

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/jc-lab/suricontroller/gen/suricontroller/agent/v1"
	"github.com/jc-lab/suricontroller/pkg/yamlmerge"
)

// fakeIfaces serves interface addresses.
type fakeIfaces struct {
	mu    sync.Mutex
	addrs map[string][]string
}

func (f *fakeIfaces) set(name string, addrs ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.addrs[name] = addrs
}

// remove makes the interface disappear (a PPPoE device going away).
func (f *fakeIfaces) remove(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.addrs, name)
}

func (f *fakeIfaces) read(name string) ([]netip.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	list, ok := f.addrs[name]
	if !ok {
		return nil, errors.New("no such interface")
	}
	var out []netip.Addr
	for _, a := range list {
		out = append(out, netip.MustParseAddr(a))
	}
	return out, nil
}

func runningHomeNet(t *testing.T, e *env, instance string) string {
	t.Helper()
	b, err := os.ReadFile(e.eng.running[instance].ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := yamlmerge.Parse(b)
	return yamlmerge.GetString(n, "vars", "address-groups", "HOME_NET")
}

func TestHomeNetInterfaceAddresses(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, t.TempDir())
	ifs := &fakeIfaces{addrs: map[string][]string{
		// An address on an alias label (ifconfig "eth2:vip") belongs to eth2;
		// link-local addresses are left out.
		"eth1": {"125.131.127.16", "fe80::b4ca:13ff:feab:10d", "2001:db8::10"},
		"eth0": {"192.168.1.1"},
	}}
	ifaceAddrs = ifs.read
	b := e.bundle(t, rulesA, "")
	rep := e.rec.apply(ctx, &agentv1.DesiredState{Generation: 1, Bundle: b, InterfaceModes: modes("eth1", "IDS", "eth0", "IPS")})
	if rep.Status != agentv1.ApplyStatus_APPLY_STATUS_SUCCEEDED {
		t.Fatalf("apply: %v %s", rep.Status, rep.Message)
	}
	if got := runningHomeNet(t, e, "ids"); got != "[[192.168.0.0/16],125.131.127.16,2001:db8::10]" {
		t.Fatalf("ids HOME_NET = %q", got)
	}
	if got := runningHomeNet(t, e, "ips"); got != "[[192.168.0.0/16],192.168.1.1]" {
		t.Fatalf("ips HOME_NET = %q", got)
	}
	if got := e.rec.HomeNetAddresses("ids"); !slices.Equal(got, []string{"125.131.127.16", "2001:db8::10"}) {
		t.Fatalf("status = %v", got)
	}

	// DHCP renumbering: applied once it settled, with a rule reload of the
	// instance concerned only; nothing restarts.
	hash, calls := e.eng.running["ids"].ConfigHash, e.eng.ensureCalls
	now := time.Now()
	ifs.set("eth1", "125.131.127.20", "2001:db8::10")
	e.rec.checkHomeNet(ctx, now)
	if len(e.eng.reloads) != 0 {
		t.Fatal("applied before settling")
	}
	e.rec.checkHomeNet(ctx, now.Add(homeNetPoll))
	if !slices.Equal(e.eng.reloads, []string{"ids"}) || e.eng.ensureCalls != calls || e.eng.running["ids"].ConfigHash != hash {
		t.Fatalf("reloads=%v ensure %d->%d", e.eng.reloads, calls, e.eng.ensureCalls)
	}
	if got := runningHomeNet(t, e, "ids"); !strings.Contains(got, "125.131.127.20") || strings.Contains(got, "125.131.127.16") {
		t.Fatalf("ids HOME_NET = %q", got)
	}

	// The address leaves (PPPoE down, VIP moved): the last ones stay.
	ifs.set("eth1", "fe80::b4ca:13ff:feab:10d")
	e.rec.checkHomeNet(ctx, now.Add(2*homeNetPoll))
	e.rec.checkHomeNet(ctx, now.Add(3*homeNetPoll))
	ifs.remove("eth1")
	e.rec.checkHomeNet(ctx, now.Add(4*homeNetPoll))
	if len(e.eng.reloads) != 1 {
		t.Fatalf("reloaded for a lost address: %v", e.eng.reloads)
	}

	// Back with a new address shortly after the last reload: applied once
	// the minimum interval passed.
	ifs.set("eth1", "125.131.127.30")
	at := now.Add(homeNetPoll + homeNetSettle)
	e.rec.checkHomeNet(ctx, at)
	e.rec.checkHomeNet(ctx, at.Add(homeNetSettle))
	if len(e.eng.reloads) != 1 {
		t.Fatal("reloaded within the minimum interval")
	}
	e.rec.checkHomeNet(ctx, now.Add(homeNetPoll+homeNetMinInterval))
	if len(e.eng.reloads) != 2 || !strings.Contains(runningHomeNet(t, e, "ids"), "125.131.127.30") {
		t.Fatalf("reloads=%v HOME_NET=%q", e.eng.reloads, runningHomeNet(t, e, "ids"))
	}
}

func TestHomeNetDisabled(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, t.TempDir())
	e.cfg.Suricata.HomeNetInterfaceAddresses = false
	ifaceAddrs = (&fakeIfaces{addrs: map[string][]string{"eth0": {"125.131.127.16"}}}).read
	rep := e.rec.apply(ctx, &agentv1.DesiredState{Generation: 1, Bundle: e.bundle(t, rulesA, ""), InterfaceModes: modes("eth0", "IDS")})
	if rep.Status != agentv1.ApplyStatus_APPLY_STATUS_SUCCEEDED || runningHomeNet(t, e, "ids") != "[192.168.0.0/16]" {
		t.Fatalf("HOME_NET = %q", runningHomeNet(t, e, "ids"))
	}
}

func TestReadHomeAddrsLabels(t *testing.T) {
	ifs := &fakeIfaces{addrs: map[string][]string{"eth2": {"125.131.127.16", "fe80::1", "127.0.0.1", "::ffff:198.51.100.7"}}}
	orig := ifaceAddrs
	ifaceAddrs = ifs.read
	t.Cleanup(func() { ifaceAddrs = orig })
	got := readHomeAddrs([]string{"eth2:vip"}, nil)
	if !slices.Equal(got["eth2:vip"], []string{"125.131.127.16", "198.51.100.7"}) {
		t.Fatalf("got %v", got)
	}
}
