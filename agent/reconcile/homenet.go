package reconcile

import (
	"context"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/jc-lab/suricontroller/agent/config"
	agentv1 "github.com/jc-lab/suricontroller/gen/suricontroller/agent/v1"
)

// HOME_NET interface addresses (config suricata.home_net_interface_addresses).
// An instance's HOME_NET gets the addresses of the interfaces it captures
// on, so a WAN-facing instance sees the node's public addresses as home.
// They are polled; a change stable for homeNetSettle is applied with a rule
// reload (Suricata re-reads the address groups), at most once per
// homeNetMinInterval: a reload builds a second detection engine, so memory
// briefly doubles.
const (
	homeNetPoll        = 5 * time.Second
	homeNetSettle      = 5 * time.Second
	homeNetMinInterval = time.Minute
)

// ifaceAddrs lists the addresses of an interface. Addresses carrying a
// label ("eth2:vip", ifconfig aliases) belong to the device and are
// included: they are looked up by interface index.
var ifaceAddrs = func(name string) ([]netip.Addr, error) {
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	addrs, err := ifc.Addrs()
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	for _, a := range addrs {
		if p, err := netip.ParsePrefix(a.String()); err == nil {
			out = append(out, p.Addr())
		}
	}
	return out, nil
}

// homeAddrs is a snapshot: interface -> sorted addresses.
type homeAddrs map[string][]string

func (h homeAddrs) equal(o homeAddrs) bool {
	return maps.EqualFunc(h, o, slices.Equal[[]string])
}

// of returns the addresses of ifaces, sorted and without duplicates.
func (h homeAddrs) of(ifaces []string) []string {
	var out []string
	for _, ifc := range ifaces {
		out = append(out, h[ifc]...)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// readHomeAddrs reads the addresses of ifaces. Loopback, link-local and
// multicast addresses are left out. An interface with no address left
// (PPPoE down, a VIP moved to the peer router, the device gone) keeps its
// previous addresses: a reconnect then costs one reload, not two, and a
// stale address of the node's own does no harm in HOME_NET.
func readHomeAddrs(ifaces []string, prev homeAddrs) homeAddrs {
	out := homeAddrs{}
	for _, name := range ifaces {
		dev, _, _ := strings.Cut(name, ":")
		addrs, _ := ifaceAddrs(dev)
		var list []string
		for _, a := range addrs {
			a = a.Unmap()
			if !a.IsValid() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsMulticast() || a.IsUnspecified() {
				continue
			}
			list = append(list, a.WithZone("").String())
		}
		slices.Sort(list)
		list = slices.Compact(list)
		if len(list) == 0 {
			list = prev[name]
		}
		if len(list) > 0 {
			out[name] = list
		}
	}
	return out
}

// homeNetIfaces returns the interfaces of a plan's instances.
func homeNetIfaces(p plan) []string {
	return append(p.interfaces(agentv1.InterfaceMode_INTERFACE_MODE_IDS), p.interfaces(agentv1.InterfaceMode_INTERFACE_MODE_IPS)...)
}

// homeNetFor returns the HOME_NET addresses of an instance capturing on
// ifaces, reading interfaces not seen yet. Called from the Run goroutine
// (or before it starts).
func (r *Reconciler) homeNetFor(ifaces []string) []string {
	if !r.d.Config.Suricata.HomeNetInterfaceAddresses {
		return nil
	}
	r.homeMu.Lock()
	defer r.homeMu.Unlock()
	var missing []string
	for _, ifc := range ifaces {
		if _, ok := r.home[ifc]; !ok {
			missing = append(missing, ifc)
		}
	}
	if len(missing) > 0 {
		if r.home == nil {
			r.home = homeAddrs{}
		}
		maps.Copy(r.home, readHomeAddrs(missing, r.home))
	}
	return r.home.of(ifaces)
}

// HomeNetAddresses returns the addresses added to an instance's HOME_NET.
func (r *Reconciler) HomeNetAddresses(instance string) []string {
	r.mu.Lock()
	p := planOf(r.cur.applied)
	r.mu.Unlock()
	var ifaces []string
	switch instance {
	case config.InstanceIDS:
		ifaces = p.interfaces(agentv1.InterfaceMode_INTERFACE_MODE_IDS)
	case config.InstanceIPS:
		ifaces = p.interfaces(agentv1.InterfaceMode_INTERFACE_MODE_IPS)
	}
	if !r.d.Config.Suricata.HomeNetInterfaceAddresses {
		return nil
	}
	r.homeMu.Lock()
	defer r.homeMu.Unlock()
	return r.home.of(ifaces)
}

// checkHomeNet polls the interface addresses and applies a settled change
// to the running instances.
func (r *Reconciler) checkHomeNet(ctx context.Context, now time.Time) {
	if !r.d.Config.Suricata.HomeNetInterfaceAddresses {
		return
	}
	r.mu.Lock()
	cur := r.cur
	r.mu.Unlock()
	if cur.applied == nil {
		return
	}
	ifaces := homeNetIfaces(planOf(cur.applied))
	r.homeMu.Lock()
	applied := homeAddrs{}
	for _, ifc := range ifaces {
		if a, ok := r.home[ifc]; ok {
			applied[ifc] = a
		}
	}
	seen := readHomeAddrs(ifaces, applied)
	switch {
	case seen.equal(applied):
		r.homePending = nil
		r.homeMu.Unlock()
		return
	case r.homePending == nil || !seen.equal(r.homePending):
		// Wait until it settles (PPPoE reconnects, DHCP renumbering).
		r.homePending, r.homePendingSince = seen, now
		r.homeMu.Unlock()
		return
	case now.Sub(r.homePendingSince) < homeNetSettle || now.Sub(r.homeReloadAt) < homeNetMinInterval:
		r.homeMu.Unlock()
		return
	}
	r.home, r.homePending, r.homeReloadAt = seen, nil, now
	r.homeMu.Unlock()
	r.log.Info("interface addresses changed; updating HOME_NET", "addresses", seen)
	r.reloadHomeNet(ctx, cur)
}

// reloadHomeNet rewrites the running configurations with the current
// addresses and reloads the rules of the instances whose file changed.
func (r *Reconciler) reloadHomeNet(ctx context.Context, cur current) {
	running, err := r.render(planOf(cur.applied), false)
	if err != nil {
		r.log.Error("render configuration for new HOME_NET", "err", err)
		return
	}
	for _, spec := range running.specs {
		if !kept(cur.specs, spec) {
			// Anything else changed too: leave it to the regular paths.
			r.log.Warn("configuration changed beyond HOME_NET; not reloading", "instance", spec.Name)
			return
		}
	}
	for _, spec := range running.specs {
		data := running.files[spec.ConfigPath]
		if string(cur.rendered[spec.ConfigPath]) == string(data) {
			continue
		}
		if err := writeFiles(map[string][]byte{spec.ConfigPath: data}); err != nil {
			r.log.Error("write configuration", "path", spec.ConfigPath, "err", err)
			continue
		}
		rctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
		err := r.d.Engine.ReloadRules(rctx, spec.Name)
		cancel()
		if err != nil {
			// The file is written: a restart picks the addresses up.
			r.log.Error("reload rules for new HOME_NET", "instance", spec.Name, "err", err)
		}
	}
	r.mu.Lock()
	r.cur.rendered, r.cur.instances = running.files, running.instances
	r.mu.Unlock()
	if r.d.OnInstances != nil {
		r.d.OnInstances(running.instances)
	}
}
