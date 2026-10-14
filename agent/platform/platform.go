// Package platform abstracts how the agent reaches the host it manages.
// In the docker profile the host filesystem is mounted at /host and host
// tools (nft, iptables, uci, fw4) run through chroot; a native install uses
// the local filesystem and tools directly.
package platform

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// Exec runs host tools.
type Exec interface {
	// Run executes name with args, feeding stdin, and returns stdout.
	// Errors include stderr.
	Run(ctx context.Context, name string, args []string, stdin []byte) ([]byte, error)
	// LookPath reports whether a tool exists on the host.
	LookPath(name string) (string, error)
}

// LocalExec runs tools of the local filesystem.
type LocalExec struct{}

// Run implements Exec.
func (LocalExec) Run(ctx context.Context, name string, args []string, stdin []byte) ([]byte, error) {
	return run(ctx, name, args, stdin)
}

// LookPath implements Exec.
func (LocalExec) LookPath(name string) (string, error) { return exec.LookPath(name) }

func run(ctx context.Context, name string, args []string, stdin []byte) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = strings.TrimSpace(stdout.String())
		}
		return stdout.Bytes(), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, msg)
	}
	return stdout.Bytes(), nil
}

// hostBinDirs are searched for host tools.
var hostBinDirs = []string{"/usr/sbin", "/sbin", "/usr/bin", "/bin", "/usr/local/sbin", "/usr/local/bin"}

// ChrootExec runs host tools with chroot into Root, falling back to tools of
// the agent's own filesystem when the host lacks them. Because the agent
// shares the host network namespace, container tools act on the host too.
type ChrootExec struct {
	Root     string
	Fallback Exec
}

func (c ChrootExec) hostPath(name string) string {
	for _, d := range hostBinDirs {
		p := filepath.Join(c.Root, d, name)
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return filepath.Join(d, name)
		}
	}
	return ""
}

// Run implements Exec.
func (c ChrootExec) Run(ctx context.Context, name string, args []string, stdin []byte) ([]byte, error) {
	if p := c.hostPath(name); p != "" {
		return run(ctx, "chroot", append([]string{c.Root, p}, args...), stdin)
	}
	if c.Fallback != nil {
		return c.Fallback.Run(ctx, name, args, stdin)
	}
	return nil, fmt.Errorf("%s: %w", name, exec.ErrNotFound)
}

// LookPath implements Exec.
func (c ChrootExec) LookPath(name string) (string, error) {
	if p := c.hostPath(name); p != "" {
		return filepath.Join(c.Root, p), nil
	}
	if c.Fallback != nil {
		return c.Fallback.LookPath(name)
	}
	return "", exec.ErrNotFound
}

// HostFS gives access to host files.
type HostFS struct {
	Root string // "/" for native installs
}

// Path maps a host path to the agent's filesystem.
func (h HostFS) Path(p string) string {
	if h.Root == "" || h.Root == "/" {
		return p
	}
	return filepath.Join(h.Root, p)
}

// ReadFile reads a host file.
func (h HostFS) ReadFile(p string) ([]byte, error) { return os.ReadFile(h.Path(p)) }

// Exists reports whether a host path exists.
func (h HostFS) Exists(p string) bool {
	_, err := os.Stat(h.Path(p))
	return err == nil
}

// Info describes the host.
type Info struct {
	OSName      string
	OSVersion   string
	Arch        string
	Hostname    string
	Kernel      string
	OpenWrt     bool
	Fw4         bool
	Nft         bool
	Iptables    bool
	FlowOffload string // "", "software" or "hardware"
}

// Probe inspects the host.
func Probe(ctx context.Context, fs HostFS, ex Exec) Info {
	info := Info{Arch: runtime.GOARCH}
	if b, err := fs.ReadFile("/etc/openwrt_release"); err == nil {
		kv := parseShellVars(b)
		info.OpenWrt = true
		info.OSName = "OpenWrt"
		info.OSVersion = kv["DISTRIB_RELEASE"]
		if arch := kv["DISTRIB_ARCH"]; arch != "" {
			info.Arch = arch
		}
	} else if b, err := fs.ReadFile("/etc/os-release"); err == nil {
		kv := parseShellVars(b)
		info.OSName = kv["NAME"]
		info.OSVersion = kv["VERSION_ID"]
	}
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		info.Kernel = strings.TrimSpace(string(b))
	}
	if b, err := fs.ReadFile("/etc/hostname"); err == nil && len(bytes.TrimSpace(b)) > 0 {
		info.Hostname = strings.TrimSpace(string(b))
	} else if b, err := os.ReadFile("/proc/sys/kernel/hostname"); err == nil {
		info.Hostname = strings.TrimSpace(string(b))
	}
	_, err := ex.LookPath("fw4")
	info.Fw4 = err == nil
	_, err = ex.LookPath("nft")
	info.Nft = err == nil
	_, err = ex.LookPath("iptables")
	info.Iptables = err == nil
	if info.OpenWrt {
		info.FlowOffload = flowOffload(ctx, ex)
	}
	return info
}

func flowOffload(ctx context.Context, ex Exec) string {
	get := func(opt string) bool {
		out, err := ex.Run(ctx, "uci", []string{"-q", "get", "firewall.@defaults[0]." + opt}, nil)
		return err == nil && strings.TrimSpace(string(out)) == "1"
	}
	switch {
	case get("flow_offloading_hw"):
		return "hardware"
	case get("flow_offloading"):
		return "software"
	}
	return ""
}

func parseShellVars(b []byte) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok || strings.HasPrefix(k, "#") {
			continue
		}
		out[k] = strings.Trim(v, `"'`)
	}
	return out
}

// InterfaceState describes a network interface of the host.
type InterfaceState struct {
	Present   bool
	Up        bool
	Addresses []string
}

// Interface reports the state of a host interface. The agent shares the
// host network namespace, so the local view is the host's.
func Interface(name string) InterfaceState {
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return InterfaceState{}
	}
	st := InterfaceState{Present: true, Up: ifc.Flags&net.FlagUp != 0}
	if addrs, err := ifc.Addrs(); err == nil {
		for _, a := range addrs {
			st.Addresses = append(st.Addresses, a.String())
		}
	}
	return st
}

// ErrUnsupported is returned for profile features not implemented yet.
var ErrUnsupported = errors.New("platform: not supported by this profile")
