// Package config loads the agent configuration (agent.yaml). The node user
// decides here which interfaces the controller may manage, whether IPS is
// allowed, and where Suricata writes its logs.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/jc-lab/suricontroller/pkg/nodeid"
	"github.com/jc-lab/suricontroller/pkg/sshkey"
)

// Profiles.
const (
	ProfileDocker        = "docker"
	ProfileOpenWrtNative = "openwrt-native"
	ProfileSystemdNative = "systemd-native"
)

// Instance names.
const (
	InstanceIDS = "ids"
	InstanceIPS = "ips"
)

// ByteSize is a size accepting suffixes like "16MiB", "64MB", "1G".
type ByteSize int64

// UnmarshalYAML implements yaml.Unmarshaler.
func (b *ByteSize) UnmarshalYAML(n *yaml.Node) error {
	v, err := ParseByteSize(n.Value)
	if err != nil {
		return err
	}
	*b = ByteSize(v)
	return nil
}

// ParseByteSize parses a size with an optional unit suffix.
func ParseByteSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	units := []struct {
		suffix string
		mult   int64
	}{
		{"KiB", 1 << 10}, {"MiB", 1 << 20}, {"GiB", 1 << 30},
		{"KB", 1000}, {"MB", 1000 * 1000}, {"GB", 1000 * 1000 * 1000},
		{"K", 1 << 10}, {"M", 1 << 20}, {"G", 1 << 30}, {"B", 1},
	}
	for _, u := range units {
		if num, ok := strings.CutSuffix(s, u.suffix); ok {
			v, err := strconv.ParseFloat(strings.TrimSpace(num), 64)
			if err != nil || v < 0 {
				return 0, fmt.Errorf("invalid size %q", s)
			}
			return int64(v * float64(u.mult)), nil
		}
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil || v < 0 {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	return v, nil
}

// Interface is an interface the controller may manage.
type Interface struct {
	Name string `yaml:"name"`
	// IPS overrides ips.enabled for this interface.
	IPS *bool `yaml:"ips"`
}

// Instance configures one Suricata instance.
type Instance struct {
	// LogDir is forced as default-log-dir of the instance.
	LogDir string `yaml:"log_dir"`
}

// LogSource is an additional file to collect.
type LogSource struct {
	Type     string `yaml:"type"` // eve | suricata | fast | stats
	Path     string `yaml:"path"`
	Instance string `yaml:"instance"`
}

// Config is the agent configuration.
type Config struct {
	NodeID  string `yaml:"node_id"`
	KeyFile string `yaml:"key_file"`

	Controller struct {
		URL     string            `yaml:"url"`
		HostKey string            `yaml:"host_key"`
		Headers map[string]string `yaml:"headers"`
		// CAFile adds trusted CAs for wss:// (the Noise layer authenticates
		// the controller regardless).
		CAFile string `yaml:"ca_file"`
		// TLSInsecureSkipVerify skips TLS certificate verification.
		TLSInsecureSkipVerify bool `yaml:"tls_insecure_skip_verify"`
	} `yaml:"controller"`

	Platform struct {
		Profile  string `yaml:"profile"`
		HostRoot string `yaml:"host_root"`
		Firewall string `yaml:"firewall"`
	} `yaml:"platform"`

	Interfaces []Interface `yaml:"interfaces"`

	IPS struct {
		Enabled bool `yaml:"enabled"`
		// Queues is a NFQUEUE number or range ("0" or "0-3").
		Queues   string `yaml:"queues"`
		FailOpen *bool  `yaml:"fail_open"`
	} `yaml:"ips"`

	Suricata struct {
		Binary        string              `yaml:"binary"`
		BaseConfig    string              `yaml:"base_config"`
		LocalRulesDir string              `yaml:"local_rules_dir"`
		AllowLua      bool                `yaml:"allow_lua"`
		Instances     map[string]Instance `yaml:"instances"`
		// HomeNetInterfaceAddresses adds the addresses of the interfaces an
		// instance captures on to its HOME_NET (default true): a WAN-facing
		// instance then sees the node's public addresses as home. They
		// follow DHCP/PPPoE changes with a rule reload, not a restart.
		HomeNetInterfaceAddresses bool `yaml:"home_net_interface_addresses"`
		// ValidateTimeout bounds `suricata -T`.
		ValidateTimeout time.Duration `yaml:"validate_timeout"`
		ExtraArgs       []string      `yaml:"extra_args"`
	} `yaml:"suricata"`

	Logs struct {
		QueueMaxBytes ByteSize    `yaml:"queue_max_bytes"`
		StartPosition string      `yaml:"start_position"`
		ExtraSources  []LogSource `yaml:"extra_sources"`
		Rotation      struct {
			Enabled bool     `yaml:"enabled"`
			MaxSize ByteSize `yaml:"max_size"`
			Keep    int      `yaml:"keep"`
		} `yaml:"rotation"`
	} `yaml:"logs"`

	StateDir string `yaml:"state_dir"`
	RunDir   string `yaml:"run_dir"`
	LogLevel string `yaml:"log_level"`

	// ExternalController: the program embedding the agent supplies the
	// controller endpoint (agent.Options.Controller), so the controller
	// url and host_key may be left out. Set by ParseWith.
	ExternalController bool `yaml:"-"`
}

// Default returns the configuration defaults.
func Default() *Config {
	c := &Config{KeyFile: "/etc/suri-agent/agent_ed25519", StateDir: "/var/lib/suri-agent", RunDir: "/run/suri-agent", LogLevel: "info"}
	c.Platform.Profile = ProfileDocker
	c.Platform.HostRoot = "/host"
	c.Platform.Firewall = "auto"
	c.IPS.Queues = "0"
	c.Suricata.Binary = "suricata"
	c.Suricata.BaseConfig = "/etc/suricata/suricata.yaml"
	c.Suricata.LocalRulesDir = "/etc/suricata/rules.local"
	c.Suricata.ValidateTimeout = 5 * time.Minute
	c.Suricata.HomeNetInterfaceAddresses = true
	c.Suricata.Instances = map[string]Instance{
		InstanceIDS: {LogDir: "/var/log/suricata/ids"},
		InstanceIPS: {LogDir: "/var/log/suricata/ips"},
	}
	c.Logs.QueueMaxBytes = 16 << 20
	c.Logs.StartPosition = "end"
	c.Logs.Rotation.Enabled = true
	c.Logs.Rotation.MaxSize = 64 << 20
	c.Logs.Rotation.Keep = 2
	return c
}

// Load reads and validates the configuration file.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

// Parse decodes and validates configuration data.
func Parse(b []byte) (*Config, error) { return ParseWith(b, ParseOptions{}) }

// ParseOptions changes what Parse accepts.
type ParseOptions struct {
	// ExternalController sets Config.ExternalController.
	ExternalController bool
}

// ParseWith is Parse with options.
func ParseWith(b []byte, o ParseOptions) (*Config, error) {
	c := Default()
	c.ExternalController = o.ExternalController
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(c); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	for name, def := range Default().Suricata.Instances {
		inst := c.Suricata.Instances[name]
		if inst.LogDir == "" {
			inst.LogDir = def.LogDir
		}
		c.Suricata.Instances[name] = inst
	}
	return c, c.Validate()
}

// Validate checks the configuration and makes local paths absolute.
func (c *Config) Validate() error {
	var errs []error
	for _, p := range []*string{&c.StateDir, &c.RunDir, &c.KeyFile, &c.Suricata.BaseConfig, &c.Suricata.LocalRulesDir} {
		if *p != "" {
			if abs, err := filepath.Abs(*p); err == nil {
				*p = abs
			}
		}
	}
	if err := nodeid.Validate(c.NodeID); err != nil {
		errs = append(errs, fmt.Errorf("node_id: %w", err))
	}
	if !c.ExternalController || c.Controller.URL != "" || c.Controller.HostKey != "" {
		if c.Controller.URL == "" {
			errs = append(errs, errors.New("controller.url is required"))
		} else if !strings.HasPrefix(c.Controller.URL, "ws://") && !strings.HasPrefix(c.Controller.URL, "wss://") {
			errs = append(errs, errors.New("controller.url must start with ws:// or wss://"))
		}
		if _, err := sshkey.ParsePublicKey(c.Controller.HostKey); err != nil {
			errs = append(errs, fmt.Errorf("controller.host_key: %w", err))
		}
	}
	switch c.Platform.Profile {
	case ProfileDocker, ProfileOpenWrtNative, ProfileSystemdNative:
	default:
		errs = append(errs, fmt.Errorf("platform.profile: unknown profile %q", c.Platform.Profile))
	}
	switch c.Platform.Firewall {
	case "auto", "nftables", "iptables", "none":
	default:
		errs = append(errs, fmt.Errorf("platform.firewall: unknown backend %q", c.Platform.Firewall))
	}
	seen := map[string]bool{}
	for _, ifc := range c.Interfaces {
		if ifc.Name == "" || strings.ContainsAny(ifc.Name, " \t\"'/{}") || len(ifc.Name) > 15 {
			errs = append(errs, fmt.Errorf("interfaces: invalid name %q", ifc.Name))
		}
		if seen[ifc.Name] {
			errs = append(errs, fmt.Errorf("interfaces: duplicate %q", ifc.Name))
		}
		seen[ifc.Name] = true
	}
	if _, _, err := c.QueueRange(); err != nil {
		errs = append(errs, err)
	}
	if c.Logs.StartPosition != "end" && c.Logs.StartPosition != "beginning" {
		errs = append(errs, errors.New("logs.start_position must be end or beginning"))
	}
	for name, inst := range c.Suricata.Instances {
		if name != InstanceIDS && name != InstanceIPS {
			errs = append(errs, fmt.Errorf("suricata.instances: unknown instance %q", name))
		}
		if !strings.HasPrefix(inst.LogDir, "/") {
			errs = append(errs, fmt.Errorf("suricata.instances.%s.log_dir must be absolute", name))
		}
	}
	if c.Suricata.Instances[InstanceIDS].LogDir == c.Suricata.Instances[InstanceIPS].LogDir {
		errs = append(errs, errors.New("suricata.instances: ids and ips must use different log directories"))
	}
	return errors.Join(errs...)
}

// IPSAllowed reports whether the controller may set IPS mode on iface.
func (c *Config) IPSAllowed(iface string) bool {
	for _, ifc := range c.Interfaces {
		if ifc.Name == iface {
			if ifc.IPS != nil {
				return *ifc.IPS
			}
			return c.IPS.Enabled
		}
	}
	return false
}

// Managed reports whether iface is listed in the configuration.
func (c *Config) Managed(iface string) bool {
	for _, ifc := range c.Interfaces {
		if ifc.Name == iface {
			return true
		}
	}
	return false
}

// FailOpen reports whether IPS should let traffic pass when Suricata is down.
func (c *Config) FailOpen() bool { return c.IPS.FailOpen == nil || *c.IPS.FailOpen }

// QueueRange returns the NFQUEUE range.
func (c *Config) QueueRange() (uint16, uint16, error) {
	s := strings.TrimSpace(c.IPS.Queues)
	lo, hi, isRange := strings.Cut(s, "-")
	a, err := strconv.ParseUint(strings.TrimSpace(lo), 10, 16)
	if err != nil {
		return 0, 0, fmt.Errorf("ips.queues: invalid %q", s)
	}
	b := a
	if isRange {
		if b, err = strconv.ParseUint(strings.TrimSpace(hi), 10, 16); err != nil || b < a {
			return 0, 0, fmt.Errorf("ips.queues: invalid %q", s)
		}
	}
	return uint16(a), uint16(b), nil
}

// LogDir returns the log directory of an instance.
func (c *Config) LogDir(instance string) string {
	return c.Suricata.Instances[instance].LogDir
}
