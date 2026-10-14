// Command suri-node-agent manages Suricata on a node (router, server or
// endpoint) on behalf of suri-controller.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/jc-lab/suricontroller/agent"
	"github.com/jc-lab/suricontroller/agent/config"
	"github.com/jc-lab/suricontroller/agent/conn"
	"github.com/jc-lab/suricontroller/agent/engine"
	"github.com/jc-lab/suricontroller/agent/firewall"
	"github.com/jc-lab/suricontroller/agent/platform"
	agentv1 "github.com/jc-lab/suricontroller/gen/suricontroller/agent/v1"
	"github.com/jc-lab/suricontroller/pkg/nodeid"
	"github.com/jc-lab/suricontroller/pkg/sshkey"
	"github.com/jc-lab/suricontroller/pkg/version"
)

const defaultConfig = "/etc/suri-agent/agent.yaml"

func usage() {
	fmt.Fprintf(os.Stderr, `Usage: suri-node-agent <command> [flags]

Commands:
  run      run the agent (default)
  keygen   create the agent key and print its public key line
  pubkey   print the public key line to register on the controller
  check    check the configuration, host and controller connectivity
  version  print the version

Flags:
`)
	flag.PrintDefaults()
}

func main() {
	configPath := flag.String("config", envOr("SURI_AGENT_CONFIG", defaultConfig), "agent configuration file")
	nodeID := flag.String("node-id", "", "node id (keygen without a configuration file)")
	keyFile := flag.String("key-file", "", "key file (keygen without a configuration file)")
	flag.Usage = usage
	cmd := "run"
	args := os.Args[1:]
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	if err := flag.CommandLine.Parse(args); err != nil {
		os.Exit(2)
	}
	var err error
	switch cmd {
	case "run":
		err = run(*configPath)
	case "keygen", "pubkey":
		err = keygen(*configPath, *nodeID, *keyFile, cmd == "keygen")
	case "check":
		err = check(*configPath)
	case "version":
		fmt.Println(version.Version)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func newLogger(level string, w io.Writer) *slog.Logger {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: l}))
}

func run(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	tee := &agent.LogTee{}
	log := newLogger(cfg.LogLevel, io.MultiWriter(os.Stderr, tee))
	slog.SetDefault(log)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	a, err := agent.New(ctx, cfg, agent.Options{Logger: log, LogTee: tee})
	if err != nil {
		return err
	}
	// SIGHUP: an external logrotate rotated the log files.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			log.Info("SIGHUP: reopening Suricata log files")
			a.ReopenLogs()
		}
	}()
	return a.Run(ctx)
}

func keygen(configPath, id, keyFile string, create bool) error {
	if id == "" || keyFile == "" {
		// Decode leniently: keygen runs before the configuration is complete.
		cfg := config.Default()
		if b, err := os.ReadFile(configPath); err == nil {
			_ = yaml.Unmarshal(b, cfg)
		}
		if id == "" {
			id = cfg.NodeID
		}
		if keyFile == "" {
			keyFile = cfg.KeyFile
		}
	}
	if err := nodeid.Validate(id); err != nil {
		return fmt.Errorf("%w (set node_id in %s or pass -node-id)", err, configPath)
	}
	var k *sshkey.PrivateKey
	var err error
	if create {
		k, _, err = sshkey.LoadOrGenerate(keyFile, id)
	} else {
		k, err = sshkey.LoadPrivateKey(keyFile)
	}
	if err != nil {
		return err
	}
	fmt.Println(k.Public(id).String())
	return nil
}

func check(configPath string) error {
	ok := true
	report := func(name string, err error, detail string) {
		status := "ok  "
		if err != nil {
			status, ok = "FAIL", false
			detail = err.Error()
		}
		fmt.Printf("[%s] %-14s %s\n", status, name, detail)
	}
	cfg, err := config.Load(configPath)
	report("config", err, configPath)
	if err != nil {
		return errors.New("configuration is invalid")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	key, err := sshkey.LoadPrivateKey(cfg.KeyFile)
	if err == nil {
		report("key", nil, key.Public(cfg.NodeID).String())
	} else {
		report("key", err, "")
	}

	var fs platform.HostFS
	var ex platform.Exec
	if cfg.Platform.Profile == config.ProfileDocker {
		fs, ex = platform.HostFS{Root: cfg.Platform.HostRoot}, platform.ChrootExec{Root: cfg.Platform.HostRoot, Fallback: platform.LocalExec{}}
	} else {
		fs, ex = platform.HostFS{Root: "/"}, platform.LocalExec{}
	}
	info := platform.Probe(ctx, fs, ex)
	report("host", nil, fmt.Sprintf("%s %s %s (kernel %s) fw4=%v nft=%v iptables=%v", info.OSName, info.OSVersion, info.Arch, info.Kernel, info.Fw4, info.Nft, info.Iptables))
	if info.FlowOffload != "" {
		report("flow offload", errors.New(info.FlowOffload+" flow offloading is enabled; offloaded flows bypass Suricata"), "")
	}

	sup := &engine.Supervisor{Binary: cfg.Suricata.Binary}
	ei, err := sup.Info(ctx)
	if err == nil {
		report("suricata", nil, fmt.Sprintf("%s nfq=%v af-packet=%v", ei.Version, ei.NFQ, ei.AFPacket))
	} else {
		report("suricata", err, "")
	}
	fw, err := firewall.New(cfg.Platform.Firewall, ex)
	if err == nil {
		report("firewall", nil, fw.Name())
	} else {
		report("firewall", err, "")
	}
	for _, ifc := range cfg.Interfaces {
		st := platform.Interface(ifc.Name)
		var ierr error
		if !st.Present {
			ierr = errors.New("does not exist")
		}
		report("iface "+ifc.Name, ierr, fmt.Sprintf("up=%v ips_allowed=%v %v", st.Up, cfg.IPSAllowed(ifc.Name), st.Addresses))
	}
	if _, err := os.Stat(cfg.Suricata.BaseConfig); err != nil {
		report("base config", err, "")
	} else {
		report("base config", nil, cfg.Suricata.BaseConfig)
	}

	if key != nil {
		hostKey, _ := sshkey.ParsePublicKey(cfg.Controller.HostKey)
		sess, err := conn.Dial(ctx, conn.Config{URL: cfg.Controller.URL, Key: key, ServerKey: hostKey, NodeID: cfg.NodeID, AgentVersion: version.Version},
			&agentv1.Hello{NodeId: cfg.NodeID, AgentVersion: version.Version}, func(context.Context, *agentv1.Envelope) (*agentv1.Envelope, error) { return nil, nil })
		if err == nil {
			report("controller", nil, cfg.Controller.URL+" (controller "+sess.HelloAck().ControllerVersion+")")
			sess.Close()
		} else {
			report("controller", err, "")
		}
	}
	if !ok {
		return errors.New("some checks failed")
	}
	return nil
}
