// Command suri-controller runs the central Suricata controller with the
// built-in web UI and a fixed administrator account.
package main

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"go.yaml.in/yaml/v3"
	"golang.org/x/crypto/bcrypt"

	"github.com/jc-lab/suricontroller/controller"
	"github.com/jc-lab/suricontroller/controller/auth"
	"github.com/jc-lab/suricontroller/pkg/sshkey"
	"github.com/jc-lab/suricontroller/pkg/version"
	"github.com/jc-lab/suricontroller/pkg/wire"
	"github.com/jc-lab/suricontroller/web"
)

// Config is the suri-controller configuration file.
type Config struct {
	Listen  string `yaml:"listen"`
	DataDir string `yaml:"data_dir"`
	TLS     struct {
		CertFile string `yaml:"cert_file"`
		KeyFile  string `yaml:"key_file"`
	} `yaml:"tls"`
	Admin struct {
		Username     string `yaml:"username"`
		Password     string `yaml:"password"`
		PasswordHash string `yaml:"password_hash"`
	} `yaml:"admin"`
	// InsecureCookie drops the Secure attribute from session cookies; only
	// for plain-HTTP deployments.
	InsecureCookie    bool   `yaml:"insecure_cookie"`
	TrustProxyHeaders bool   `yaml:"trust_proxy_headers"`
	LogLevel          string `yaml:"log_level"`
	// ETOpen enables the default ET Open provider on first start.
	ETOpen *bool `yaml:"et_open"`
}

func defaultConfig() *Config {
	c := &Config{Listen: ":8080", DataDir: "/var/lib/suricontroller", LogLevel: "info"}
	c.Admin.Username = "admin"
	return c
}

func loadConfig(path string) (*Config, error) {
	c := defaultConfig()
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		dec := yaml.NewDecoder(strings.NewReader(string(b)))
		dec.KnownFields(true)
		if err := dec.Decode(c); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	env := func(name string, dst *string) {
		if v, ok := os.LookupEnv(name); ok {
			*dst = v
		}
	}
	env("SURICONTROLLER_LISTEN", &c.Listen)
	env("SURICONTROLLER_DATA_DIR", &c.DataDir)
	env("SURICONTROLLER_ADMIN_USERNAME", &c.Admin.Username)
	env("SURICONTROLLER_ADMIN_PASSWORD", &c.Admin.Password)
	env("SURICONTROLLER_ADMIN_PASSWORD_HASH", &c.Admin.PasswordHash)
	env("SURICONTROLLER_LOG_LEVEL", &c.LogLevel)
	if v := os.Getenv("SURICONTROLLER_INSECURE_COOKIE"); v != "" {
		c.InsecureCookie = v == "1" || strings.EqualFold(v, "true")
	}
	if v := os.Getenv("SURICONTROLLER_TRUST_PROXY_HEADERS"); v != "" {
		c.TrustProxyHeaders = v == "1" || strings.EqualFold(v, "true")
	}
	if v := os.Getenv("SURICONTROLLER_ET_OPEN"); v != "" {
		b := v == "1" || strings.EqualFold(v, "true")
		c.ETOpen = &b
	}
	return c, nil
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage: suri-controller [command] [flags]

Commands:
  serve          run the controller (default)
  hostkey        print the controller host public key (for agent.yaml)
  hash-password  read a password from stdin and print its bcrypt hash
  version        print the version

Flags:
`)
	flag.PrintDefaults()
}

func main() {
	configPath := flag.String("config", os.Getenv("SURICONTROLLER_CONFIG"), "configuration file")
	flag.Usage = usage
	cmd := "serve"
	args := os.Args[1:]
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	if err := flag.CommandLine.Parse(args); err != nil {
		os.Exit(2)
	}
	var err error
	switch cmd {
	case "serve":
		err = serve(*configPath)
	case "hostkey":
		err = printHostKey(*configPath)
	case "hash-password":
		err = hashPassword()
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

func newLogger(level string) *slog.Logger {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
}

func printHostKey(configPath string) error {
	cfg, err := loadConfig(configPath)
	if err != nil {
		return err
	}
	k, _, err := sshkey.LoadOrGenerate(filepath.Join(cfg.DataDir, "hostkey"), controller.HostKeyComment)
	if err != nil {
		return err
	}
	fmt.Println(k.Public(controller.HostKeyComment).String())
	return nil
}

func hashPassword() error {
	var pw string
	if _, err := fmt.Fscanln(os.Stdin, &pw); err != nil {
		return err
	}
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	fmt.Println(string(h))
	return nil
}

// sessionSecret loads or creates the cookie signing secret.
func sessionSecret(dataDir string) ([]byte, error) {
	p := filepath.Join(dataDir, "session.key")
	b, err := os.ReadFile(p)
	if err == nil && len(b) >= 32 {
		return b, nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	b = make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return nil, err
	}
	return b, os.WriteFile(p, b, 0o600)
}

func serve(configPath string) error {
	cfg, err := loadConfig(configPath)
	if err != nil {
		return err
	}
	log := newLogger(cfg.LogLevel)

	var admin *auth.StaticAdmin
	switch {
	case cfg.Admin.PasswordHash != "":
		admin, err = auth.NewStaticAdminHash(cfg.Admin.Username, cfg.Admin.PasswordHash)
	case cfg.Admin.Password != "":
		admin, err = auth.NewStaticAdmin(cfg.Admin.Username, cfg.Admin.Password)
	default:
		err = errors.New("an admin password is required (admin.password, admin.password_hash or SURICONTROLLER_ADMIN_PASSWORD)")
	}
	if err != nil {
		return err
	}
	secret, err := sessionSecret(cfg.DataDir)
	if err != nil {
		return err
	}
	insecure := cfg.InsecureCookie
	sessions, err := auth.NewCookieSession(auth.CookieSessionConfig{Login: admin, Secret: secret, Insecure: insecure})
	if err != nil {
		return err
	}

	ctl, err := controller.New(controller.Options{
		DataDir:           cfg.DataDir,
		Auth:              sessions,
		Logger:            log,
		TrustProxyHeaders: cfg.TrustProxyHeaders,
		DisableETOpen:     cfg.ETOpen != nil && !*cfg.ETOpen,
	})
	if err != nil {
		return err
	}
	defer ctl.Close()

	mux := http.NewServeMux()
	mux.Handle(wire.AgentPath, ctl.AgentHandler())
	mux.Handle("/api/", http.StripPrefix("/api", ctl.APIHandler()))
	mux.Handle("/", web.Handler(web.Options{}))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok\n")) })

	srv := &http.Server{Addr: cfg.Listen, Handler: mux, ReadHeaderTimeout: 15 * time.Second, IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 64 << 10}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		_ = ctl.Run(ctx)
	}()
	errc := make(chan error, 1)
	go func() {
		log.Info("suri-controller listening", "addr", cfg.Listen, "version", version.Version, "host_key", ctl.HostPublicKey())
		if cfg.TLS.CertFile != "" {
			errc <- srv.ListenAndServeTLS(cfg.TLS.CertFile, cfg.TLS.KeyFile)
		} else {
			if !insecure {
				log.Warn("serving plain HTTP: put a TLS reverse proxy in front, or set insecure_cookie for HTTP-only access")
			}
			errc <- srv.ListenAndServe()
		}
	}()
	select {
	case err = <-errc:
		stop()
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	<-runDone
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	return err
}
