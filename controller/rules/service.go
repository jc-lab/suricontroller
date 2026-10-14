package rules

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jc-lab/suricontroller/controller/gitrepo"
	"github.com/jc-lab/suricontroller/controller/store"
)

// ErrUnknownProvider is returned for a provider name that does not exist.
var ErrUnknownProvider = errors.New("rules: unknown provider")

// Bot is the commit author of provider updates.
var Bot = gitrepo.Signature{Name: "suricontroller-bot", Email: "bot@suricontroller.local"}

// Config configures a Service.
type Config struct {
	Store  store.Store
	Repo   *gitrepo.Repo
	Logger *slog.Logger
	// HTTPClient for downloads (default: 5 minute timeout, proxy from env).
	HTTPClient *http.Client
	// Types overrides the provider types (default: et-open, local, url).
	Types []TypeInfo
	// OnCommit is called after a provider update was committed.
	OnCommit func(commit string)
	// DisableETOpen creates the default et-open provider disabled (for
	// air-gapped installations). It has no effect once the provider exists.
	DisableETOpen bool
}

// Service schedules provider fetches and manages provider settings.
type Service struct {
	cfg   Config
	log   *slog.Logger
	types map[string]TypeInfo
	now   func() time.Time

	syncMu sync.Mutex // one sync at a time
}

// New creates the service.
func New(cfg Config) *Service {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 5 * time.Minute, Transport: &http.Transport{Proxy: http.ProxyFromEnvironment}}
	}
	if cfg.Types == nil {
		cfg.Types = []TypeInfo{
			{Name: TypeETOpen, Fetcher: &ETOpen{Client: cfg.HTTPClient}, DefaultInterval: 24 * time.Hour,
				DefaultOptions: map[string]string{"suricata_version": DefaultSuricataVersion}},
			{Name: TypeLocal},
			{Name: TypeURL, Fetcher: &URL{Client: cfg.HTTPClient}, DefaultInterval: 24 * time.Hour},
		}
	}
	s := &Service{cfg: cfg, log: cfg.Logger.With("component", "rules"), types: map[string]TypeInfo{}, now: time.Now}
	for _, t := range cfg.Types {
		s.types[t.Name] = t
	}
	return s
}

// Init creates the default providers (et-open enabled, local) when missing.
func (s *Service) Init(ctx context.Context) error {
	defaults := []*store.Provider{
		{Name: "et-open", Type: TypeETOpen, Enabled: !s.cfg.DisableETOpen, Interval: 24 * time.Hour, Options: map[string]string{"suricata_version": DefaultSuricataVersion}},
		{Name: "local", Type: TypeLocal, Enabled: true},
	}
	for _, d := range defaults {
		if _, ok := s.types[d.Type]; !ok {
			continue
		}
		if _, err := s.cfg.Store.GetProvider(ctx, d.Name); errors.Is(err, store.ErrNotFound) {
			if err := s.cfg.Store.PutProvider(ctx, d); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
	}
	return nil
}

// Fetches reports whether providers of the given type download rules.
func (s *Service) Fetches(typ string) bool {
	return s.types[typ].Fetcher != nil
}

// List returns all providers.
func (s *Service) List(ctx context.Context) ([]*store.Provider, error) {
	return s.cfg.Store.ListProviders(ctx)
}

// Update changes provider settings. Nil arguments are left unchanged;
// options are merged (empty values delete a key).
func (s *Service) Update(ctx context.Context, name string, enabled *bool, interval *time.Duration, options map[string]string) (*store.Provider, error) {
	p, err := s.cfg.Store.GetProvider(ctx, name)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrUnknownProvider
	}
	if err != nil {
		return nil, err
	}
	if enabled != nil {
		p.Enabled = *enabled
	}
	if interval != nil {
		if *interval < 10*time.Minute {
			return nil, fmt.Errorf("interval must be at least 10 minutes")
		}
		p.Interval = *interval
	}
	for k, v := range options {
		if p.Options == nil {
			p.Options = map[string]string{}
		}
		if v == "" {
			delete(p.Options, k)
		} else {
			p.Options[k] = v
		}
	}
	// A changed source must be downloaded again.
	if len(options) > 0 {
		p.Checksum = ""
	}
	return p, s.cfg.Store.PutProvider(ctx, p)
}

// IsManagedPath reports whether a rules repository path belongs to a
// fetching provider, i.e. must not be edited by hand.
func (s *Service) IsManagedPath(ctx context.Context, p string) (bool, error) {
	providers, err := s.cfg.Store.ListProviders(ctx)
	if err != nil {
		return false, err
	}
	first, _, _ := strings.Cut(p, "/")
	for _, pr := range providers {
		if pr.Name == first && s.Fetches(pr.Type) {
			return true, nil
		}
	}
	return false, nil
}

// Sync fetches one provider now and commits changes. It returns the new
// commit, or "" when nothing changed.
func (s *Service) Sync(ctx context.Context, name string) (string, error) {
	s.syncMu.Lock()
	defer s.syncMu.Unlock()
	p, err := s.cfg.Store.GetProvider(ctx, name)
	if errors.Is(err, store.ErrNotFound) {
		return "", ErrUnknownProvider
	}
	if err != nil {
		return "", err
	}
	t, ok := s.types[p.Type]
	if !ok || t.Fetcher == nil {
		return "", fmt.Errorf("provider %q does not download rules", name)
	}
	fetchedAt := s.now()
	commit, checksum, syncErr := s.sync(ctx, p, t)
	// Reload so settings changed by an administrator during the download
	// are kept; only the fetch state is written back.
	cur, err := s.cfg.Store.GetProvider(ctx, name)
	if err != nil {
		return "", err
	}
	cur.LastFetchAt = fetchedAt
	if syncErr != nil {
		cur.LastError = syncErr.Error()
		s.log.Warn("provider sync failed", "provider", name, "err", syncErr)
	} else {
		cur.LastError = ""
		cur.LastSuccessAt = fetchedAt
		if checksum != "" {
			cur.Checksum = checksum
		}
		if commit != "" {
			cur.LastCommit = commit
		}
	}
	if err := s.cfg.Store.PutProvider(ctx, cur); err != nil {
		return "", err
	}
	if syncErr != nil {
		return "", syncErr
	}
	if commit != "" {
		s.log.Info("provider updated", "provider", name, "commit", commit)
		if s.cfg.OnCommit != nil {
			s.cfg.OnCommit(commit)
		}
	}
	return commit, nil
}

// sync fetches and commits a provider; it returns the new commit ("" if
// unchanged) and the upstream checksum.
func (s *Service) sync(ctx context.Context, p *store.Provider, t TypeInfo) (string, string, error) {
	res, err := t.Fetcher.Fetch(ctx, p)
	if errors.Is(err, ErrNotModified) {
		return "", "", nil
	}
	if err != nil {
		return "", "", err
	}
	msg := fmt.Sprintf("%s: update", p.Name)
	if res.Checksum != "" {
		msg += " (" + res.Checksum + ")"
	}
	commit, err := s.cfg.Repo.ReplaceDir(p.Name, res.Files, msg, Bot)
	if errors.Is(err, gitrepo.ErrNoChanges) {
		return "", res.Checksum, nil
	}
	if err != nil {
		return "", "", err
	}
	return commit, res.Checksum, nil
}

// Run checks every minute for enabled fetching providers whose interval
// elapsed, and syncs them. It returns when ctx is cancelled.
func (s *Service) Run(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		s.runDue(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *Service) runDue(ctx context.Context) {
	providers, err := s.cfg.Store.ListProviders(ctx)
	if err != nil {
		s.log.Error("list providers", "err", err)
		return
	}
	now := s.now()
	for _, p := range providers {
		if !p.Enabled || !s.Fetches(p.Type) {
			continue
		}
		interval := p.Interval
		if interval <= 0 {
			interval = s.types[p.Type].DefaultInterval
		}
		// Retry failures sooner, but not more often than every 15 minutes.
		if p.LastError != "" && interval > 15*time.Minute && now.Sub(p.LastFetchAt) >= 15*time.Minute {
			interval = 15 * time.Minute
		}
		if !p.LastFetchAt.IsZero() && now.Sub(p.LastFetchAt) < interval {
			continue
		}
		if _, err := s.Sync(ctx, p.Name); err != nil && ctx.Err() != nil {
			return
		}
	}
}
