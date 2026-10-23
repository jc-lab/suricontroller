package agent

import (
	"context"
	"crypto/ed25519"
	"time"

	"github.com/jc-lab/suricontroller/pkg/sshkey"
)

// Endpoint is a controller address and the host key the agent pins.
type Endpoint struct {
	URL     string
	HostKey *sshkey.PublicKey
}

// EndpointSource supplies the controller endpoint at run time, e.g. learned
// from another authenticated channel, in place of the controller section.
type EndpointSource interface {
	// Endpoint returns the current endpoint, waiting until one is known or
	// ctx ends, and a channel that is closed when it changes.
	Endpoint(ctx context.Context) (Endpoint, <-chan struct{}, error)
}

// endpoint returns where to connect next.
func (a *Agent) endpoint(ctx context.Context) (Endpoint, <-chan struct{}, error) {
	if a.src == nil {
		return Endpoint{URL: a.cfg.Controller.URL, HostKey: a.staticKey}, nil, nil
	}
	return a.src.Endpoint(ctx)
}

// bundleKey returns the host key of the controller of the current (or
// last) session: bundles come from it.
func (a *Agent) bundleKey() ed25519.PublicKey {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.hostKey == nil {
		return nil
	}
	return a.hostKey.Key
}

func (a *Agent) setHostKey(k *sshkey.PublicKey) {
	a.mu.Lock()
	a.hostKey = k
	a.mu.Unlock()
}

// sleepOrChange waits d, or less when ctx ends or changed is closed; it
// reports a change.
func sleepOrChange(ctx context.Context, d time.Duration, changed <-chan struct{}) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	case <-changed:
		return true
	}
	return false
}
