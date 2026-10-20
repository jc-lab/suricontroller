// Package nodes manages registered nodes: their keys, facts reported by the
// agent, live status and the interface modes requested by administrators.
package nodes

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jc-lab/suricontroller/controller/store"
	agentv1 "github.com/jc-lab/suricontroller/gen/suricontroller/agent/v1"
	"github.com/jc-lab/suricontroller/pkg/nodeid"
	"github.com/jc-lab/suricontroller/pkg/sshkey"
)

// ErrInvalidArgument wraps validation errors.
var ErrInvalidArgument = errors.New("invalid argument")

// Service manages nodes. It implements agentgw.NodeLookup.
//
// Key lookups go to the store when it implements LookupNodeByX25519
// (delegated mode), so that a store shared with another program sees nodes
// added or disabled there. Otherwise the service keeps an in-memory key
// index loaded at startup.
type Service struct {
	store store.Store
	now   func() time.Time
	// delegated is set when the store answers key lookups itself.
	delegated bool

	// OnChange is called after a change that affects a node's desired state
	// (interface modes, enable/disable, log policy, new facts).
	OnChange func(nodeID string)

	mu     sync.RWMutex
	byKey  map[string]keyEntry // hex x25519 -> node; unused when delegated
	status map[string]*agentv1.StatusReport
}

type keyEntry struct {
	id      string
	enabled bool
}

// New creates the service. Unless the store answers key lookups itself, it
// loads the key index.
func New(ctx context.Context, st store.Store) (*Service, error) {
	s := &Service{store: st, now: time.Now, byKey: map[string]keyEntry{}, status: map[string]*agentv1.StatusReport{}}
	// Probe with a key no node has. Any answer other than ErrNotImplemented
	// (including a transient error) means the store implements lookups.
	if _, _, err := st.LookupNodeByX25519(ctx, make([]byte, 32)); !errors.Is(err, store.ErrNotImplemented) {
		s.delegated = true
		return s, nil
	}
	nodes, err := st.ListNodes(ctx)
	if err != nil {
		return nil, err
	}
	for _, n := range nodes {
		if err := s.index(n); err != nil {
			return nil, fmt.Errorf("node %s: %w", n.ID, err)
		}
	}
	return s, nil
}

func (s *Service) index(n *store.Node) error {
	if s.delegated {
		return nil
	}
	pk, err := sshkey.ParsePublicKey(n.PublicKey)
	if err != nil {
		return err
	}
	x, err := pk.X25519()
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.byKey[hex.EncodeToString(x)] = keyEntry{id: n.ID, enabled: n.Enabled}
	s.mu.Unlock()
	return nil
}

func (s *Service) unindex(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, e := range s.byKey {
		if e.id == id {
			delete(s.byKey, k)
		}
	}
	delete(s.status, id)
}

func (s *Service) changed(id string) {
	if s.OnChange != nil {
		s.OnChange(id)
	}
}

// Delegated reports whether key lookups go to the store.
func (s *Service) Delegated() bool { return s.delegated }

// LookupNodeByX25519 implements agentgw.NodeLookup. It returns
// store.ErrNotFound for an unknown key.
func (s *Service) LookupNodeByX25519(ctx context.Context, key []byte) (string, bool, error) {
	if s.delegated {
		return s.store.LookupNodeByX25519(ctx, key)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.byKey[hex.EncodeToString(key)]
	if !ok {
		return "", false, store.ErrNotFound
	}
	return e.id, e.enabled, nil
}

// Add registers a node from its public key line; the node id is the key
// comment.
func (s *Service) Add(ctx context.Context, publicKey, description string) (*store.Node, error) {
	pk, err := sshkey.ParsePublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	if pk.Comment == "" {
		return nil, fmt.Errorf("%w: the public key must end with the node id as comment", ErrInvalidArgument)
	}
	if err := nodeid.Validate(pk.Comment); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	x, err := pk.X25519()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	// Different ed25519 keys can map to the same X25519 key; the agent is
	// identified by the latter. In delegated mode the store's unique
	// constraint is the final guard against a concurrent insert.
	switch _, _, err := s.LookupNodeByX25519(ctx, x); {
	case err == nil:
		return nil, fmt.Errorf("%w: a node with this key already exists", store.ErrAlreadyExists)
	case !errors.Is(err, store.ErrNotFound):
		return nil, err
	}
	now := s.now()
	n := &store.Node{
		ID:          pk.Comment,
		PublicKey:   pk.String(),
		Fingerprint: pk.Fingerprint(),
		Enabled:     true,
		Description: description,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := s.store.CreateNode(ctx, n); err != nil {
		if errors.Is(err, store.ErrAlreadyExists) {
			return nil, fmt.Errorf("%w: a node with this id or key already exists", store.ErrAlreadyExists)
		}
		return nil, err
	}
	if err := s.index(n); err != nil {
		return nil, err
	}
	s.changed(n.ID)
	return n, nil
}

// Update changes the enabled flag and/or description.
func (s *Service) Update(ctx context.Context, id string, enabled *bool, description *string) (*store.Node, error) {
	n, err := s.store.UpdateNode(ctx, id, func(n *store.Node) error {
		if enabled != nil {
			n.Enabled = *enabled
		}
		if description != nil {
			n.Description = *description
		}
		n.UpdatedAt = s.now()
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err := s.index(n); err != nil {
		return nil, err
	}
	if enabled != nil {
		s.changed(id)
	}
	return n, nil
}

// Delete removes a node.
func (s *Service) Delete(ctx context.Context, id string) error {
	if err := s.store.DeleteNode(ctx, id); err != nil {
		return err
	}
	s.unindex(id)
	return nil
}

// Get returns a node.
func (s *Service) Get(ctx context.Context, id string) (*store.Node, error) {
	return s.store.GetNode(ctx, id)
}

// List returns all nodes.
func (s *Service) List(ctx context.Context) ([]*store.Node, error) {
	return s.store.ListNodes(ctx)
}

// SetInterfaceModes replaces the requested interface modes. Interfaces must
// be among those the agent reported, and IPS requires the agent to allow it.
func (s *Service) SetInterfaceModes(ctx context.Context, id string, modes map[string]agentv1.InterfaceMode) (*store.Node, error) {
	n, err := s.store.UpdateNode(ctx, id, func(n *store.Node) error {
		allowed := map[string]*agentv1.InterfaceInfo{}
		for _, ifc := range n.Hello.GetInterfaces() {
			allowed[ifc.Name] = ifc
		}
		out := map[string]agentv1.InterfaceMode{}
		for name, mode := range modes {
			ifc, ok := allowed[name]
			if !ok {
				return fmt.Errorf("%w: interface %q is not managed by the agent", ErrInvalidArgument, name)
			}
			switch mode {
			case agentv1.InterfaceMode_INTERFACE_MODE_OFF, agentv1.InterfaceMode_INTERFACE_MODE_IDS:
			case agentv1.InterfaceMode_INTERFACE_MODE_IPS:
				if !ifc.IpsAllowed {
					return fmt.Errorf("%w: the agent does not allow IPS mode on %q", ErrInvalidArgument, name)
				}
			default:
				return fmt.Errorf("%w: invalid mode for %q", ErrInvalidArgument, name)
			}
			out[name] = mode
		}
		n.InterfaceModes = out
		n.UpdatedAt = s.now()
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.changed(id)
	return n, nil
}

// SetLogPolicy sets (or with nil, clears) the node's log collection override.
func (s *Service) SetLogPolicy(ctx context.Context, id string, p *agentv1.LogCollectionPolicy) error {
	_, err := s.store.UpdateNode(ctx, id, func(n *store.Node) error {
		n.LogPolicy = p
		n.UpdatedAt = s.now()
		return nil
	})
	if err == nil {
		s.changed(id)
	}
	return err
}

// RecordHello persists the facts from an agent Hello.
func (s *Service) RecordHello(ctx context.Context, id string, hello *agentv1.Hello) error {
	_, err := s.store.UpdateNode(ctx, id, func(n *store.Node) error {
		n.Hello = hello
		n.LastSeenAt = s.now()
		if hello.Applied != nil {
			n.Applied = hello.Applied
		}
		return nil
	})
	return err
}

// RecordStatus keeps the latest status report in memory and refreshes the
// interfaces and log sources reported by the agent.
func (s *Service) RecordStatus(id string, st *agentv1.StatusReport) {
	s.mu.Lock()
	s.status[id] = st
	s.mu.Unlock()
}

// RecordDisconnect updates the last-seen time.
func (s *Service) RecordDisconnect(ctx context.Context, id string) {
	_, _ = s.store.UpdateNode(ctx, id, func(n *store.Node) error {
		n.LastSeenAt = s.now()
		return nil
	})
	s.mu.Lock()
	delete(s.status, id)
	s.mu.Unlock()
}

// Status returns the latest status report of an online node, or nil.
func (s *Service) Status(id string) *agentv1.StatusReport {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.status[id]
}
