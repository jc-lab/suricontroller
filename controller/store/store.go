// Package store defines the controller's persistence interface. The default
// implementation is store/sqlite; programs embedding the controller can
// provide their own.
package store

import (
	"context"
	"errors"
	"time"

	agentv1 "github.com/jc-lab/suricontroller/gen/suricontroller/agent/v1"
)

var (
	// ErrNotFound is returned when a record does not exist.
	ErrNotFound = errors.New("store: not found")
	// ErrAlreadyExists is returned when creating a duplicate record.
	ErrAlreadyExists = errors.New("store: already exists")
)

// Node is a registered agent and its persisted state.
type Node struct {
	ID string
	// PublicKey is the authorized key line ("ssh-ed25519 AAAA... node-id").
	PublicKey   string
	Fingerprint string
	Enabled     bool
	Description string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	LastSeenAt  time.Time

	// Hello is the latest Hello received from the agent.
	Hello *agentv1.Hello
	// InterfaceModes are the modes requested by the administrator.
	InterfaceModes map[string]agentv1.InterfaceMode
	// LogPolicy overrides the global log collection policy; nil inherits.
	LogPolicy *agentv1.LogCollectionPolicy

	Desired *agentv1.DesiredState
	// DesiredError is set when the desired state could not be computed.
	DesiredError string
	Applied      *agentv1.AppliedState
	LastReport   *agentv1.ApplyReport
	LastReportAt time.Time
}

// ApplyHistoryEntry is a finished apply attempt reported by a node.
type ApplyHistoryEntry struct {
	ID        int64
	NodeID    string
	Report    *agentv1.ApplyReport
	CreatedAt time.Time
}

// DeployPolicy controls which commit of a repository nodes run.
type DeployPolicy struct {
	// Kind is "rules" or "config".
	Kind string
	// Mode is "auto", "pinned" or "paused".
	Mode            string
	PinnedCommit    string
	EffectiveCommit string
	UpdatedAt       time.Time
	UpdatedBy       string
}

// Provider is a rule provider configuration and its fetch state.
type Provider struct {
	Name     string
	Type     string
	Enabled  bool
	Interval time.Duration
	Options  map[string]string

	LastFetchAt   time.Time
	LastSuccessAt time.Time
	LastError     string
	LastCommit    string
	// Checksum of the last fetched upstream archive (e.g. ET Open md5).
	Checksum string
}

// AuditEntry records an administrative action.
type AuditEntry struct {
	ID        int64
	Time      time.Time
	Principal string
	Action    string
	Target    string
	Detail    string
}

// Store persists controller state. Implementations must be safe for
// concurrent use.
type Store interface {
	CreateNode(ctx context.Context, n *Node) error
	GetNode(ctx context.Context, id string) (*Node, error)
	ListNodes(ctx context.Context) ([]*Node, error)
	// UpdateNode atomically loads a node, applies fn and saves the result.
	// If fn returns an error the node is left unchanged.
	UpdateNode(ctx context.Context, id string, fn func(n *Node) error) (*Node, error)
	DeleteNode(ctx context.Context, id string) error

	AppendApplyHistory(ctx context.Context, e *ApplyHistoryEntry) error
	ListApplyHistory(ctx context.Context, nodeID string, limit int) ([]*ApplyHistoryEntry, error)
	// PruneApplyHistory keeps the newest keep entries per node.
	PruneApplyHistory(ctx context.Context, keep int) error

	// GetDeployPolicy returns ErrNotFound if the policy was never saved.
	GetDeployPolicy(ctx context.Context, kind string) (*DeployPolicy, error)
	PutDeployPolicy(ctx context.Context, p *DeployPolicy) error

	ListProviders(ctx context.Context) ([]*Provider, error)
	GetProvider(ctx context.Context, name string) (*Provider, error)
	PutProvider(ctx context.Context, p *Provider) error
	DeleteProvider(ctx context.Context, name string) error

	// GetSetting decodes the JSON value of key into v. It returns false if
	// the key is not set.
	GetSetting(ctx context.Context, key string, v any) (bool, error)
	PutSetting(ctx context.Context, key string, v any) error

	AppendAudit(ctx context.Context, e *AuditEntry) error
	ListAudit(ctx context.Context, limit int) ([]*AuditEntry, error)

	Close() error
}
