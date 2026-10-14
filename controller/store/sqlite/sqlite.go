// Package sqlite implements store.Store on SQLite (pure Go, no CGO).
package sqlite

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	_ "modernc.org/sqlite"

	"github.com/jc-lab/suricontroller/controller/store"
	agentv1 "github.com/jc-lab/suricontroller/gen/suricontroller/agent/v1"
)

//go:embed schema.sql
var schema string

const schemaVersion = 1

// Store is a SQLite-backed store.Store.
type Store struct {
	db *sql.DB
}

var _ store.Store = (*Store)(nil)

// Open opens (and migrates) the database at path. Use ":memory:" for a
// throwaway database.
func Open(path string) (*Store, error) {
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "foreign_keys(1)")
	dsn := "file:" + path
	if path != ":memory:" {
		q.Add("_pragma", "journal_mode(WAL)")
		q.Add("_pragma", "synchronous(NORMAL)")
	}
	db, err := sql.Open("sqlite", dsn+"?"+q.Encode())
	if err != nil {
		return nil, err
	}
	// A single connection serializes access; the controller's write volume is
	// small and this avoids SQLITE_BUSY between connections.
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) migrate() error {
	var v int
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&v); err != nil {
		return err
	}
	if v >= schemaVersion {
		return nil
	}
	if v == 0 {
		if _, err := s.db.Exec(schema); err != nil {
			return fmt.Errorf("sqlite: create schema: %w", err)
		}
	}
	_, err := s.db.Exec(fmt.Sprintf("PRAGMA user_version = %d", schemaVersion))
	return err
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// --- helpers -----------------------------------------------------------------

func ms(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

func fromMS(v int64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.UnixMilli(v)
}

func marshalProto(m proto.Message) (sql.NullString, error) {
	if m == nil || !m.ProtoReflect().IsValid() {
		return sql.NullString{}, nil
	}
	b, err := protojson.Marshal(m)
	if err != nil {
		return sql.NullString{}, err
	}
	return sql.NullString{String: string(b), Valid: true}, nil
}

func unmarshalProto[T proto.Message](v sql.NullString, newT func() T) (T, error) {
	var zero T
	if !v.Valid || v.String == "" {
		return zero, nil
	}
	m := newT()
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal([]byte(v.String), m); err != nil {
		return zero, err
	}
	return m, nil
}

func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// --- nodes -------------------------------------------------------------------

const nodeColumns = `id, public_key, fingerprint, enabled, description, created_at, updated_at, last_seen_at,
	hello, interface_modes, log_policy, desired, desired_error, applied, last_report, last_report_at`

type rowScanner interface{ Scan(dest ...any) error }

func scanNode(r rowScanner) (*store.Node, error) {
	var (
		n                                    store.Node
		enabled                              int
		created, updated, lastSeen, reportAt int64
		hello, modes, logPolicy              sql.NullString
		desired, applied, report             sql.NullString
	)
	if err := r.Scan(&n.ID, &n.PublicKey, &n.Fingerprint, &enabled, &n.Description, &created, &updated, &lastSeen,
		&hello, &modes, &logPolicy, &desired, &n.DesiredError, &applied, &report, &reportAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	n.Enabled = enabled != 0
	n.CreatedAt, n.UpdatedAt, n.LastSeenAt, n.LastReportAt = fromMS(created), fromMS(updated), fromMS(lastSeen), fromMS(reportAt)
	var err error
	if n.Hello, err = unmarshalProto(hello, func() *agentv1.Hello { return &agentv1.Hello{} }); err != nil {
		return nil, err
	}
	if n.LogPolicy, err = unmarshalProto(logPolicy, func() *agentv1.LogCollectionPolicy { return &agentv1.LogCollectionPolicy{} }); err != nil {
		return nil, err
	}
	if n.Desired, err = unmarshalProto(desired, func() *agentv1.DesiredState { return &agentv1.DesiredState{} }); err != nil {
		return nil, err
	}
	if n.Applied, err = unmarshalProto(applied, func() *agentv1.AppliedState { return &agentv1.AppliedState{} }); err != nil {
		return nil, err
	}
	if n.LastReport, err = unmarshalProto(report, func() *agentv1.ApplyReport { return &agentv1.ApplyReport{} }); err != nil {
		return nil, err
	}
	if modes.Valid && modes.String != "" {
		var m map[string]string
		if err := json.Unmarshal([]byte(modes.String), &m); err != nil {
			return nil, err
		}
		n.InterfaceModes = make(map[string]agentv1.InterfaceMode, len(m))
		for k, v := range m {
			n.InterfaceModes[k] = agentv1.InterfaceMode(agentv1.InterfaceMode_value[v])
		}
	}
	return &n, nil
}

func nodeArgs(n *store.Node) ([]any, error) {
	hello, err := marshalProto(n.Hello)
	if err != nil {
		return nil, err
	}
	logPolicy, err := marshalProto(n.LogPolicy)
	if err != nil {
		return nil, err
	}
	desired, err := marshalProto(n.Desired)
	if err != nil {
		return nil, err
	}
	applied, err := marshalProto(n.Applied)
	if err != nil {
		return nil, err
	}
	report, err := marshalProto(n.LastReport)
	if err != nil {
		return nil, err
	}
	var modes sql.NullString
	if len(n.InterfaceModes) > 0 {
		m := make(map[string]string, len(n.InterfaceModes))
		for k, v := range n.InterfaceModes {
			m[k] = v.String()
		}
		b, _ := json.Marshal(m)
		modes = sql.NullString{String: string(b), Valid: true}
	}
	enabled := 0
	if n.Enabled {
		enabled = 1
	}
	return []any{n.ID, n.PublicKey, n.Fingerprint, enabled, n.Description, ms(n.CreatedAt), ms(n.UpdatedAt), ms(n.LastSeenAt),
		hello, modes, logPolicy, desired, n.DesiredError, applied, report, ms(n.LastReportAt)}, nil
}

// CreateNode implements store.Store.
func (s *Store) CreateNode(ctx context.Context, n *store.Node) error {
	args, err := nodeArgs(n)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO nodes (`+nodeColumns+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, args...)
	if isUniqueViolation(err) {
		return store.ErrAlreadyExists
	}
	return err
}

// GetNode implements store.Store.
func (s *Store) GetNode(ctx context.Context, id string) (*store.Node, error) {
	return scanNode(s.db.QueryRowContext(ctx, `SELECT `+nodeColumns+` FROM nodes WHERE id = ?`, id))
}

// ListNodes implements store.Store.
func (s *Store) ListNodes(ctx context.Context) ([]*store.Node, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+nodeColumns+` FROM nodes ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*store.Node
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// UpdateNode implements store.Store.
func (s *Store) UpdateNode(ctx context.Context, id string, fn func(n *store.Node) error) (*store.Node, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	n, err := scanNode(tx.QueryRowContext(ctx, `SELECT `+nodeColumns+` FROM nodes WHERE id = ?`, id))
	if err != nil {
		return nil, err
	}
	if err := fn(n); err != nil {
		return nil, err
	}
	n.ID = id
	args, err := nodeArgs(n)
	if err != nil {
		return nil, err
	}
	_, err = tx.ExecContext(ctx, `UPDATE nodes SET public_key=?, fingerprint=?, enabled=?, description=?, created_at=?, updated_at=?, last_seen_at=?,
		hello=?, interface_modes=?, log_policy=?, desired=?, desired_error=?, applied=?, last_report=?, last_report_at=? WHERE id=?`,
		append(args[1:], id)...)
	if err != nil {
		return nil, err
	}
	return n, tx.Commit()
}

// DeleteNode implements store.Store.
func (s *Store) DeleteNode(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM nodes WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	return nil
}

// --- apply history -----------------------------------------------------------

// AppendApplyHistory implements store.Store.
func (s *Store) AppendApplyHistory(ctx context.Context, e *store.ApplyHistoryEntry) error {
	rep, err := marshalProto(e.Report)
	if err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO apply_history (node_id, report, created_at) VALUES (?,?,?)`, e.NodeID, rep, ms(e.CreatedAt))
	if err != nil {
		return err
	}
	e.ID, _ = res.LastInsertId()
	return nil
}

// ListApplyHistory implements store.Store.
func (s *Store) ListApplyHistory(ctx context.Context, nodeID string, limit int) ([]*store.ApplyHistoryEntry, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, node_id, report, created_at FROM apply_history WHERE node_id = ? ORDER BY id DESC LIMIT ?`, nodeID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*store.ApplyHistoryEntry
	for rows.Next() {
		var (
			e       store.ApplyHistoryEntry
			rep     sql.NullString
			created int64
		)
		if err := rows.Scan(&e.ID, &e.NodeID, &rep, &created); err != nil {
			return nil, err
		}
		e.CreatedAt = fromMS(created)
		if e.Report, err = unmarshalProto(rep, func() *agentv1.ApplyReport { return &agentv1.ApplyReport{} }); err != nil {
			return nil, err
		}
		out = append(out, &e)
	}
	return out, rows.Err()
}

// PruneApplyHistory implements store.Store.
func (s *Store) PruneApplyHistory(ctx context.Context, keep int) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM apply_history WHERE id IN (
		SELECT id FROM (
			SELECT id, ROW_NUMBER() OVER (PARTITION BY node_id ORDER BY id DESC) AS rn FROM apply_history
		) WHERE rn > ?)`, keep)
	return err
}

// --- deploy policies ---------------------------------------------------------

// GetDeployPolicy implements store.Store.
func (s *Store) GetDeployPolicy(ctx context.Context, kind string) (*store.DeployPolicy, error) {
	var (
		p       store.DeployPolicy
		updated int64
	)
	err := s.db.QueryRowContext(ctx, `SELECT kind, mode, pinned_commit, effective_commit, updated_at, updated_by FROM deploy_policies WHERE kind = ?`, kind).
		Scan(&p.Kind, &p.Mode, &p.PinnedCommit, &p.EffectiveCommit, &updated, &p.UpdatedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	p.UpdatedAt = fromMS(updated)
	return &p, nil
}

// PutDeployPolicy implements store.Store.
func (s *Store) PutDeployPolicy(ctx context.Context, p *store.DeployPolicy) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO deploy_policies (kind, mode, pinned_commit, effective_commit, updated_at, updated_by) VALUES (?,?,?,?,?,?)
		ON CONFLICT(kind) DO UPDATE SET mode=excluded.mode, pinned_commit=excluded.pinned_commit, effective_commit=excluded.effective_commit,
		updated_at=excluded.updated_at, updated_by=excluded.updated_by`,
		p.Kind, p.Mode, p.PinnedCommit, p.EffectiveCommit, ms(p.UpdatedAt), p.UpdatedBy)
	return err
}

// --- providers ---------------------------------------------------------------

const providerColumns = `name, type, enabled, interval_seconds, options, last_fetch_at, last_success_at, last_error, last_commit, checksum`

func scanProvider(r rowScanner) (*store.Provider, error) {
	var (
		p                   store.Provider
		enabled             int
		interval            int64
		options             string
		lastFetch, lastSucc int64
	)
	if err := r.Scan(&p.Name, &p.Type, &enabled, &interval, &options, &lastFetch, &lastSucc, &p.LastError, &p.LastCommit, &p.Checksum); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	p.Enabled = enabled != 0
	p.Interval = time.Duration(interval) * time.Second
	p.LastFetchAt, p.LastSuccessAt = fromMS(lastFetch), fromMS(lastSucc)
	if options != "" {
		if err := json.Unmarshal([]byte(options), &p.Options); err != nil {
			return nil, err
		}
	}
	return &p, nil
}

// ListProviders implements store.Store.
func (s *Store) ListProviders(ctx context.Context) ([]*store.Provider, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+providerColumns+` FROM providers ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*store.Provider
	for rows.Next() {
		p, err := scanProvider(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// GetProvider implements store.Store.
func (s *Store) GetProvider(ctx context.Context, name string) (*store.Provider, error) {
	return scanProvider(s.db.QueryRowContext(ctx, `SELECT `+providerColumns+` FROM providers WHERE name = ?`, name))
}

// PutProvider implements store.Store.
func (s *Store) PutProvider(ctx context.Context, p *store.Provider) error {
	opts := "{}"
	if len(p.Options) > 0 {
		b, err := json.Marshal(p.Options)
		if err != nil {
			return err
		}
		opts = string(b)
	}
	enabled := 0
	if p.Enabled {
		enabled = 1
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO providers (`+providerColumns+`) VALUES (?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(name) DO UPDATE SET type=excluded.type, enabled=excluded.enabled, interval_seconds=excluded.interval_seconds,
		options=excluded.options, last_fetch_at=excluded.last_fetch_at, last_success_at=excluded.last_success_at,
		last_error=excluded.last_error, last_commit=excluded.last_commit, checksum=excluded.checksum`,
		p.Name, p.Type, enabled, int64(p.Interval/time.Second), opts, ms(p.LastFetchAt), ms(p.LastSuccessAt), p.LastError, p.LastCommit, p.Checksum)
	return err
}

// DeleteProvider implements store.Store.
func (s *Store) DeleteProvider(ctx context.Context, name string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM providers WHERE name = ?`, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	return nil
}

// --- settings ----------------------------------------------------------------

// GetSetting implements store.Store.
func (s *Store) GetSetting(ctx context.Context, key string, v any) (bool, error) {
	var raw string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if m, ok := v.(proto.Message); ok {
		return true, (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal([]byte(raw), m)
	}
	return true, json.Unmarshal([]byte(raw), v)
}

// PutSetting implements store.Store.
func (s *Store) PutSetting(ctx context.Context, key string, v any) error {
	var (
		b   []byte
		err error
	)
	if m, ok := v.(proto.Message); ok {
		b, err = protojson.Marshal(m)
	} else {
		b, err = json.Marshal(v)
	}
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, string(b))
	return err
}

// --- audit -------------------------------------------------------------------

// AppendAudit implements store.Store.
func (s *Store) AppendAudit(ctx context.Context, e *store.AuditEntry) error {
	res, err := s.db.ExecContext(ctx, `INSERT INTO audit_log (time, principal, action, target, detail) VALUES (?,?,?,?,?)`,
		ms(e.Time), e.Principal, e.Action, e.Target, e.Detail)
	if err != nil {
		return err
	}
	e.ID, _ = res.LastInsertId()
	return nil
}

// ListAudit implements store.Store.
func (s *Store) ListAudit(ctx context.Context, limit int) ([]*store.AuditEntry, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, time, principal, action, target, detail FROM audit_log ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*store.AuditEntry
	for rows.Next() {
		var (
			e  store.AuditEntry
			ts int64
		)
		if err := rows.Scan(&e.ID, &ts, &e.Principal, &e.Action, &e.Target, &e.Detail); err != nil {
			return nil, err
		}
		e.Time = fromMS(ts)
		out = append(out, &e)
	}
	return out, rows.Err()
}
