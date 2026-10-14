CREATE TABLE nodes (
    id              TEXT PRIMARY KEY,
    public_key      TEXT NOT NULL,
    fingerprint     TEXT NOT NULL UNIQUE,
    enabled         INTEGER NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL,
    last_seen_at    INTEGER NOT NULL DEFAULT 0,
    hello           TEXT,
    interface_modes TEXT,
    log_policy      TEXT,
    desired         TEXT,
    desired_error   TEXT NOT NULL DEFAULT '',
    applied         TEXT,
    last_report     TEXT,
    last_report_at  INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE apply_history (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id    TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    report     TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX apply_history_node ON apply_history(node_id, id);

CREATE TABLE deploy_policies (
    kind             TEXT PRIMARY KEY,
    mode             TEXT NOT NULL,
    pinned_commit    TEXT NOT NULL,
    effective_commit TEXT NOT NULL,
    updated_at       INTEGER NOT NULL,
    updated_by       TEXT NOT NULL
);

CREATE TABLE providers (
    name             TEXT PRIMARY KEY,
    type             TEXT NOT NULL,
    enabled          INTEGER NOT NULL,
    interval_seconds INTEGER NOT NULL,
    options          TEXT NOT NULL,
    last_fetch_at    INTEGER NOT NULL DEFAULT 0,
    last_success_at  INTEGER NOT NULL DEFAULT 0,
    last_error       TEXT NOT NULL DEFAULT '',
    last_commit      TEXT NOT NULL DEFAULT '',
    checksum         TEXT NOT NULL DEFAULT ''
);

CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE audit_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    time      INTEGER NOT NULL,
    principal TEXT NOT NULL,
    action    TEXT NOT NULL,
    target    TEXT NOT NULL,
    detail    TEXT NOT NULL
);
