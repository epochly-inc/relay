-- W2.3 sidecar SQLite migration 0001: event_log_entries
--
-- Mirrors the W1 EventLogEntry canonical envelope (spec A.11 / VAL-W1-015..017)
-- and adds the W2.3-specific observability columns required by VAL-W2-019:
--
--   event_kind            -- discriminator. Canonical envelope event_type
--                            carries the high-level kind (e.g. sidecar.spawned);
--                            event_kind is a W2.3 sidecar-local refinement used
--                            to tag internal-only retry rows. Default empty
--                            string for canonical envelope rows.
--   attempt_number        -- 1-indexed retry counter on sqlite_busy_retry rows.
--                            NULL on non-retry rows.
--   backoff_ms            -- milliseconds the writer slept before this retry.
--                            NULL on non-retry rows.
--   sql_statement_digest  -- sha256 digest of the SQL statement that hit BUSY.
--                            NULL on non-retry rows.
--
-- Idempotency: a unique index on (scope_id, idempotency_key) gives every
-- transactional_db_write a deterministic dedupe surface. NULL idempotency_key
-- (the common case) is permitted multiple times per scope by SQLite (NULL
-- != NULL in unique index semantics).
--
-- NOTE: this is the LOCAL OSS sidecar schema only. The W2 SQL grants
-- (control-plane-writes-the-result enforcement on Postgres) are NOT in scope
-- here; local SQLite is open-access. Role enforcement lands when the hosted
-- control plane is built in later milestones.

CREATE TABLE IF NOT EXISTS event_log_entries (
    -- W1 canonical fields (relay.event_log_entry.v1)
    event_id              TEXT    PRIMARY KEY NOT NULL,
    schema_version        TEXT    NOT NULL DEFAULT 'relay.event_log_entry.v1',
    project_id            TEXT    NOT NULL,
    scope_type            TEXT    NOT NULL,
    scope_id              TEXT    NOT NULL,
    event_type            TEXT    NOT NULL,
    actor_kind            TEXT    NOT NULL,
    actor_id              TEXT,
    manifest_commit_hash  TEXT,
    payload               TEXT    NOT NULL DEFAULT '{}',
    occurred_at           TEXT    NOT NULL,
    ingest_sequence       INTEGER NOT NULL,
    -- W2.3 observability fields
    event_kind            TEXT    NOT NULL DEFAULT '',
    attempt_number        INTEGER,
    backoff_ms            INTEGER,
    sql_statement_digest  TEXT,
    -- W2.3 idempotency surface (caller-supplied; NULL when caller does not
    -- request idempotency).
    idempotency_key       TEXT
);

-- Unique index on (scope_id, idempotency_key) for the idempotency contract.
-- SQLite treats NULL != NULL in unique constraints so NULL idempotency_key
-- rows are unbounded; only non-NULL keys dedupe per scope.
CREATE UNIQUE INDEX IF NOT EXISTS uq_event_log_entries_idempotency
    ON event_log_entries(scope_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

-- Index on ingest_sequence for monotonic-order queries (VAL-W2-019).
CREATE INDEX IF NOT EXISTS ix_event_log_entries_ingest_sequence
    ON event_log_entries(ingest_sequence);

-- Index on event_kind for retry-row queries (VAL-W2-019 forced-contention
-- evidence: SELECT count() WHERE event_kind = 'sqlite_busy_retry').
CREATE INDEX IF NOT EXISTS ix_event_log_entries_event_kind
    ON event_log_entries(event_kind);
