-- 0002_control_plane.sql
--
-- W1.2 scope: control-plane envelope tables.
--
--   manifest_versions   (spec A.9)
--   scope_state         (spec W; per-scope-kind state sets spec C.1)
--   idempotency_records (spec A.12; ULID-keyed dedupe)
--   event_log_entries   (spec A.11; append-only audit trail)
--
-- This migration is hand-authored to match the canonical YAML at
-- packages/schemas/raw/envelopes.yaml. The W1.5 codegen pipeline will
-- replace the hand-authoring with generator output; the W1.5 drift check
-- (VAL-W1-035) will enforce sync.
--
-- The role-based grants that enforce CLAUDE.md keystone invariant #1
-- (the control plane writes the result) for run_results / gate_decisions
-- land in W2 (m02-w2-sidecar-core). This file delivers the DDL shape
-- only; role grants are W2's responsibility.
--
-- Per CLAUDE.md keystone invariant #10, every canonical envelope row
-- carries schema_version pinned via a SQL CHECK constraint. Per VAL-W1-049
-- through VAL-W1-051, those pins are enforced at the SQL layer in addition
-- to the wire-format layer.
--
-- ASCII-only per CLAUDE.md "ASCII-Safe Source".

-- -----------------------------------------------------------------------------
-- manifest_versions (spec A.9; VAL-W1-009, VAL-W1-010)
-- -----------------------------------------------------------------------------

CREATE TABLE manifest_versions (
    manifest_version_id uuid PRIMARY KEY,
    manifest_id uuid NOT NULL,
    commit_hash text NOT NULL
        CHECK (commit_hash ~ '^sha256-[0-9a-f]{64}$'),
    schema_version text NOT NULL DEFAULT 'relay.manifest.v1'
        CHECK (schema_version = 'relay.manifest.v1'),
    body jsonb NOT NULL,
    signed_by text NULL,
    signature text NULL,
    signature_key_id text NULL,
    effective_at timestamptz NOT NULL DEFAULT now(),
    effective_until timestamptz NULL,
    UNIQUE (manifest_id, commit_hash)
);

CREATE INDEX manifest_versions_manifest_effective
    ON manifest_versions(manifest_id, effective_at DESC);

-- -----------------------------------------------------------------------------
-- scope_state (spec W; VAL-W1-011, VAL-W1-012, VAL-W1-049)
-- -----------------------------------------------------------------------------
--
-- scope_kind is a closed enum. The state column is constrained per-kind via
-- the cross-column CHECK constraint scope_state_state_per_kind, mirroring
-- the discriminated-union enforcement on the wire-format layer.
--
-- epoch is the optimistic-concurrency aggregate version (spec C.4). bigint,
-- non-negative, incremented exactly once per successful compare_and_set_state
-- transition (spec C.4 lines 3679-3722).

CREATE TABLE scope_state (
    scope_kind text NOT NULL
        CHECK (scope_kind IN (
            'run', 'replay_case', 'gate_round', 'evidence_bundle'
        )),
    scope_id uuid NOT NULL,
    project_id uuid NOT NULL,
    state text NOT NULL,
    epoch bigint NOT NULL DEFAULT 0
        CHECK (epoch >= 0),
    schema_version text NOT NULL DEFAULT 'relay.scope_state.v1'
        CHECK (schema_version = 'relay.scope_state.v1'),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (scope_kind, scope_id),

    -- VAL-W1-011: state must belong to the scope_kind's declared set
    -- (spec C.1 lines 3632-3636). A cross-tag combination such as
    -- (scope_kind='run', state='building') fails this constraint.
    CONSTRAINT scope_state_state_per_kind CHECK (
        (scope_kind = 'run' AND state IN (
            'pending', 'captured', 'validating', 'gated',
            'result_written', 'terminal'
        ))
        OR (scope_kind = 'replay_case' AND state IN (
            'proposed', 'fixtures_ready', 'executing', 'analyzed',
            'terminal'
        ))
        OR (scope_kind = 'gate_round' AND state IN (
            'open', 'draft_received', 'evaluating', 'decision_written',
            'restarted', 'terminal'
        ))
        OR (scope_kind = 'evidence_bundle' AND state IN (
            'building', 'signed', 'published', 'superseded', 'revoked'
        ))
    )
);

CREATE INDEX scope_state_project_kind_state
    ON scope_state(project_id, scope_kind, state);

-- -----------------------------------------------------------------------------
-- idempotency_records (spec A.12; VAL-W1-013, VAL-W1-014, VAL-W1-050)
-- -----------------------------------------------------------------------------

CREATE TABLE idempotency_records (
    idempotency_key text PRIMARY KEY
        CHECK (idempotency_key ~ '^[0-9A-HJKMNP-TV-Z]{26}$'),
    schema_version text NOT NULL DEFAULT 'relay.idempotency_record.v1'
        CHECK (schema_version = 'relay.idempotency_record.v1'),
    project_id uuid NOT NULL,
    request_digest text NOT NULL
        CHECK (request_digest ~ '^sha256-[0-9a-f]{64}$'),
    response_status int NOT NULL
        CHECK (response_status >= 0),
    response_ref text NULL,
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL DEFAULT (now() + interval '24 hours')
);

CREATE INDEX idempotency_records_expiry
    ON idempotency_records(expires_at);

CREATE INDEX idempotency_records_project_first_seen
    ON idempotency_records(project_id, first_seen_at DESC);

-- -----------------------------------------------------------------------------
-- event_log_entries (spec A.11; VAL-W1-015, VAL-W1-016, VAL-W1-017, VAL-W1-051)
-- -----------------------------------------------------------------------------
--
-- The event log is the append-only audit trail. Every state transition
-- (spec C.4) emits exactly one row here. Per spec A.11, the table is
-- partitioned monthly in production; this DDL ships the unpartitioned
-- shape suitable for local dev / SQLite-style sidecar work. W2 will lift
-- this to partitioned shape when the hosted control plane lands.

CREATE TABLE event_log_entries (
    event_id uuid PRIMARY KEY,
    schema_version text NOT NULL DEFAULT 'relay.event_log_entry.v1'
        CHECK (schema_version = 'relay.event_log_entry.v1'),
    project_id uuid NOT NULL,
    scope_type text NOT NULL
        CHECK (scope_type IN (
            'run', 'replay', 'gate', 'eval_run', 'release',
            'manifest', 'key', 'other'
        )),
    scope_id uuid NOT NULL,
    event_type text NOT NULL,
    actor_kind text NOT NULL
        CHECK (actor_kind IN (
            'control_plane', 'gate_engine', 'worker', 'sdk', 'user', 'cron'
        )),
    actor_id uuid NULL,
    manifest_commit_hash text NULL
        CHECK (
            manifest_commit_hash IS NULL
            OR manifest_commit_hash ~ '^sha256-[0-9a-f]{64}$'
        ),
    payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    occurred_at timestamptz NOT NULL DEFAULT now(),
    ingest_sequence bigint GENERATED BY DEFAULT AS IDENTITY
);

CREATE INDEX event_log_scope
    ON event_log_entries(scope_type, scope_id, occurred_at DESC);

CREATE INDEX event_log_project_seq
    ON event_log_entries(project_id, ingest_sequence);
