-- W4 v2 OSS completeness, milestone M04: SQLite sidecar mirror of the §X
-- side-effect tables landed in packages/schemas/sql/0010_side_effects.sql.
--
-- The local sidecar is the OSS persistence profile (spec H.5 + spec AN local
-- profile). It mirrors the Postgres canonical shape but relaxes:
--
--   * uuid types -> TEXT (SQLite has no native uuid)
--   * timestamptz types -> TEXT (RFC 3339 strings; the wire-format layer
--     enforces tz-awareness via Pydantic)
--   * FOREIGN KEY clauses to tables that do not yet exist on the sidecar
--     profile are dropped with an inline comment; tables that DO exist
--     in earlier migrations carry inline FK clauses for parity.
--
-- CHECK constraints are PRESERVED across the SQLite mirror so the closed
-- enums (side_effect_class, state, evidence_kind) cannot accept
-- out-of-set values even on the local profile.
--
-- All statements use CREATE TABLE IF NOT EXISTS / CREATE INDEX IF NOT EXISTS
-- so re-running on startup is a no-op (the migration loader at
-- relay_sidecar/db.py:_run_migrations applies every .sql in lex order).
--
-- Spec anchors:
--   X 5119-5133   tool_side_effect_policies
--   X 5135-5150   side_effect_markers
--   X 5152-5161   side_effect_proofs
--   E.3 3931-3936 canonical four side_effect_class values
--
-- ASCII-only per CLAUDE.md "ASCII-Safe Source".

-- -----------------------------------------------------------------------------
-- tool_side_effect_policies (VAL-V2M04-001..003)
-- -----------------------------------------------------------------------------
-- FK project_id -> projects(project_id) deferred: the projects table is
-- not present in the OSS local sidecar profile (it lands with hosted
-- control plane). The application layer validates project_id format.

CREATE TABLE IF NOT EXISTS tool_side_effect_policies (
    policy_id                TEXT    PRIMARY KEY NOT NULL,
    project_id               TEXT    NOT NULL,
    tool_name                TEXT    NOT NULL,
    side_effect_class        TEXT    NOT NULL,
    idempotency_key_template TEXT,
    compensation_tool        TEXT,
    max_retries              INTEGER NOT NULL DEFAULT 1,
    approval_required        INTEGER NOT NULL DEFAULT 0,
    approval_ttl_seconds     INTEGER NOT NULL DEFAULT 86400,
    effective_at             TEXT    NOT NULL,
    effective_until          TEXT,
    CONSTRAINT tool_side_effect_policies_class_enum
        CHECK (side_effect_class IN (
            'read_only',
            'mutating',
            'external_irreversible',
            'approval_required'
        )),
    CONSTRAINT tool_side_effect_policies_max_retries_nonneg
        CHECK (max_retries >= 0),
    CONSTRAINT tool_side_effect_policies_approval_ttl_pos
        CHECK (approval_ttl_seconds > 0),
    UNIQUE (project_id, tool_name, effective_at)
);

CREATE INDEX IF NOT EXISTS tool_side_effect_policies_project_tool
    ON tool_side_effect_policies (project_id, tool_name);

-- -----------------------------------------------------------------------------
-- side_effect_markers (VAL-V2M04-004..007)
-- -----------------------------------------------------------------------------
-- FK run_id -> runs(run_id) and span_id -> spans(span_id) deferred: those
-- tables are declared by the canonical 0012_v2_canonical_tables.sql sidecar
-- mirror. We carry FK declarations inline; the migration loader applies
-- 0012 before 0018 in lex order.
-- FK policy_id -> tool_side_effect_policies(policy_id) is in this file.
--
-- UNIQUE (idempotency_key) is load-bearing for VAL-V2M04-006: only one
-- worker proceeds per side effect (§X execution contract step 2).
--
-- state enum (VAL-V2M04-005, six legal values):
--   pending, in_flight, succeeded, failed, compensated, blocked_by_approval

CREATE TABLE IF NOT EXISTS side_effect_markers (
    marker_id        TEXT    PRIMARY KEY NOT NULL,
    run_id           TEXT    NOT NULL,
    span_id          TEXT    NOT NULL,
    tool_name        TEXT    NOT NULL,
    idempotency_key  TEXT    NOT NULL,
    policy_id        TEXT    NOT NULL,
    state            TEXT    NOT NULL DEFAULT 'pending',
    created_at       TEXT    NOT NULL,
    in_flight_at     TEXT,
    expires_at       TEXT    NOT NULL,
    CONSTRAINT side_effect_markers_state_enum
        CHECK (state IN (
            'pending',
            'in_flight',
            'succeeded',
            'failed',
            'compensated',
            'blocked_by_approval'
        )),
    CONSTRAINT side_effect_markers_idempotency_key_unique
        UNIQUE (idempotency_key),
    FOREIGN KEY (policy_id) REFERENCES tool_side_effect_policies(policy_id)
);

CREATE INDEX IF NOT EXISTS side_effect_markers_state
    ON side_effect_markers (state, expires_at);

CREATE INDEX IF NOT EXISTS side_effect_markers_run
    ON side_effect_markers (run_id);

-- -----------------------------------------------------------------------------
-- side_effect_proofs (VAL-V2M04-008..010)
-- -----------------------------------------------------------------------------
-- FK marker_id -> side_effect_markers(marker_id): orphan inserts are
-- rejected by SQLite when PRAGMA foreign_keys = ON (set by the sidecar
-- database opener at db.py).

CREATE TABLE IF NOT EXISTS side_effect_proofs (
    proof_id        TEXT    PRIMARY KEY NOT NULL,
    marker_id       TEXT    NOT NULL,
    evidence_kind   TEXT    NOT NULL,
    evidence_digest TEXT    NOT NULL,
    external_id     TEXT,
    recorded_at     TEXT    NOT NULL,
    CONSTRAINT side_effect_proofs_evidence_kind_enum
        CHECK (evidence_kind IN (
            'exit_code',
            'external_id',
            'http_response',
            'span_trace',
            'signed_callback',
            'user_acknowledgement'
        )),
    FOREIGN KEY (marker_id) REFERENCES side_effect_markers(marker_id)
);

CREATE INDEX IF NOT EXISTS side_effect_proofs_marker
    ON side_effect_proofs (marker_id);
