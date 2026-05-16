-- 0013_legal_holds.sql
--
-- W1-4 v0.2 OSS completeness, milestone M01: SQLite sidecar mirror of the
-- two new canonical tables landed in packages/schemas/sql/0005_legal_holds.sql.
--
-- See the header of apps/local-sidecar/migrations/0012_v2_canonical_tables.sql
-- for the mirroring conventions:
--
--   * uuid types -> TEXT
--   * timestamptz types -> TEXT (RFC 3339 strings; tz-aware enforced at wire layer)
--   * boolean types -> INTEGER with CHECK (col IN (0,1))
--   * FOREIGN KEY clauses to tables that do not yet exist on the sidecar
--     profile are dropped with an inline comment; the canonical Postgres
--     profile carries the FKs.
--
-- CHECK constraints are PRESERVED across the SQLite mirror so the closed
-- enums (scope_kind, state for legal holds; state for the registry) cannot
-- accept out-of-set values even on the local profile.
--
-- All statements use CREATE TABLE IF NOT EXISTS / CREATE INDEX IF NOT EXISTS
-- so re-running on startup is a no-op (the migration loader at
-- relay_sidecar/db.py applies every .sql in lex order).
--
-- ASCII-only per CLAUDE.md "ASCII-Safe Source".

-- ---- evidence_legal_holds (VAL-V2M01-026) ----
-- FKs org_id -> orgs(org_id), imposed_by_user_id -> users(user_id),
-- released_by_user_id -> users(user_id) all deferred on the sidecar
-- profile (orgs and users tables not present locally).

CREATE TABLE IF NOT EXISTS evidence_legal_holds (
    hold_id                TEXT    PRIMARY KEY NOT NULL,
    org_id                 TEXT    NOT NULL,
    scope_kind             TEXT    NOT NULL,
    scope_id               TEXT    NOT NULL,
    reason                 TEXT    NOT NULL,
    legal_matter_ref       TEXT,
    imposed_by_user_id     TEXT    NOT NULL,
    counsel_signoff_at     TEXT,
    counsel_signoff_by     TEXT,
    state                  TEXT    NOT NULL DEFAULT 'active',
    imposed_at             TEXT    NOT NULL,
    released_at            TEXT,
    released_by_user_id    TEXT,
    CONSTRAINT evidence_legal_holds_scope_kind_enum
        CHECK (scope_kind IN ('org','project','run','evidence_bundle')),
    CONSTRAINT evidence_legal_holds_state_enum
        CHECK (state IN ('active','released'))
);

-- Partial index mirrors the Postgres profile: only active rows participate
-- in the "is this scope under hold?" lookup the retention sweep performs.
CREATE INDEX IF NOT EXISTS evidence_legal_holds_active
    ON evidence_legal_holds(scope_kind, scope_id) WHERE state = 'active';

-- ---- evidence_bundle_registry (VAL-V2M01-027) ----
-- FK evidence_bundle_id -> evidence_bundles(bundle_id) deferred: the
-- sidecar mirror of evidence_bundles uses PK column ``bundle_id`` not
-- ``evidence_bundle_id`` (apps/local-sidecar/migrations/0009_gate_decision_writer.sql
-- line 80). The Postgres profile uses ``evidence_bundle_id`` per
-- packages/schemas/sql/0003_evidence_replay.sql line 37. The wire-format
-- layer normalizes the field name across both profiles via the
-- EvidenceBundleRegistry envelope.

CREATE TABLE IF NOT EXISTS evidence_bundle_registry (
    evidence_bundle_id               TEXT    PRIMARY KEY NOT NULL,
    state                            TEXT    NOT NULL DEFAULT 'active',
    superseded_by                    TEXT,
    subject_redacted_after_signing   INTEGER NOT NULL DEFAULT 0,
    redaction_event_ref              TEXT,
    legal_hold_id                    TEXT,
    last_state_change_at             TEXT    NOT NULL,
    CONSTRAINT evidence_bundle_registry_state_enum
        CHECK (state IN ('active','superseded','tombstoned','legal_hold')),
    CONSTRAINT evidence_bundle_registry_subject_redacted_bool
        CHECK (subject_redacted_after_signing IN (0,1))
);

CREATE INDEX IF NOT EXISTS evidence_bundle_registry_state
    ON evidence_bundle_registry(state);
CREATE INDEX IF NOT EXISTS evidence_bundle_registry_legal_hold
    ON evidence_bundle_registry(legal_hold_id) WHERE legal_hold_id IS NOT NULL;
