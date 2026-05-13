-- W2.4 migration 0002: run_results (canonical run outcome).
--
-- Mirrors spec A.1 schema. The local-sidecar SQLite variant differs from
-- the spec's Postgres DDL in three ways:
--   1. UUIDs are stored as TEXT (SQLite has no native uuid type).
--   2. timestamptz columns are stored as TEXT (ISO-8601 with explicit Z).
--   3. Foreign-key targets that have not yet been created on SQLite
--      (projects, runs, evidence_bundles) are stored as plain TEXT
--      columns without REFERENCES clauses; the hosted Postgres profile
--      will enforce FKs. SQLite enforcement lands when those tables
--      land in later W2 sub-features.
--
-- Per CLAUDE.md keystone invariant #1 (control plane writes the result):
-- the ``written_by = 'control_plane'`` CHECK constraint is the SQL-layer
-- enforcement of that invariant. Direct INSERT with any other value MUST
-- fail with IntegrityError (VAL-W2-025).
--
-- Per spec A.1 constraint clause: ``status = 'accepted'`` requires
-- ``evidence_bundle_id IS NOT NULL`` (the ``accepted_requires_evidence``
-- CHECK; VAL-W2-026).
--
-- This migration is idempotent (CREATE ... IF NOT EXISTS) per the W2.3
-- migrations contract.

CREATE TABLE IF NOT EXISTS run_results (
    run_result_id          TEXT    PRIMARY KEY NOT NULL,
    run_id                 TEXT    NOT NULL UNIQUE,
    project_id             TEXT    NOT NULL,
    schema_version         TEXT    NOT NULL DEFAULT 'relay.run_result.v1',
    written_by             TEXT    NOT NULL DEFAULT 'control_plane',
    status                 TEXT    NOT NULL,
    primary_failure_class  TEXT,
    error_priority_rule    TEXT    NOT NULL
                                      DEFAULT 'first_p0_then_highest_severity_then_earliest_span',
    evidence_bundle_id     TEXT,
    manifest_commit_hash   TEXT    NOT NULL,
    actor_identity_hash    TEXT    NOT NULL,
    decided_at             TEXT    NOT NULL,
    decision_epoch         INTEGER NOT NULL,
    signature              TEXT    NOT NULL,
    signature_key_id       TEXT    NOT NULL,
    -- Keystone invariant #1: only the control plane writes this table.
    CONSTRAINT written_by_control_plane
        CHECK (written_by = 'control_plane'),
    -- Spec A.1 status enum.
    CONSTRAINT run_results_status_enum
        CHECK (status IN ('accepted', 'remediate_required', 'blocked', 'invalid')),
    -- Spec A.1 cross-field constraint: accepted requires evidence.
    CONSTRAINT accepted_requires_evidence
        CHECK (status <> 'accepted' OR evidence_bundle_id IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS ix_run_results_project_decided
    ON run_results(project_id, decided_at);
