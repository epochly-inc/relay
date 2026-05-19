-- 0031_v3_generator_disabled.sql
--
-- V3M4-F02: sidecar mirror of packages/schemas/sql/0020_v3_generator_disabled.sql
-- (VAL-V3M4-005).
--
-- Spec anchor: planning/epochly-replay-spec.md AJ line 5745 ("Auto-
-- disable + banner").
--
-- The Postgres canonical DDL lives at
-- packages/schemas/sql/0020_v3_generator_disabled.sql. This file is the
-- SQLite mirror executed by the sidecar migration runner
-- (apps/local-sidecar/relay_sidecar/db.py:_run_migrations).
--
-- Differences from the Postgres canonical:
--   - timestamptz -> TEXT (RFC 3339 string; SQLite has no native tz type)
--   - Postgres '~' regex -> SQLite GLOB approximation (full regex
--     enforcement lives in the application layer at
--     packages/schemas/python/relay_schemas/root_cause_hypothesis.GENERATOR_REGEX
--     and is also enforced by the heuristic generator's versioned-name
--     property at packages/explain/src/relay_explain/heuristic.py).
--
-- The auto-disable write path
-- (packages/explain/src/relay_explain/heuristic.py::auto_disable_generator)
-- writes ONE generator_disabled row AND ONE event_log_entries row of
-- event_type 'generator.auto_disabled' atomically inside a BEGIN
-- IMMEDIATE..COMMIT block per CLAUDE.md keystone invariant #8 (atomic
-- primitives). The state-engine-writes-only guard at
-- apps/local-sidecar/tests/test_state_engine_writes_only.py whitelists
-- the explain heuristic module for this event-emission path (see the
-- V3M4-F02 _PERMITTED_EXPLAIN_HEURISTIC_FILE entry).
--
-- VAL-V3M4-010 versioning: the PK is the canonical versioned form
-- (heuristic.v<N> / llm.<model>:v<N>). Disabling 'heuristic.v1' does not
-- affect 'heuristic.v2'; each version is an independent control surface.
--
-- Idempotent (CREATE TABLE IF NOT EXISTS + CREATE INDEX IF NOT EXISTS).
--
-- ASCII-only per CLAUDE.md "ASCII-Safe Source".

CREATE TABLE IF NOT EXISTS generator_disabled (
    generator_name   TEXT    PRIMARY KEY NOT NULL,
    disabled_at      TEXT    NOT NULL,
    reason           TEXT    NOT NULL,
    criteria_failed  TEXT    NOT NULL DEFAULT '',
    CONSTRAINT generator_disabled_generator_name_glob
        CHECK (
            generator_name GLOB 'heuristic.v[0-9]*'
            OR generator_name GLOB 'llm.*:v[0-9]*'
        )
);

CREATE INDEX IF NOT EXISTS ix_generator_disabled_disabled_at
    ON generator_disabled(disabled_at);
