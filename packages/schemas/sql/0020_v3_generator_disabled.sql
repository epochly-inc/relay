-- 0020_v3_generator_disabled.sql
--
-- V3M4-F02: spec AJ auto-disable banner table (VAL-V3M4-005).
--
-- Spec anchor: planning/epochly-replay-spec.md AJ line 5745 ("Auto-
-- disable + banner").
--
-- The quality harness in packages/explain/src/relay_explain/quality/harness.py
-- evaluates a generator against a labeled ground-truth corpus per
-- HYPOTHESIS_CLASS and surfaces threshold violations via
-- QualityReport.criteria_failed (per VAL-V3M4-002..004). When a P0
-- failure-class criterion trips, the runner calls auto_disable_generator
-- (see packages/explain/src/relay_explain/heuristic.py) which atomically:
--
--   1. Inserts one row into generator_disabled, keyed on the versioned
--      generator_name (e.g. 'heuristic.v1', 'llm.gpt-5:v3').
--   2. Appends one event_log_entries row of event_type
--      'generator.auto_disabled' carrying the failure summary.
--
-- Both writes are co-committed in a single BEGIN IMMEDIATE..COMMIT block
-- per CLAUDE.md keystone invariant #8 (atomic primitives).
--
-- The emission-time check in HeuristicV1Generator.generate() reads this
-- table by versioned generator_name BEFORE producing drafts and raises
-- GeneratorDisabledError when a matching row exists (VAL-V3M4-006).
--
-- The verifier-side read helper get_generator_status() returns
-- {'disabled','active'} based on row presence (VAL-V3M4-008). A disabled
-- generator status warns but does NOT invalidate already-signed bundles;
-- it is surfaced as informational metadata on the verifier output.
--
-- Versioning (VAL-V3M4-010): the primary key is the versioned
-- generator_name in canonical form per spec AJ taxonomy:
--   heuristic.v<N>
--   llm.<model>:v<N>
-- Disabling v1 of a generator does NOT prevent v2 from emitting; the
-- table is keyed on the full versioned form so each version is an
-- independent control surface.
--
-- Columns:
--   generator_name   versioned generator id; e.g. 'heuristic.v1'.
--                    Matches the regex enforced by
--                    packages/schemas/python/relay_schemas/root_cause_hypothesis.GENERATOR_REGEX.
--   disabled_at      RFC 3339 UTC timestamp when the row was inserted.
--   reason           Free-text rationale (e.g.
--                    'quality_harness:p0_recall_below_threshold').
--   criteria_failed  Pipe-delimited string of {class_name}:{criterion}
--                    pairs ('schema_contract_violation:recall|p0_assertion_failure:precision').
--                    Storing as TEXT keeps the schema portable across
--                    SQLite and Postgres; the structured shape lives in
--                    the paired event_log_entries.payload.
--
-- Idempotent (CREATE TABLE IF NOT EXISTS + CREATE INDEX IF NOT EXISTS).
--
-- ASCII-only per CLAUDE.md "ASCII-Safe Source".

CREATE TABLE IF NOT EXISTS generator_disabled (
    generator_name   text         PRIMARY KEY NOT NULL,
    disabled_at      timestamptz  NOT NULL,
    reason           text         NOT NULL,
    criteria_failed  text         NOT NULL DEFAULT '',
    CONSTRAINT generator_disabled_generator_name_format
        CHECK (
            generator_name ~ '^heuristic\.v\d+$'
            OR generator_name ~ '^llm\.[a-z0-9-]+:v\d+$'
        )
);

CREATE INDEX IF NOT EXISTS ix_generator_disabled_disabled_at
    ON generator_disabled(disabled_at);
