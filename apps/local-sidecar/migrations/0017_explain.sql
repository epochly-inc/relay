-- M05 w5-explain sidecar mirror of packages/schemas/sql/0009_explain.sql
-- (VAL-V2M05-007..013).
--
-- SUPERSEDED BY 0023_audit_r3_schema_alignment.sql (VAL-V3M1-025): the
-- narrow reviewer_decision CHECK declared at lines 64-66 of this file
-- ({accept, modify, reject}) was widened by 0023:128-174 to the
-- spec-aligned 4-value enum {accept, reject, modify, pending} via a
-- DROP+CREATE rebuild of root_cause_hypotheses. Readers of this file
-- should consult 0023 for the authoritative reviewer_decision shape.
--
-- The Postgres canonical DDL lives at packages/schemas/sql/0009_explain.sql.
-- This file is the SQLite mirror executed by the sidecar migration runner
-- (apps/local-sidecar/relay_sidecar/db.py:_run_migrations).
--
-- Differences from the Postgres canonical:
--   - uuid -> TEXT (SQLite has no native UUID type)
--   - jsonb -> TEXT (SQLite stores JSON as text; the validator runs at
--     write time in the application layer)
--   - numeric(4,3) -> REAL (SQLite NUMERIC affinity is the same as REAL)
--   - Postgres ~ regex -> the generator CHECK uses a GLOB-style approximation
--     for SQLite; full taxonomy enforcement is at the wire/application layer
--     via packages/schemas/python/relay_schemas/root_cause_hypothesis.GENERATOR_REGEX
--     because SQLite REGEXP requires a user-defined function. The
--     application layer is the source of truth; the CHECK here catches
--     the most common malformed values.
--   - timestamptz -> TEXT (RFC 3339 string)
--
-- Spec anchors:
--   T 4856-4896    Explain object behavior
--   A.15 3316-3328 envelope fields
--   AJ 5733-5746   generator taxonomy
--
-- ASCII-only per CLAUDE.md "ASCII-Safe Source".

-- Drop the M01 placeholder root_cause_hypotheses table (no production data
-- yet; M01 created the bare scaffold without the M05 columns).
DROP TABLE IF EXISTS root_cause_hypotheses;

CREATE TABLE root_cause_hypotheses (
    hypothesis_id              TEXT    PRIMARY KEY NOT NULL,
    run_id                     TEXT    NOT NULL,
    span_id                    TEXT,
    hypothesis_class           TEXT    NOT NULL,
    confidence                 REAL    NOT NULL,
    evidence_refs              TEXT    NOT NULL DEFAULT '[]',
    evidence_refs_digest       TEXT    NOT NULL,
    generator                  TEXT    NOT NULL,
    reviewer_email             TEXT,
    reviewer_decision          TEXT,
    promoted_to_replay_case_id TEXT,
    schema_version             TEXT    NOT NULL
        DEFAULT 'relay.root_cause_hypothesis.v1',
    created_at                 TEXT    NOT NULL,
    CONSTRAINT root_cause_hypotheses_class_enum
        CHECK (hypothesis_class IN (
            'schema_contract_drift',
            'retrieval_miss',
            'tool_arg_invalid',
            'prompt_regression',
            'provider_drift',
            'rate_limit',
            'cost_overrun',
            'context_overflow',
            'hallucinated_citation',
            'stale_tool_doc',
            'user_misuse',
            'unknown'
        )),
    CONSTRAINT root_cause_hypotheses_confidence_range
        CHECK (confidence >= 0 AND confidence <= 1),
    CONSTRAINT root_cause_hypotheses_reviewer_decision_enum
        CHECK (reviewer_decision IS NULL
               OR reviewer_decision IN ('accept','modify','reject')),
    CONSTRAINT root_cause_hypotheses_schema_version_pin
        CHECK (schema_version = 'relay.root_cause_hypothesis.v1'),
    CONSTRAINT root_cause_hypotheses_generator_glob
        CHECK (
            generator GLOB 'heuristic.v[0-9]*'
            OR generator GLOB 'llm.*:v[0-9]*'
        ),
    CONSTRAINT root_cause_hypotheses_dedupe_uq
        UNIQUE (run_id, hypothesis_class, evidence_refs_digest)
);

CREATE INDEX IF NOT EXISTS root_cause_hypotheses_run_idx
    ON root_cause_hypotheses(run_id);
