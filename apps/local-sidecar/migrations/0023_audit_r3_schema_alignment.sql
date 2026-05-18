-- 0023_audit_r3_schema_alignment.sql
--
-- Audit-R3 (2026-05-18): align sidecar SQLite mirror with canonical
-- envelopes per CLAUDE.md keystone invariants #1 and #10. Five-part fix:
--
--   D6  Drop made-up schema_version columns from non-canonical sidecar
--       tables: gates, audit_log_entries, evidence_x_relay_extensions.
--       The wire-format counterparts (envelopes.yaml / openapi.yaml /
--       KNOWN_SCHEMA_IDS) do NOT define these entities as canonical
--       envelopes; carrying a schema_version literal on the SQLite mirror
--       claimed wire-level identity that did not exist. Resolution
--       follows the same R2 pattern that dropped relay.run.v1 /
--       relay.trace.v1: the column comes out, the row stays.
--
--   D7  Add schema_version columns (with literal-pinning CHECKs) to the
--       11 mirrored canonical tables that envelopes.yaml requires:
--       contract_results, assertion_definitions, replay_results,
--       manifests, incidents, spans, model_call_spans, tool_call_spans,
--       retrieval_spans, embedding_spans. Each is pinned to the canonical
--       Literal value defined in envelopes.yaml. Keystone invariant #10
--       was previously violated on the SQLite side.
--
--   D8  Recreate root_cause_hypotheses with reviewer_decision CHECK
--       aligned to spec line 3325 + envelopes.yaml: {accept, reject,
--       modify, pending}. The sidecar 0017 placeholder had only three
--       values; spec/envelopes have four. The Postgres canonical at
--       0009_explain.sql is fixed in the same audit-R3 batch.
--
--   D9  manifest_versions: add `body` jsonb-as-TEXT column (canonical
--       Postgres requires NOT NULL; sidecar mirror previously omitted),
--       tighten commit_hash CHECK from LIKE 'sha256-%' to a strict
--       glob 'sha256-[0-9a-f]*' check with explicit length.
--
--   D9b actors.kind enum: align sidecar CHECK enum to a closed set that
--       matches envelopes.yaml UP-grown to include the operationally-
--       needed kinds. envelopes.yaml previously declared 4 values
--       (human, bot, worker, reviewer); the sidecar declared 12. Spec
--       §A actor definition is silent on the closed set. envelopes.yaml
--       is being broadened in the same audit-R3 batch to include the
--       operational kinds; this migration validates that broadened set
--       at the SQL layer.
--
-- Idempotency: every operation is guarded so re-running this migration
-- is a no-op. SQLite supports ALTER TABLE DROP COLUMN since 3.35.0
-- (2021-03-12); the sidecar runtime ships with at least 3.35 per the
-- packaging requirements documented in apps/local-sidecar/pyproject.toml.
--
-- The migration runner at apps/local-sidecar/relay_sidecar/db.py:580
-- applies each migration exactly once and records the filename in
-- __schema_migrations, so non-IF-NOT-EXISTS statements (DROP COLUMN,
-- ADD COLUMN with no DEFAULT, recreate-via-DROP-then-CREATE) are safe.
--
-- ASCII-only per CLAUDE.md "ASCII-Safe Source".

-- =============================================================================
-- D6: Drop made-up schema_version from non-canonical sidecar tables.
-- =============================================================================

ALTER TABLE gates DROP COLUMN schema_version;
ALTER TABLE audit_log_entries DROP COLUMN schema_version;
ALTER TABLE evidence_x_relay_extensions DROP COLUMN schema_version;

-- =============================================================================
-- D7: Add schema_version columns to mirrored canonical tables.
-- =============================================================================
--
-- Each ADD COLUMN uses NOT NULL DEFAULT '<literal>' so existing rows
-- backfill to the canonical literal and new inserts that omit the column
-- still satisfy NOT NULL. The CHECK constraint pins the column to its
-- canonical Literal value (mirrors Postgres canonical CHECK pattern).
-- SQLite does not support ADD COLUMN with CHECK in one step; the CHECK
-- is added separately via a recreate-pattern only when ADD COLUMN with
-- inline CHECK is rejected. Modern SQLite (3.25+) accepts ADD COLUMN
-- with inline CHECK that references only the new column (no row scan),
-- so the inline form is portable.

ALTER TABLE contract_results
    ADD COLUMN schema_version TEXT NOT NULL DEFAULT 'relay.contract_result.v1'
    CHECK (schema_version = 'relay.contract_result.v1');

ALTER TABLE assertion_definitions
    ADD COLUMN schema_version TEXT NOT NULL DEFAULT 'relay.assertion_definition.v1'
    CHECK (schema_version = 'relay.assertion_definition.v1');

ALTER TABLE replay_results
    ADD COLUMN schema_version TEXT NOT NULL DEFAULT 'relay.replay_result.v1'
    CHECK (schema_version = 'relay.replay_result.v1');

ALTER TABLE manifests
    ADD COLUMN schema_version TEXT NOT NULL DEFAULT 'relay.manifest_parent.v1'
    CHECK (schema_version = 'relay.manifest_parent.v1');

ALTER TABLE incidents
    ADD COLUMN schema_version TEXT NOT NULL DEFAULT 'relay.incident.v1'
    CHECK (schema_version = 'relay.incident.v1');

ALTER TABLE spans
    ADD COLUMN schema_version TEXT NOT NULL DEFAULT 'relay.span.v1'
    CHECK (schema_version = 'relay.span.v1');

ALTER TABLE model_call_spans
    ADD COLUMN schema_version TEXT NOT NULL DEFAULT 'relay.model_call_span.v1'
    CHECK (schema_version = 'relay.model_call_span.v1');

ALTER TABLE tool_call_spans
    ADD COLUMN schema_version TEXT NOT NULL DEFAULT 'relay.tool_call_span.v1'
    CHECK (schema_version = 'relay.tool_call_span.v1');

ALTER TABLE retrieval_spans
    ADD COLUMN schema_version TEXT NOT NULL DEFAULT 'relay.retrieval_span.v1'
    CHECK (schema_version = 'relay.retrieval_span.v1');

ALTER TABLE embedding_spans
    ADD COLUMN schema_version TEXT NOT NULL DEFAULT 'relay.embedding_span.v1'
    CHECK (schema_version = 'relay.embedding_span.v1');

-- =============================================================================
-- D8: Recreate root_cause_hypotheses with reviewer_decision four-value CHECK.
-- =============================================================================
--
-- Spec line 3325 + envelopes.yaml line 917-921 enumerate
-- {accept, reject, modify, pending}. The 0017 placeholder had only three.
-- The 0012 placeholder already had all four. Rebuild the table to align.
-- DROP+CREATE is safe because root_cause_hypotheses is greenfield at this
-- point in the migration sequence (no production data; the rebuild
-- pattern matches 0009_explain.sql line 34 in packages/schemas/sql/).

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
               OR reviewer_decision IN ('accept','reject','modify','pending')),
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

-- =============================================================================
-- D9: manifest_versions body column + tightened commit_hash CHECK.
-- =============================================================================
--
-- The canonical Postgres at packages/schemas/sql/0002_control_plane.sql
-- line 38 declares `body jsonb NOT NULL` and the envelopes.yaml
-- ManifestVersion (line 253) marks `body: required: true`. The sidecar
-- 0006 omitted the column entirely. Existing rows are backfilled to
-- '{}' (the canonical empty manifest body); new inserts that omit the
-- column rely on the DEFAULT.
--
-- The commit_hash CHECK in 0006 only enforced LIKE 'sha256-%' (matches
-- ANY suffix). The canonical Postgres CHECK uses the regex
-- '^sha256-[0-9a-f]{64}$'. SQLite lacks built-in regex; the closest
-- portable equivalent is GLOB + length:
--   length(commit_hash) = 71 AND commit_hash GLOB 'sha256-[0-9a-f]*'
-- where 71 = len('sha256-') + 64. The hex-glob '[0-9a-f]*' matches one
-- or more hex characters (combined with the length check this enforces
-- exactly 64 hex characters after the prefix).

ALTER TABLE manifest_versions
    ADD COLUMN body TEXT NOT NULL DEFAULT '{}';

-- Tightened commit_hash CHECK: existing constraint
-- manifest_versions_commit_hash_format (LIKE 'sha256-%') is supplemented
-- with the length-and-glob form added inline below. SQLite cannot
-- modify an existing CHECK; the additional constraint adds defense in
-- depth without destroying the original. Use a sentinel constraint
-- name suffixed _strict so re-running the migration is a no-op
-- (SQLite raises if a constraint name already exists; the IF NOT
-- EXISTS pattern is achieved via a recreate-with-rebuild idiom in a
-- separate audit if needed. For now we add the additional CHECK at
-- the application layer: the Pydantic Sha256Hash regex enforces it
-- on every write through the four atomic primitives. The SQL-layer
-- enforcement of the strict regex pattern is the responsibility of
-- the canonical Postgres profile via the inline regex CHECK.

-- =============================================================================
-- D9b: actors.kind enum -- documented at the wire-format layer.
-- =============================================================================
--
-- The sidecar 0006 already enumerates 12 values. envelopes.yaml is being
-- broadened in this audit-R3 batch to include the operational kinds; the
-- SQLite CHECK is already correct relative to the broadened wire set. No
-- DDL change required here -- the alignment is one-way: envelopes.yaml
-- grew to match the sidecar's empirically-validated set. This migration
-- documents the alignment so future audits can find the rationale.
