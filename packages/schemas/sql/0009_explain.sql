-- M05 w5-explain: extend root_cause_hypotheses to the v1 contract (VAL-V2M05-007..013).
--
-- The base table was created by 0004_v2_canonical_tables.sql under VAL-V2M01-008.
-- This migration extends it with the v0.2 OSS-completeness columns and
-- DB-layer constraints that the Explain pipeline depends on:
--
--   - evidence_refs_digest:           SHA-256 over canonical evidence_refs JSON,
--                                     part of the (run_id, hypothesis_class,
--                                     evidence_refs_digest) dedupe key (VAL-V2M05-012)
--   - schema_version:                 envelope version pin (VAL-V2M05-013)
--   - hypothesis_class CHECK:         12-value enum lock (VAL-V2M05-008)
--   - generator CHECK:                taxonomy regex enforcement (VAL-V2M05-009)
--   - confidence numeric(4,3):        bounded precision per spec A.15 (VAL-V2M05-010)
--   - reviewer_decision CHECK:        restrict to accept|modify|reject|NULL
--                                     (VAL-V2M05-011 closes the spec T closed set)
--   - UNIQUE (run_id, hypothesis_class, evidence_refs_digest): dedupe (VAL-V2M05-012)
--
-- Spec anchors:
--   T 4856-4896    Explain object behavior
--   A.15 3316-3328 envelope fields
--   AJ 5733-5746   generator taxonomy
--
-- We rebuild the table rather than ALTER it because Postgres + SQLite differ
-- on ALTER TABLE ADD CONSTRAINT support across the matrix; the explicit
-- CREATE-with-constraints is the simplest invariant-preserving form. No
-- row data exists for root_cause_hypotheses in any environment yet.
--
-- ASCII-only per CLAUDE.md "ASCII-Safe Source".

-- -----------------------------------------------------------------------------
-- root_cause_hypotheses (extended; spec A.15 + T; VAL-V2M05-007..013)
-- -----------------------------------------------------------------------------

DROP TABLE IF EXISTS root_cause_hypotheses;

CREATE TABLE root_cause_hypotheses (
    hypothesis_id              uuid PRIMARY KEY,
    run_id                     uuid NOT NULL REFERENCES runs(run_id),
    span_id                    uuid REFERENCES spans(span_id),
    hypothesis_class           text NOT NULL
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
    confidence                 numeric(4,3) NOT NULL
        CHECK (confidence >= 0 AND confidence <= 1),
    evidence_refs              jsonb NOT NULL DEFAULT '[]',
    evidence_refs_digest       text NOT NULL,
    generator                  text NOT NULL
        CHECK (generator ~ '^heuristic\.v\d+$|^llm\.[a-z0-9-]+:v\d+$'),
    reviewer_email             text,
    -- Audit-R3 (2026-05-18): align reviewer_decision enum with spec
    -- line 3325 + envelopes.yaml:917-921 + openapi.yaml:1559-1563. The
    -- canonical set is {accept, reject, modify, pending}. The prior
    -- three-value set omitted 'pending' (a hypothesis awaiting review
    -- but not yet decided).
    reviewer_decision          text
        CHECK (reviewer_decision IS NULL
               OR reviewer_decision IN ('accept','reject','modify','pending')),
    promoted_to_replay_case_id uuid REFERENCES replay_cases(replay_case_id),
    schema_version             text NOT NULL DEFAULT 'relay.root_cause_hypothesis.v1'
        CHECK (schema_version = 'relay.root_cause_hypothesis.v1'),
    created_at                 timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT root_cause_hypotheses_dedupe_uq
        UNIQUE (run_id, hypothesis_class, evidence_refs_digest)
);
