-- W1-1 v2 OSS completeness, milestone M01: SQLite sidecar mirror of the 13
-- new canonical tables landed in packages/schemas/sql/0004_v2_canonical_tables.sql.
--
-- The local sidecar is the OSS persistence profile (spec H.5 + spec AN local
-- profile). It mirrors the Postgres canonical shape but relaxes:
--
--   * uuid types -> TEXT (SQLite has no native uuid)
--   * timestamptz types -> TEXT (RFC 3339 strings; the wire-format layer
--     enforces tz-awareness via Pydantic)
--   * jsonb types -> TEXT (JSON-encoded; readers parse on demand)
--   * uuid[] arrays -> TEXT (JSON-encoded array of TEXT; SQLite has no
--     native array type)
--   * GENERATED ... AS IDENTITY -> INTEGER PRIMARY KEY (only relevant for
--     event_log_entries which is already mirrored in 0001; not used here)
--   * FOREIGN KEY clauses to tables that do not yet exist on the sidecar
--     profile are dropped with an inline comment explaining the deferred
--     FK chain (the canonical Postgres profile carries the FKs; the
--     sidecar enforces the same shape through application-level checks
--     until the dependent migrations land).
--
-- CHECK constraints are PRESERVED across the SQLite mirror so the closed
-- enums (blocking_severity, outcome, severity, lifecycle_state, state,
-- reviewer_decision, args_validation_outcome, span_type) cannot accept
-- out-of-set values even on the local profile.
--
-- All statements use CREATE TABLE IF NOT EXISTS / CREATE INDEX IF NOT EXISTS
-- so re-running on startup is a no-op (the migration loader at
-- relay_sidecar/db.py:450-470 applies every .sql in lex order).
--
-- ASCII-only per CLAUDE.md "ASCII-Safe Source".

-- ---- gate_policies (VAL-V2M01-001) ----
-- FK gate_id -> gates(gate_id) deferred (gates table lands with M03).

CREATE TABLE IF NOT EXISTS gate_policies (
    gate_policy_id           TEXT    PRIMARY KEY NOT NULL,
    gate_id                  TEXT    NOT NULL,
    policy_version           TEXT    NOT NULL,
    schema_version           TEXT    NOT NULL DEFAULT 'relay.gate_policy.v1',
    conditions               TEXT    NOT NULL,
    baseline_selector        TEXT,
    flaky_quarantine_policy  TEXT,
    blocking_severity        TEXT    NOT NULL DEFAULT 'p0_only',
    effective_at             TEXT    NOT NULL,
    effective_until          TEXT,
    CONSTRAINT gate_policies_blocking_severity_enum
        CHECK (blocking_severity IN ('p0_only','p0_p1','any_failure')),
    CONSTRAINT gate_policies_schema_version_pin
        CHECK (schema_version = 'relay.gate_policy.v1'),
    UNIQUE(gate_id, policy_version)
);

-- ---- contract_results (VAL-V2M01-002) ----
-- FKs run_id -> runs, contract_id -> contracts, span_id -> spans deferred
-- (runs and contracts land with M02/M03; spans is created in this same
-- migration below so that FK could be added inline, but SQLite is
-- relaxed for parity with the other deferred FKs).

CREATE TABLE IF NOT EXISTS contract_results (
    contract_result_id           TEXT    PRIMARY KEY NOT NULL,
    run_id                       TEXT    NOT NULL,
    contract_id                  TEXT    NOT NULL,
    contract_version             TEXT    NOT NULL,
    assertion_id                 TEXT,
    span_id                      TEXT,
    outcome                      TEXT    NOT NULL,
    severity                     TEXT,
    raw_signature_hash           TEXT,
    repair_attempt               INTEGER NOT NULL DEFAULT 0,
    evaluation_engine_version    TEXT    NOT NULL,
    evaluated_at                 TEXT    NOT NULL,
    metadata                     TEXT    NOT NULL DEFAULT '{}',
    CONSTRAINT contract_results_outcome_enum
        CHECK (outcome IN ('pass','fail','repaired','skipped','error')),
    CONSTRAINT contract_results_severity_enum
        CHECK (severity IS NULL OR severity IN ('p0','p1','p2','info'))
);

CREATE INDEX IF NOT EXISTS contract_results_run
    ON contract_results(run_id);
CREATE INDEX IF NOT EXISTS contract_results_run_outcome
    ON contract_results(run_id, outcome);

-- ---- assertion_definitions (VAL-V2M01-003) ----
-- PK is TEXT (not uuid) per spec A.7. project_id FK -> projects deferred.

CREATE TABLE IF NOT EXISTS assertion_definitions (
    assertion_id        TEXT    PRIMARY KEY NOT NULL,
    project_id          TEXT    NOT NULL,
    kind                TEXT    NOT NULL,
    severity            TEXT    NOT NULL,
    title               TEXT    NOT NULL,
    description         TEXT,
    owner_email         TEXT    NOT NULL,
    expression          TEXT    NOT NULL,
    applies_to          TEXT    NOT NULL DEFAULT '{}',
    lifecycle_state     TEXT    NOT NULL DEFAULT 'draft',
    current_version     INTEGER NOT NULL DEFAULT 1,
    created_at          TEXT    NOT NULL,
    updated_at          TEXT    NOT NULL,
    CONSTRAINT assertion_definitions_kind_enum
        CHECK (kind IN ('schema_contract','behavioral','tool_arg','eval','coverage')),
    CONSTRAINT assertion_definitions_severity_enum
        CHECK (severity IN ('p0','p1','p2','info')),
    CONSTRAINT assertion_definitions_lifecycle_state_enum
        CHECK (lifecycle_state IN ('draft','active','deprecated','retired'))
);

-- ---- replay_results (VAL-V2M01-004) ----
-- FK replay_case_id -> replay_cases (defined in 0004 Postgres but not in
-- the sidecar yet; deferred). FK replay_run_id -> runs deferred.
-- FK evidence_bundle_id -> evidence_bundles deferred.

CREATE TABLE IF NOT EXISTS replay_results (
    replay_result_id              TEXT    PRIMARY KEY NOT NULL,
    replay_case_id                TEXT    NOT NULL,
    replay_run_id                 TEXT    NOT NULL,
    outcome                       TEXT    NOT NULL,
    failure_signature_match       INTEGER,
    fixture_hits                  INTEGER NOT NULL DEFAULT 0,
    fixture_misses                INTEGER NOT NULL DEFAULT 0,
    sandbox_driver                TEXT    NOT NULL,
    sandbox_id                    TEXT,
    network_egress_denied         INTEGER NOT NULL DEFAULT 0,
    side_effect_attempts          INTEGER NOT NULL DEFAULT 0,
    side_effect_approved          INTEGER NOT NULL DEFAULT 0,
    evidence_bundle_id            TEXT,
    created_at                    TEXT    NOT NULL,
    CONSTRAINT replay_results_outcome_enum
        CHECK (outcome IN ('reproduced','diverged','blocked','sandbox_error')),
    CONSTRAINT replay_results_failure_signature_match_bool
        CHECK (failure_signature_match IS NULL OR failure_signature_match IN (0,1)),
    CONSTRAINT replay_results_fixture_hits_nonneg
        CHECK (fixture_hits >= 0),
    CONSTRAINT replay_results_fixture_misses_nonneg
        CHECK (fixture_misses >= 0)
);

-- ---- manifests parent (VAL-V2M01-005) ----
-- Parent of manifest_versions (which lives in 0006_manifest_versions.sql).
-- FK project_id -> projects deferred.

CREATE TABLE IF NOT EXISTS manifests (
    manifest_id          TEXT    PRIMARY KEY NOT NULL,
    project_id           TEXT    NOT NULL,
    name                 TEXT    NOT NULL,
    created_at           TEXT    NOT NULL,
    UNIQUE(project_id, name)
);

-- ---- redaction_policies (VAL-V2M01-006; CLAUDE.md keystone invariant #7) ----
-- raw_capture_default MUST default to literal false (= 0 in SQLite).
-- FK project_id -> projects deferred.

CREATE TABLE IF NOT EXISTS redaction_policies (
    policy_id               TEXT    PRIMARY KEY NOT NULL,
    project_id              TEXT    NOT NULL,
    policy_version          TEXT    NOT NULL,
    schema_version          TEXT    NOT NULL DEFAULT 'relay.redaction.v1',
    body                    TEXT    NOT NULL,
    raw_capture_default     INTEGER NOT NULL DEFAULT 0,
    effective_at            TEXT    NOT NULL,
    effective_until         TEXT,
    CONSTRAINT redaction_policies_raw_capture_bool
        CHECK (raw_capture_default IN (0,1)),
    CONSTRAINT redaction_policies_schema_version_pin
        CHECK (schema_version = 'relay.redaction.v1'),
    UNIQUE(project_id, policy_version)
);

-- ---- incidents (VAL-V2M01-007) ----
-- affected_run_ids is uuid[] on Postgres; mirrored as a JSON-encoded TEXT
-- on SQLite (no native array type). FK project_id -> projects deferred.

CREATE TABLE IF NOT EXISTS incidents (
    incident_id                 TEXT    PRIMARY KEY NOT NULL,
    project_id                  TEXT    NOT NULL,
    cluster_signature_hash      TEXT    NOT NULL,
    severity                    TEXT    NOT NULL,
    state                       TEXT    NOT NULL DEFAULT 'open',
    affected_run_ids            TEXT    NOT NULL DEFAULT '[]',
    first_seen_at               TEXT    NOT NULL,
    last_seen_at                TEXT    NOT NULL,
    owner_email                 TEXT,
    postmortem_ref              TEXT,
    promoted_to_regression      INTEGER NOT NULL DEFAULT 0,
    created_at                  TEXT    NOT NULL,
    CONSTRAINT incidents_severity_enum
        CHECK (severity IN ('sev1','sev2','sev3','sev4')),
    CONSTRAINT incidents_state_enum
        CHECK (state IN ('open','mitigated','closed','suppressed')),
    CONSTRAINT incidents_promoted_to_regression_bool
        CHECK (promoted_to_regression IN (0,1))
);

CREATE INDEX IF NOT EXISTS incidents_cluster
    ON incidents(project_id, cluster_signature_hash);

-- ---- root_cause_hypotheses (VAL-V2M01-008; Explain object, spec T) ----
-- FK run_id -> runs deferred. FK span_id -> spans satisfied below.
-- FK promoted_to_replay_case_id -> replay_cases deferred.

CREATE TABLE IF NOT EXISTS root_cause_hypotheses (
    hypothesis_id                  TEXT    PRIMARY KEY NOT NULL,
    run_id                         TEXT    NOT NULL,
    span_id                        TEXT,
    hypothesis_class               TEXT    NOT NULL,
    confidence                     REAL    NOT NULL,
    evidence_refs                  TEXT    NOT NULL DEFAULT '[]',
    generator                      TEXT    NOT NULL,
    reviewer_email                 TEXT,
    reviewer_decision              TEXT,
    promoted_to_replay_case_id     TEXT,
    created_at                     TEXT    NOT NULL,
    CONSTRAINT root_cause_hypotheses_confidence_range
        CHECK (confidence >= 0 AND confidence <= 1),
    CONSTRAINT root_cause_hypotheses_reviewer_decision_enum
        CHECK (reviewer_decision IS NULL
               OR reviewer_decision IN ('accept','reject','modify','pending'))
);

-- ---- spans parent (VAL-V2M01-009) ----
-- The polymorphic typed-detail-row invariant: see comment block in
-- packages/schemas/sql/0004_v2_canonical_tables.sql header. The ingest
-- worker writes both the parent and the typed-detail row atomically.
-- Canonical missing-detail error code: RELAY-INGEST-SPAN-DETAIL-MISSING.

CREATE TABLE IF NOT EXISTS spans (
    span_id              TEXT    PRIMARY KEY NOT NULL,
    run_id               TEXT,
    parent_span_id       TEXT,
    span_type            TEXT    NOT NULL,
    name                 TEXT    NOT NULL,
    status               TEXT    NOT NULL,
    started_at           TEXT    NOT NULL,
    ended_at             TEXT,
    error_class          TEXT,
    metadata             TEXT    NOT NULL DEFAULT '{}',
    CONSTRAINT spans_span_type_enum
        CHECK (span_type IN ('model_call','tool_call','retrieval','embedding','custom'))
);

CREATE INDEX IF NOT EXISTS spans_run ON spans(run_id);
CREATE INDEX IF NOT EXISTS spans_parent ON spans(parent_span_id);

-- ---- model_call_spans (VAL-V2M01-010) ----

CREATE TABLE IF NOT EXISTS model_call_spans (
    span_id                              TEXT    PRIMARY KEY NOT NULL
        REFERENCES spans(span_id) ON DELETE CASCADE,
    provider                             TEXT    NOT NULL,
    model                                TEXT    NOT NULL,
    model_signature                      TEXT,
    request_message_count                INTEGER,
    request_token_count                  INTEGER,
    response_token_count                 INTEGER,
    cached_token_count                   INTEGER,
    reasoning_token_count                INTEGER,
    cost_usd                             REAL,
    latency_ms                           INTEGER,
    finish_reason                        TEXT,
    structured_output_mode               TEXT,
    schema_contract_id                   TEXT,
    tool_choice_mode                     TEXT,
    streaming                            INTEGER NOT NULL DEFAULT 0,
    input_redaction_policy_version      TEXT    NOT NULL,
    input_digest                         TEXT,
    output_digest                        TEXT,
    http_status                          INTEGER,
    provider_error_code                  TEXT,
    provider_error_class                 TEXT,
    CONSTRAINT model_call_spans_streaming_bool
        CHECK (streaming IN (0,1))
);

-- ---- tool_call_spans (VAL-V2M01-011) ----
-- FK marker_id -> side_effect_markers deferred (lands with M04).

CREATE TABLE IF NOT EXISTS tool_call_spans (
    span_id                              TEXT    PRIMARY KEY NOT NULL
        REFERENCES spans(span_id) ON DELETE CASCADE,
    tool_name                            TEXT    NOT NULL,
    side_effect_class                    TEXT    NOT NULL,
    args_digest                          TEXT,
    args_redaction_policy_version        TEXT    NOT NULL,
    args_schema_contract_id              TEXT,
    args_validation_outcome              TEXT,
    result_digest                        TEXT,
    status                               TEXT    NOT NULL,
    latency_ms                           INTEGER,
    marker_id                            TEXT,
    parallel_index                       INTEGER,
    CONSTRAINT tool_call_spans_args_validation_outcome_enum
        CHECK (args_validation_outcome IS NULL
               OR args_validation_outcome IN ('pass','fail','repaired','skipped','error'))
);

-- ---- retrieval_spans (VAL-V2M01-012) ----

CREATE TABLE IF NOT EXISTS retrieval_spans (
    span_id                              TEXT    PRIMARY KEY NOT NULL
        REFERENCES spans(span_id) ON DELETE CASCADE,
    retriever_name                       TEXT    NOT NULL,
    query_digest                         TEXT,
    query_redaction_policy_version       TEXT    NOT NULL,
    document_count                       INTEGER,
    duplicate_document_count             INTEGER,
    empty_retrieval                      INTEGER NOT NULL DEFAULT 0,
    relevance_proxy_score                REAL,
    citation_coverage                    REAL,
    context_token_count                  INTEGER,
    context_waste_tokens                 INTEGER,
    latency_ms                           INTEGER,
    CONSTRAINT retrieval_spans_empty_retrieval_bool
        CHECK (empty_retrieval IN (0,1))
);

-- ---- embedding_spans (VAL-V2M01-013) ----

CREATE TABLE IF NOT EXISTS embedding_spans (
    span_id                              TEXT    PRIMARY KEY NOT NULL
        REFERENCES spans(span_id) ON DELETE CASCADE,
    provider                             TEXT    NOT NULL,
    model                                TEXT    NOT NULL,
    input_token_count                    INTEGER,
    embedding_dim                        INTEGER,
    cached                               INTEGER NOT NULL DEFAULT 0,
    cost_usd                             REAL,
    latency_ms                           INTEGER,
    CONSTRAINT embedding_spans_cached_bool
        CHECK (cached IN (0,1))
);
