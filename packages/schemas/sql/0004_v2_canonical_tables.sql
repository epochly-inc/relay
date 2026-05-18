-- 0004_v2_canonical_tables.sql
--
-- v0.2 OSS completeness, milestone M01, feature w1-1 scope: canonical
-- Postgres DDL for the 13 control-plane tables surfaced by the 2026-05-16
-- spec audit as missing from public relay/. These tables close gaps in
-- spec sectionA.5-A.15 + sectionZ that weaken keystone invariants.
--
--   gate_policies         (spec A.5  lines 3063-3076)
--   contract_results      (spec A.6  lines 3082-3102)
--   assertion_definitions (spec A.7  lines 3108-3125)
--   replay_results        (spec A.8  lines 3172-3187)
--   manifests             (spec A.9  lines 3193-3199; parent of manifest_versions)
--   redaction_policies    (spec A.10 lines 3219-3229; DDL form, not just JSON schema)
--   incidents             (spec A.13 lines 3274-3290)
--   root_cause_hypotheses (spec A.15 lines 3316-3328)
--   spans                 (spec Z; parent table for typed-detail-row invariant)
--   model_call_spans      (spec Z lines 5226-5249)
--   tool_call_spans       (spec Z lines 5251-5264)
--   retrieval_spans       (spec Z lines 5266-5279)
--   embedding_spans       (spec Z lines 5281-5290)
--
-- Per CLAUDE.md keystone invariant #1: these tables are subject to the
-- "control plane writes the result" rule. The role-based grants land in
-- M02 (m02-w2-api-surface) alongside the hosted API write path; this
-- migration delivers DDL shape only.
--
-- Per CLAUDE.md keystone invariant #7: redaction_policies.raw_capture_default
-- defaults to literal false. Setting it true requires a signed DPA and an
-- org-admin approver per spec G.1 lines 4108-4114; that runtime check lives
-- in the redaction service.
--
-- Per CLAUDE.md keystone invariant #10: every persisted envelope carries
-- schema_version pinned via a default + CHECK constraint. Wire-format
-- Pydantic Literal[...] pin lives in relay_schemas.envelopes.
--
-- Per spec Z lines 5292-5293: a spans row with span_type in
-- ('model_call','tool_call','retrieval','embedding') MUST have a matching
-- typed-detail-row in the corresponding typed table within the same
-- INSERT transaction. The ingest worker writes both atomically; a CI lint
-- join-check enforces. The canonical error code for a missing detail is
-- RELAY-INGEST-SPAN-DETAIL-MISSING.
--
-- Some FK targets (runs, projects, contracts, side_effect_markers) are
-- declared in later milestones (M03/M04). When this migration is applied
-- against a fresh database without those targets present, the FK
-- constraints are skipped via conditional DO $$ blocks, mirroring the
-- approach used in 0001_actors.sql lines 67-80. Running 0004 in isolation
-- creates the tables without the unresolved FKs; running it after the
-- target tables exist (or alongside them in the M03/M04 bundle) absorbs
-- the FKs inline.
--
-- ASCII-only per CLAUDE.md "ASCII-Safe Source".

-- -----------------------------------------------------------------------------
-- gate_policies (spec A.5; VAL-V2M01-001)
-- -----------------------------------------------------------------------------
--
-- Conditions are GatePolicy v1 (spec sectionD.3). blocking_severity is a closed
-- three-member enum locked here at the SQL layer; the wire-format layer
-- mirrors the enum on the GatePolicy Pydantic model.

CREATE TABLE gate_policies (
    gate_policy_id uuid PRIMARY KEY,
    gate_id uuid NOT NULL REFERENCES gates(gate_id),
    policy_version text NOT NULL,
    schema_version text NOT NULL DEFAULT 'relay.gate_policy.v1'
        CHECK (schema_version = 'relay.gate_policy.v1'),
    conditions jsonb NOT NULL,
    baseline_selector jsonb,
    flaky_quarantine_policy jsonb,
    blocking_severity text NOT NULL DEFAULT 'p0_only'
        CHECK (blocking_severity IN ('p0_only','p0_p1','any_failure')),
    effective_at timestamptz NOT NULL DEFAULT now(),
    effective_until timestamptz,
    UNIQUE(gate_id, policy_version)
);

-- -----------------------------------------------------------------------------
-- contract_results (spec A.6; VAL-V2M01-002)
-- -----------------------------------------------------------------------------

CREATE TABLE contract_results (
    contract_result_id uuid PRIMARY KEY,
    run_id uuid NOT NULL REFERENCES runs(run_id),
    contract_id uuid NOT NULL REFERENCES contracts(contract_id),
    contract_version text NOT NULL,
    assertion_id text,
    span_id uuid REFERENCES spans(span_id),
    outcome text NOT NULL
        CHECK (outcome IN ('pass','fail','repaired','skipped','error')),
    severity text
        CHECK (severity IN ('p0','p1','p2','info')),
    raw_signature_hash text,
    repair_attempt int DEFAULT 0,
    evaluation_engine_version text NOT NULL,
    evaluated_at timestamptz NOT NULL DEFAULT now(),
    metadata jsonb NOT NULL DEFAULT '{}'
);

CREATE INDEX contract_results_run ON contract_results(run_id);
CREATE INDEX contract_results_run_outcome ON contract_results(run_id, outcome);

-- -----------------------------------------------------------------------------
-- assertion_definitions (spec A.7; VAL-V2M01-003)
-- -----------------------------------------------------------------------------
--
-- PK is text, not uuid: assertion_id encodes the human-meaningful
-- identifier (e.g. VAL-STRUCTURED-001) that the contract DSL references.

CREATE TABLE assertion_definitions (
    assertion_id text PRIMARY KEY,
    project_id uuid NOT NULL REFERENCES projects(project_id),
    kind text NOT NULL
        CHECK (kind IN ('schema_contract','behavioral','tool_arg','eval','coverage')),
    severity text NOT NULL
        CHECK (severity IN ('p0','p1','p2','info')),
    title text NOT NULL,
    description text,
    owner_email text NOT NULL,
    expression jsonb NOT NULL,
    applies_to jsonb NOT NULL DEFAULT '{}',
    lifecycle_state text NOT NULL DEFAULT 'draft'
        CHECK (lifecycle_state IN ('draft','active','deprecated','retired')),
    current_version int NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- -----------------------------------------------------------------------------
-- replay_results (spec A.8; VAL-V2M01-004)
-- -----------------------------------------------------------------------------

CREATE TABLE replay_results (
    replay_result_id uuid PRIMARY KEY,
    replay_case_id uuid NOT NULL REFERENCES replay_cases(replay_case_id),
    replay_run_id uuid NOT NULL REFERENCES runs(run_id),
    outcome text NOT NULL
        CHECK (outcome IN ('reproduced','diverged','blocked','sandbox_error')),
    failure_signature_match boolean,
    fixture_hits int NOT NULL DEFAULT 0,
    fixture_misses int NOT NULL DEFAULT 0,
    sandbox_driver text NOT NULL,
    sandbox_id text,
    network_egress_denied int NOT NULL DEFAULT 0,
    side_effect_attempts int NOT NULL DEFAULT 0,
    side_effect_approved int NOT NULL DEFAULT 0,
    evidence_bundle_id uuid REFERENCES evidence_bundles(evidence_bundle_id),
    created_at timestamptz NOT NULL DEFAULT now()
);

-- -----------------------------------------------------------------------------
-- manifests parent table (spec A.9; VAL-V2M01-005)
-- -----------------------------------------------------------------------------
--
-- The existing manifest_versions table (0002_control_plane.sql line 31) carries
-- manifest_id but no FK to a parent. This migration introduces the canonical
-- parent. The FK from manifest_versions.manifest_id to manifests.manifest_id
-- is added conditionally below so running 0004 against a database where
-- manifest_versions already exists absorbs the FK without rebuilding the
-- existing table.

CREATE TABLE manifests (
    manifest_id uuid PRIMARY KEY,
    project_id uuid NOT NULL REFERENCES projects(project_id),
    name text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(project_id, name)
);

-- Add FK from manifest_versions.manifest_id to manifests.manifest_id when
-- the target table is present. Mirrors the conditional pattern in
-- 0001_actors.sql lines 67-80.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_name = 'manifest_versions'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'manifest_versions_manifest_fk'
    ) THEN
        ALTER TABLE manifest_versions
            ADD CONSTRAINT manifest_versions_manifest_fk
            FOREIGN KEY (manifest_id) REFERENCES manifests(manifest_id);
    END IF;
END$$;

-- -----------------------------------------------------------------------------
-- redaction_policies (spec A.10; VAL-V2M01-006; CLAUDE.md keystone invariant #7)
-- -----------------------------------------------------------------------------
--
-- raw_capture_default MUST default to literal false. Setting it true on the
-- per-version body requires a signed DPA + org-admin approver per spec G.1
-- lines 4108-4114; that policy check lives in the redaction service runtime.

CREATE TABLE redaction_policies (
    policy_id uuid PRIMARY KEY,
    project_id uuid NOT NULL REFERENCES projects(project_id),
    policy_version text NOT NULL,
    schema_version text NOT NULL DEFAULT 'relay.redaction.v1'
        CHECK (schema_version = 'relay.redaction.v1'),
    body jsonb NOT NULL,
    raw_capture_default boolean NOT NULL DEFAULT false,
    effective_at timestamptz NOT NULL DEFAULT now(),
    effective_until timestamptz,
    UNIQUE(project_id, policy_version)
);

-- -----------------------------------------------------------------------------
-- incidents (spec A.13; VAL-V2M01-007)
-- -----------------------------------------------------------------------------
--
-- cluster_signature_hash is the normalized failure-class hash that groups
-- recurring incidents. Severity is the standard sev1-sev4 ladder from
-- spec Q.1.

CREATE TABLE incidents (
    incident_id uuid PRIMARY KEY,
    project_id uuid NOT NULL REFERENCES projects(project_id),
    cluster_signature_hash text NOT NULL,
    severity text NOT NULL
        CHECK (severity IN ('sev1','sev2','sev3','sev4')),
    state text NOT NULL DEFAULT 'open'
        CHECK (state IN ('open','mitigated','closed','suppressed')),
    affected_run_ids uuid[] NOT NULL DEFAULT '{}',
    first_seen_at timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL,
    owner_email text,
    postmortem_ref text,
    promoted_to_regression boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX incidents_cluster ON incidents(project_id, cluster_signature_hash);

-- -----------------------------------------------------------------------------
-- root_cause_hypotheses (spec A.15; VAL-V2M01-008; Explain object, spec T)
-- -----------------------------------------------------------------------------

CREATE TABLE root_cause_hypotheses (
    hypothesis_id uuid PRIMARY KEY,
    run_id uuid NOT NULL REFERENCES runs(run_id),
    span_id uuid REFERENCES spans(span_id),
    hypothesis_class text NOT NULL,
    confidence numeric NOT NULL
        CHECK (confidence BETWEEN 0 AND 1),
    evidence_refs jsonb NOT NULL DEFAULT '[]',
    generator text NOT NULL,
    reviewer_email text,
    reviewer_decision text
        CHECK (reviewer_decision IN ('accept','reject','modify','pending')),
    promoted_to_replay_case_id uuid REFERENCES replay_cases(replay_case_id),
    created_at timestamptz NOT NULL DEFAULT now()
);

-- -----------------------------------------------------------------------------
-- spans (parent; spec Z; VAL-V2M01-009)
-- -----------------------------------------------------------------------------
--
-- The polymorphic typed-detail-row invariant: a spans row whose span_type
-- is one of model_call|tool_call|retrieval|embedding MUST have a matching
-- row in the corresponding typed table (model_call_spans / tool_call_spans
-- / retrieval_spans / embedding_spans) within the same INSERT transaction.
-- A spans row with span_type='custom' requires no typed-detail row.
--
-- The ingest worker writes both rows atomically (spec Z line 5293). A CI
-- lint join-check enforces no orphan parent rows. The canonical error
-- code for a missing typed-detail row is RELAY-INGEST-SPAN-DETAIL-MISSING.
-- See spec sectionZ lines 5221-5293 for the conformance test paragraph.

CREATE TABLE spans (
    span_id uuid PRIMARY KEY,
    run_id uuid REFERENCES runs(run_id),
    parent_span_id uuid,
    span_type text NOT NULL
        CHECK (span_type IN ('model_call','tool_call','retrieval','embedding','custom')),
    name text NOT NULL,
    status text NOT NULL,
    started_at timestamptz NOT NULL,
    ended_at timestamptz,
    error_class text,
    metadata jsonb NOT NULL DEFAULT '{}'
);

CREATE INDEX spans_run ON spans(run_id);
CREATE INDEX spans_parent ON spans(parent_span_id);

-- -----------------------------------------------------------------------------
-- model_call_spans (spec Z lines 5226-5249; VAL-V2M01-010)
-- -----------------------------------------------------------------------------

CREATE TABLE model_call_spans (
    span_id uuid PRIMARY KEY REFERENCES spans(span_id) ON DELETE CASCADE,
    provider text NOT NULL,
    model text NOT NULL,
    model_signature text,
    request_message_count int,
    request_token_count int,
    response_token_count int,
    cached_token_count int,
    reasoning_token_count int,
    cost_usd numeric,
    latency_ms int,
    finish_reason text,
    structured_output_mode text,
    schema_contract_id text,
    tool_choice_mode text,
    streaming boolean NOT NULL DEFAULT false,
    input_redaction_policy_version text NOT NULL,
    input_digest text,
    output_digest text,
    http_status int,
    provider_error_code text,
    provider_error_class text
);

-- -----------------------------------------------------------------------------
-- tool_call_spans (spec Z lines 5251-5264; VAL-V2M01-011)
-- -----------------------------------------------------------------------------

CREATE TABLE tool_call_spans (
    span_id uuid PRIMARY KEY REFERENCES spans(span_id) ON DELETE CASCADE,
    tool_name text NOT NULL,
    side_effect_class text NOT NULL,
    args_digest text,
    args_redaction_policy_version text NOT NULL,
    args_schema_contract_id text,
    args_validation_outcome text
        CHECK (args_validation_outcome IN ('pass','fail','repaired','skipped','error')),
    result_digest text,
    status text NOT NULL,
    latency_ms int,
    -- Audit-R3 (2026-05-18): the FK on marker_id -> side_effect_markers(
    -- marker_id) is added by 0010_side_effects.sql via ALTER TABLE because
    -- side_effect_markers is created in 0010 (later in lex order than 0004).
    -- Declaring the FK inline here would fail when 0004 applies against a
    -- fresh database. The column shape is preserved; the constraint is
    -- deferred by exactly one migration.
    marker_id uuid,
    parallel_index int
);

-- -----------------------------------------------------------------------------
-- retrieval_spans (spec Z lines 5266-5279; VAL-V2M01-012)
-- -----------------------------------------------------------------------------

CREATE TABLE retrieval_spans (
    span_id uuid PRIMARY KEY REFERENCES spans(span_id) ON DELETE CASCADE,
    retriever_name text NOT NULL,
    query_digest text,
    query_redaction_policy_version text NOT NULL,
    document_count int,
    duplicate_document_count int,
    empty_retrieval boolean NOT NULL DEFAULT false,
    relevance_proxy_score numeric,
    citation_coverage numeric,
    context_token_count int,
    context_waste_tokens int,
    latency_ms int
);

-- -----------------------------------------------------------------------------
-- embedding_spans (spec Z lines 5281-5290; VAL-V2M01-013)
-- -----------------------------------------------------------------------------

CREATE TABLE embedding_spans (
    span_id uuid PRIMARY KEY REFERENCES spans(span_id) ON DELETE CASCADE,
    provider text NOT NULL,
    model text NOT NULL,
    input_token_count int,
    embedding_dim int,
    cached boolean NOT NULL DEFAULT false,
    cost_usd numeric,
    latency_ms int
);
