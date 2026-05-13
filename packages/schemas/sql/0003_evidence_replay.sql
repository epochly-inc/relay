-- 0003_evidence_replay.sql
--
-- W1.3 scope: evidence + replay envelope tables.
--
--   evidence_bundles    (spec J line 2792-2810)
--   evidence_claims     (spec A.16 lines 3331-3353)
--   replay_cases        (spec A.8 lines 3131-3145)
--   replay_fixtures     (spec A.8 lines 3147-3168, E.2-E.3)
--
-- This migration is hand-authored to match the canonical YAML at
-- packages/schemas/raw/envelopes.yaml. The W1.5 codegen pipeline will
-- replace the hand-authoring with generator output; the W1.5 drift check
-- (VAL-W1-035) will enforce sync.
--
-- The role-based grants that enforce CLAUDE.md keystone invariant #1
-- (the control plane writes the result) for run_results / gate_decisions
-- land in W2 (m02-w2-sidecar-core). This file delivers the DDL shape
-- only; role grants are W2's responsibility.
--
-- Per CLAUDE.md keystone invariant #10, every canonical envelope row
-- carries schema_version pinned via a SQL CHECK constraint. Per
-- VAL-W1-052 through VAL-W1-055, those pins are enforced at the SQL
-- layer in addition to the wire-format layer.
--
-- VAL-W1-019 enum-lock-in: spec J does not enumerate verification_status
-- values; the eng-plan-locked candidate set
-- {unverified, verified, tampered, revoked} is locked here AND in the
-- canonical YAML.
--
-- ASCII-only per CLAUDE.md "ASCII-Safe Source".

-- -----------------------------------------------------------------------------
-- evidence_bundles (spec J line 2792-2810; VAL-W1-018, VAL-W1-019, VAL-W1-052)
-- -----------------------------------------------------------------------------

CREATE TABLE evidence_bundles (
    evidence_bundle_id uuid PRIMARY KEY,
    schema_version text NOT NULL DEFAULT 'relay.evidence_bundle.v1'
        CHECK (schema_version = 'relay.evidence_bundle.v1'),
    org_id uuid NOT NULL,
    project_id uuid NOT NULL,
    scope_type text NOT NULL,
    scope_id uuid NOT NULL,
    -- VAL-W1-018: canonical sha256-<hex> wire form, non-nullable.
    bundle_digest text NOT NULL
        CHECK (bundle_digest ~ '^sha256-[0-9a-f]{64}$'),
    acef_core_version text NOT NULL,
    relay_extension_version text NOT NULL,
    signing_key_id text NULL,
    signature_algorithm text NULL,
    -- VAL-W1-019: closed four-member enum (eng-plan-locked candidate set).
    verification_status text NOT NULL
        CHECK (verification_status IN (
            'unverified', 'verified', 'tampered', 'revoked'
        )),
    redaction_policy_version text NOT NULL,
    manifest_commit_hash text NULL
        CHECK (
            manifest_commit_hash IS NULL
            OR manifest_commit_hash ~ '^sha256-[0-9a-f]{64}$'
        ),
    object_ref text NOT NULL,
    supersedes_bundle_id uuid NULL
        REFERENCES evidence_bundles(evidence_bundle_id),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (project_id, scope_type, scope_id, bundle_digest)
);

CREATE INDEX evidence_bundles_project_scope
    ON evidence_bundles(project_id, scope_type, scope_id, created_at DESC);

-- -----------------------------------------------------------------------------
-- evidence_claims (spec A.16 lines 3331-3353; VAL-W1-020, VAL-W1-021, V053)
-- -----------------------------------------------------------------------------

CREATE TABLE evidence_claims (
    evidence_claim_id uuid PRIMARY KEY,
    schema_version text NOT NULL DEFAULT 'relay.evidence_claim.v1'
        CHECK (schema_version = 'relay.evidence_claim.v1'),
    evidence_bundle_id uuid NOT NULL
        REFERENCES evidence_bundles(evidence_bundle_id),
    -- VAL-W1-020: closed eight-member enum.
    claim_type text NOT NULL
        CHECK (claim_type IN (
            'run_result', 'gate_decision', 'contract_result',
            'replay_result', 'human_oversight', 'incident',
            'data_quality_check', 'provider_compatibility'
        )),
    subject_kind text NOT NULL,
    subject_id uuid NOT NULL,
    -- VAL-W1-021: canonical sha256-<hex> wire form.
    claim_digest text NOT NULL
        CHECK (claim_digest ~ '^sha256-[0-9a-f]{64}$'),
    redaction_transform_version text NOT NULL,
    manifest_commit_hash text NOT NULL
        CHECK (manifest_commit_hash ~ '^sha256-[0-9a-f]{64}$'),
    signer_key_id text NOT NULL,
    -- VAL-W1-021: signature is required and non-empty.
    signature text NOT NULL
        CHECK (length(signature) > 0),
    supersedes_claim_id uuid NULL
        REFERENCES evidence_claims(evidence_claim_id),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX evidence_claims_bundle ON evidence_claims(evidence_bundle_id);
CREATE INDEX evidence_claims_subject ON evidence_claims(subject_kind, subject_id);

-- -----------------------------------------------------------------------------
-- replay_cases (spec A.8 lines 3131-3145; VAL-W1-022, VAL-W1-054)
-- -----------------------------------------------------------------------------

CREATE TABLE replay_cases (
    replay_case_id uuid PRIMARY KEY,
    schema_version text NOT NULL DEFAULT 'relay.replay_case.v1'
        CHECK (schema_version = 'relay.replay_case.v1'),
    project_id uuid NOT NULL,
    source_run_id uuid NULL,
    -- VAL-W1-022: failure_signature_hash required, non-empty.
    failure_signature_hash text NOT NULL
        CHECK (length(failure_signature_hash) > 0),
    inputs_ref text NOT NULL,
    inputs_digest text NOT NULL
        CHECK (inputs_digest ~ '^sha256-[0-9a-f]{64}$'),
    expected_assertion_ids text[] NOT NULL DEFAULT '{}',
    human_reviewed boolean NOT NULL DEFAULT false,
    reviewer_email text NULL,
    reviewed_at timestamptz NULL,
    -- VAL-W1-022: closed three-member enum, default 'proposed'.
    status text NOT NULL DEFAULT 'proposed'
        CHECK (status IN ('proposed', 'approved', 'retired')),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX replay_cases_project_status
    ON replay_cases(project_id, status, created_at DESC);

-- -----------------------------------------------------------------------------
-- replay_fixtures (spec A.8 lines 3147-3168, E.2-E.3;
--                  VAL-W1-023, VAL-W1-024, VAL-W1-025, VAL-W1-055)
-- -----------------------------------------------------------------------------

CREATE TABLE replay_fixtures (
    fixture_id uuid PRIMARY KEY,
    schema_version text NOT NULL DEFAULT 'relay.replay_fixture.v1'
        CHECK (schema_version = 'relay.replay_fixture.v1'),
    replay_case_id uuid NOT NULL
        REFERENCES replay_cases(replay_case_id),
    source_span_id uuid NOT NULL,
    -- VAL-W1-023: closed five-member enum.
    kind text NOT NULL
        CHECK (kind IN (
            'model_call', 'tool_call', 'retrieval', 'embedding', 'custom'
        )),
    -- VAL-W1-023: closed four-member enum.
    mode text NOT NULL
        CHECK (mode IN ('cassette', 'live', 'degraded_live', 'mock')),
    redaction_policy_version text NOT NULL,
    input_digest text NOT NULL
        CHECK (input_digest ~ '^sha256-[0-9a-f]{64}$'),
    output_ref text NULL,
    output_digest text NULL
        CHECK (
            output_digest IS NULL
            OR output_digest ~ '^sha256-[0-9a-f]{64}$'
        ),
    provider text NULL,
    model text NULL,
    model_signature text NULL,
    -- VAL-W1-024: capture_clock RFC 3339 timezone-aware. timestamptz in
    -- PostgreSQL is always offset-aware on input; the wire-format layer
    -- enforces the offset requirement.
    capture_clock timestamptz NOT NULL,
    -- VAL-W1-025: closed four-member enum, default invalidate_on_signature_change.
    refresh_policy text NOT NULL DEFAULT 'invalidate_on_signature_change'
        CHECK (refresh_policy IN (
            'invalidate_on_signature_change',
            'hold_forever',
            'refresh_weekly',
            'invalidate_on_model_version_change'
        )),
    -- VAL-W1-023: closed four-member enum.
    side_effect_class text NOT NULL
        CHECK (side_effect_class IN (
            'read_only', 'mutating', 'external_irreversible', 'approval_required'
        )),
    allowed_in_replay boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX replay_fixtures_case ON replay_fixtures(replay_case_id);
