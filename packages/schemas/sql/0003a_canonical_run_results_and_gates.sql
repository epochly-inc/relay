-- 0003a_canonical_run_results_and_gates.sql
--
-- Audit-R3 (2026-05-18): canonical Postgres DDL for the four foundational
-- envelopes that the spec marks canonical at A.1 (run_results), A.2
-- (gate_decisions), A.3 (gate_decision_drafts), and A.4 (gate_rounds). Per
-- the audit, NO Postgres DDL existed for these tables in packages/schemas/
-- sql/ -- only the SQLite sidecar mirror at apps/local-sidecar/migrations/
-- (0002_run_results.sql, 0003_gate_decisions.sql, 0004_gate_decision_
-- drafts.sql, plus the gate_rounds shape implicit in 0011_gate_circuit_
-- breaker.sql). The hosted control plane could not be deployed without
-- these tables; this migration closes the gap.
--
-- Column shapes are derived from envelopes.yaml + the sidecar SQL mirror
-- (which has been the working reference for months). Differences from the
-- sidecar:
--   * TEXT -> uuid (Postgres native uuid type)
--   * TEXT (ISO-8601) -> timestamptz
--   * TEXT (JSON) -> jsonb
--   * INTEGER (0/1) -> boolean
--   * FK constraints to runs/projects/gates/evidence_bundles INLINE per
--     the canonical Postgres shape (the sidecar relaxes those FKs).
--
-- Per CLAUDE.md keystone invariant #1 (control plane writes the result):
--   - run_results.written_by CHECK forces literal 'control_plane'.
--   - gate_decisions.decided_by CHECK forces literal 'gate_engine'.
-- The hosted control plane's role grants additionally restrict INSERT/
-- UPDATE on these tables to the `relay_control_plane` and `relay_gate_
-- engine` roles. Those grants land in private relay-platform migrations.
--
-- Per CLAUDE.md keystone invariant #2 (pass without evidence is not a pass):
--   - run_results.accepted_requires_evidence CHECK forces status='accepted'
--     => evidence_bundle_id IS NOT NULL.
--
-- Per CLAUDE.md keystone invariant #10 (schema versioning):
--   - Every table carries schema_version pinned to its canonical Literal
--     value via a SQL CHECK constraint.
--
-- ASCII-only per CLAUDE.md "ASCII-Safe Source".

-- -----------------------------------------------------------------------------
-- run_results (spec A.1; VAL-W2-025, VAL-W2-026)
-- -----------------------------------------------------------------------------
--
-- Canonical run outcome. Written exclusively by the control plane. A
-- successful run requires a bound evidence_bundle_id.

CREATE TABLE IF NOT EXISTS run_results (
    run_result_id          uuid PRIMARY KEY,
    run_id                 uuid NOT NULL UNIQUE REFERENCES runs(run_id),
    project_id             uuid NOT NULL REFERENCES projects(project_id),
    schema_version         text NOT NULL DEFAULT 'relay.run_result.v1'
        CHECK (schema_version = 'relay.run_result.v1'),
    written_by             text NOT NULL DEFAULT 'control_plane'
        CHECK (written_by = 'control_plane'),
    status                 text NOT NULL
        CHECK (status IN ('accepted', 'remediate_required', 'blocked', 'invalid')),
    primary_failure_class  text,
    error_priority_rule    text NOT NULL
        DEFAULT 'first_p0_then_highest_severity_then_earliest_span',
    evidence_bundle_id     uuid REFERENCES evidence_bundles(evidence_bundle_id),
    manifest_commit_hash   text NOT NULL
        CHECK (manifest_commit_hash ~ '^sha256-[0-9a-f]{64}$'),
    actor_identity_hash    text NOT NULL
        CHECK (actor_identity_hash ~ '^sha256-[0-9a-f]{64}$'),
    decided_at             timestamptz NOT NULL DEFAULT now(),
    decision_epoch         bigint NOT NULL DEFAULT 0
        CHECK (decision_epoch >= 0),
    signature              text NOT NULL,
    signature_key_id       text NOT NULL,
    CONSTRAINT accepted_requires_evidence
        CHECK (status <> 'accepted' OR evidence_bundle_id IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS run_results_project_decided
    ON run_results(project_id, decided_at DESC);

-- -----------------------------------------------------------------------------
-- gate_decisions (spec A.2)
-- -----------------------------------------------------------------------------
--
-- Canonical gate decision. Written exclusively by the gate engine. Bound
-- to an evidence_bundle_id and to the three-anchor handoff
-- (manifest_commit_hash, actor_identity_hash, scope_id).

CREATE TABLE IF NOT EXISTS gate_decisions (
    gate_decision_id        uuid PRIMARY KEY,
    schema_version          text NOT NULL DEFAULT 'relay.gate_decision.v1'
        CHECK (schema_version = 'relay.gate_decision.v1'),
    gate_id                 uuid NOT NULL REFERENCES gates(gate_id),
    scope_type              text NOT NULL
        CHECK (scope_type IN ('run','replay','eval_run','release','domain_pack')),
    scope_id                uuid NOT NULL,
    round                   int NOT NULL
        CHECK (round >= 1),
    action                  text NOT NULL
        CHECK (action IN ('accept','remediate','block','invalid')),
    strict_pass             boolean NOT NULL DEFAULT false,
    failed_assertion_ids    jsonb NOT NULL DEFAULT '[]'::jsonb,
    unmet_conditions        jsonb NOT NULL DEFAULT '[]'::jsonb,
    evidence_bundle_id      uuid NOT NULL REFERENCES evidence_bundles(evidence_bundle_id),
    cascade_on_block        boolean NOT NULL DEFAULT true,
    decided_by              text NOT NULL DEFAULT 'gate_engine'
        CHECK (decided_by = 'gate_engine'),
    decided_at              timestamptz NOT NULL DEFAULT now(),
    manifest_commit_hash    text NOT NULL
        CHECK (manifest_commit_hash ~ '^sha256-[0-9a-f]{64}$'),
    actor_identity_hash     text NOT NULL
        CHECK (actor_identity_hash ~ '^sha256-[0-9a-f]{64}$'),
    signature               text NOT NULL,
    signature_key_id        text NOT NULL,
    decision_epoch          bigint DEFAULT 0
        CHECK (decision_epoch IS NULL OR decision_epoch >= 0),
    UNIQUE(gate_id, scope_type, scope_id, round)
);

CREATE INDEX IF NOT EXISTS gate_decisions_scope
    ON gate_decisions(scope_type, scope_id, round);

-- -----------------------------------------------------------------------------
-- gate_decision_drafts (spec A.3)
-- -----------------------------------------------------------------------------
--
-- Submitter-facing draft. NOT authoritative. Resolved into a gate_decision
-- exactly once by the state engine. A dry_run_unsigned draft moves through
-- pending -> {expired, cancelled, rejected_handoff, duplicate_submission}
-- but can NEVER resolve to a gate_decision.

CREATE TABLE IF NOT EXISTS gate_decision_drafts (
    draft_id                     uuid PRIMARY KEY,
    schema_version               text NOT NULL DEFAULT 'relay.gate_decision_draft.v1'
        CHECK (schema_version = 'relay.gate_decision_draft.v1'),
    gate_id                      uuid NOT NULL REFERENCES gates(gate_id),
    scope_type                   text NOT NULL,
    scope_id                     uuid NOT NULL,
    round                        int NOT NULL CHECK (round >= 1),
    release_sha                  text,
    eval_run_ids                 jsonb NOT NULL DEFAULT '[]'::jsonb,
    evidence_refs                jsonb NOT NULL DEFAULT '[]'::jsonb,
    worker_id                    uuid NOT NULL,
    manifest_commit_hash         text NOT NULL
        CHECK (manifest_commit_hash ~ '^sha256-[0-9a-f]{64}$'),
    actor_identity_hash          text NOT NULL
        CHECK (actor_identity_hash ~ '^sha256-[0-9a-f]{64}$'),
    submitted_at                 timestamptz NOT NULL DEFAULT now(),
    resolved_gate_decision_id    uuid REFERENCES gate_decisions(gate_decision_id),
    draft_kind                   text NOT NULL DEFAULT 'submitted'
        CHECK (draft_kind IN ('submitted','dry_run_unsigned')),
    resolution_state             text NOT NULL DEFAULT 'pending'
        CHECK (resolution_state IN (
            'pending','resolved','rejected_handoff','expired','cancelled',
            'duplicate_submission'
        )),
    cancelled_at                 timestamptz,
    cancellation_reason          text,
    CONSTRAINT dry_run_never_resolves CHECK (
        draft_kind = 'submitted'
        OR resolution_state IN ('pending','expired','cancelled','rejected_handoff','duplicate_submission')
    ),
    CONSTRAINT dry_run_no_decision CHECK (
        draft_kind = 'submitted' OR resolved_gate_decision_id IS NULL
    ),
    UNIQUE(gate_id, scope_type, scope_id, round, worker_id)
);

-- gate_decision_drafts.actor_identity_hash FK to actors.identity_hash
-- (declared as the canonical FK contract by 0001_actors.sql). Run inline
-- now that gate_decision_drafts exists.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_name = 'actors'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'gate_decision_drafts_actor_fk'
    ) THEN
        ALTER TABLE gate_decision_drafts
            ADD CONSTRAINT gate_decision_drafts_actor_fk
            FOREIGN KEY (actor_identity_hash) REFERENCES actors(identity_hash);
    END IF;
END$$;

CREATE INDEX IF NOT EXISTS gate_decision_drafts_state
    ON gate_decision_drafts(gate_id, resolution_state, submitted_at DESC);

-- -----------------------------------------------------------------------------
-- gate_rounds (spec A.4)
-- -----------------------------------------------------------------------------
--
-- Per-round audit trail. restart_predecessor is NULL on the first round
-- and references the predecessor gate_round_id on every restart round
-- (gate restart on failure rule).

CREATE TABLE IF NOT EXISTS gate_rounds (
    gate_round_id           uuid PRIMARY KEY,
    schema_version          text NOT NULL DEFAULT 'relay.gate_round.v1'
        CHECK (schema_version = 'relay.gate_round.v1'),
    gate_id                 uuid NOT NULL REFERENCES gates(gate_id),
    scope_type              text NOT NULL,
    scope_id                uuid NOT NULL,
    round                   int NOT NULL CHECK (round >= 1),
    initiated_at            timestamptz NOT NULL DEFAULT now(),
    -- envelopes.yaml GateRound.initiated_by declares
    -- {control_plane, cron, user, remediation}; the sidecar 0009 mirror
    -- declares {submission, remediation, admin_override}. Audit-R3
    -- widens the SQL enum to the union of both -- the wire-format layer
    -- can narrow per-scope as needed; the SQL CHECK is the floor of
    -- "documented values" not the ceiling.
    initiated_by            text NOT NULL
        CHECK (initiated_by IN (
            'control_plane','cron','user','remediation',
            'submission','admin_override'
        )),
    initiation_reason       text,
    gate_decision_id        uuid REFERENCES gate_decisions(gate_decision_id),
    restart_predecessor     uuid REFERENCES gate_rounds(gate_round_id),
    UNIQUE(gate_id, scope_type, scope_id, round)
);

CREATE INDEX IF NOT EXISTS gate_rounds_scope
    ON gate_rounds(scope_type, scope_id, round);
