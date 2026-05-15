-- W8.4 migration 0011: gate remediation circuit breaker + admin transitions.
--
-- Adds the bookkeeping surface for VAL-W8-030..VAL-W8-038:
--
--   1. ``gates`` table (spec A.5 lines 3050-3061). Holds per-gate
--      configuration that the circuit breaker reads at decision time:
--        - remediation_round_cap  default 5, range [1, 50]  (VAL-W8-030,
--                                  VAL-W8-031).
--        - cascade_on_block       default true (1); when false, a block
--                                  decision goes terminal without opening
--                                  a new remediation round (VAL-W8-038).
--
--      The OSS local profile keeps gates open-access; the hosted Postgres
--      migration in services/gate-engine/migrations/ will enforce role
--      grants matched to ``relay_gate_engine``. Schema follows §A.5 with
--      the SQLite type accommodations (TEXT for uuid/timestamptz, INTEGER
--      for boolean).
--
--   2. ``gate_stalled_state`` table. Records that a (scope_type, scope_id)
--      has transitioned to the ``gate.stalled`` state per §AD lines
--      5471-5488. The W2 ``scope_state`` table is the canonical scope-
--      state holder, but the W2 state engine is the ONLY writer permitted
--      to mutate ``scope_state`` (CLAUDE.md keystone #1 / VAL-W2-024).
--      Per contract gap #3 (VAL-W8-032 "scope_state.state='gate.stalled'
--      or equivalent stalled marker"), we materialize the equivalent
--      stalled marker in this companion table that packages/gate/ owns.
--      Co-committed with the cap-exceeded event in one BEGIN IMMEDIATE..
--      COMMIT block per VAL-W8-018 atomicity.
--
--      Columns:
--        - scope_type / scope_id    composite key into the affected scope.
--        - gate_id                  the failing gate that consumed the
--                                    last remediation round.
--        - terminal_round           the round whose attempted submission
--                                    triggered the cap-exceeded transition
--                                    (= remediation_round_cap; the new
--                                    round (cap+1) is NEVER opened per
--                                    VAL-W8-032).
--        - reason                   one of:
--                                     'cap_exceeded' -- circuit breaker
--                                     'admin_paused' -- (future use)
--                                     'admin_terminated' -- after
--                                       admin.terminate seals the final
--                                       block (VAL-W8-037).
--        - opened_at                RFC 3339 UTC timestamp.
--        - reopened_at              non-null after admin.reopen (records
--                                    the most recent reopen for audit).
--        - terminated_at            non-null after admin.terminate.
--
--      Idempotent on (scope_type, scope_id): a second trip-to-stalled
--      call is a no-op (the gate_stalled_state row already exists and is
--      not overwritten). The admin-reopen path clears the stalled marker
--      by UPDATE (sets reopened_at + nulls the active flag).
--
--   3. ``audit_log_entries`` table. Append-only audit trail for admin
--      actions (admin.reopen, admin.terminate) per §AD lines 5479-5480.
--      VAL-W8-036 requires the reopen audit row to carry the reason,
--      actor identity, prior round id, and new round id. VAL-W8-037
--      audit row records the terminate evidence claim binding.
--
--      Distinct from ``event_log_entries`` (which is the state-engine's
--      cross-scope event stream): audit rows here are specifically the
--      org-admin actions that require legal-grade retention and queries
--      by role. The hosted Postgres profile carries the same shape with
--      partitioning and retention policy attached.
--
--   4. ``evidence_claims`` table (spec A.16 lines 3331-3354). Per-bundle
--      atomic units. The OSS local profile follows the canonical schema;
--      ``claim_type`` is restricted to the spec enum and does NOT include
--      'x-relay/admin-terminate'. The x-relay extension claim lands in
--      the companion table below.
--
--   5. ``evidence_x_relay_extensions`` table. Carries the ACEF x-relay/*
--      extension claims attached to a bundle. VAL-W8-037 references
--      ``x-relay/admin-terminate``; per contract gap #6 the canonical
--      claim shape is unspecified, so the OSS profile carries a generic
--      (bundle_id, extension_namespace, claim_digest, payload) shape that
--      W11 can tighten when ACEF wire format publishes the canonical
--      x-relay/admin-terminate schema. The signature is computed over
--      the canonical JSON of the (extension_namespace + payload) record
--      by the admin terminate action; storage here is the persisted form.
--
-- Per CLAUDE.md keystone invariants 1, 2, 4, 8 and the gate guard tests:
--   keystone 1 (control plane writes): gate_stalled_state inserts are
--     made by the W8.4 circuit_breaker.py module only; admin transitions
--     update via admin_actions.py.
--   keystone 4 (three-anchor handoff): admin actions carry the actor
--     identity hash + manifest commit hash on every audit row.
--   keystone 8 (atomic primitives): each transition co-commits the
--     gate_stalled_state INSERT/UPDATE with one event_log_entries append
--     and one audit_log_entries append in ONE BEGIN IMMEDIATE..COMMIT.
--
-- Idempotent (CREATE ... IF NOT EXISTS).

-- ---- gates (spec A.5) ------------------------------------------------------
--
-- VAL-W8-030: remediation_round_cap default 5.
-- VAL-W8-031: configurable per-gate, range [1, 50].
-- VAL-W8-038: cascade_on_block default true (1).

CREATE TABLE IF NOT EXISTS gates (
    gate_id                  TEXT    PRIMARY KEY NOT NULL,
    schema_version           TEXT    NOT NULL DEFAULT 'relay.gate.v1',
    project_id               TEXT    NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    name                     TEXT    NOT NULL,
    scope_type               TEXT    NOT NULL,
    enabled                  INTEGER NOT NULL DEFAULT 1,
    draft_ttl_seconds        INTEGER NOT NULL DEFAULT 900,
    remediation_round_cap    INTEGER NOT NULL DEFAULT 5,
    cascade_on_block         INTEGER NOT NULL DEFAULT 1,
    created_at               TEXT    NOT NULL,
    CONSTRAINT gates_scope_enum
        CHECK (scope_type IN ('run','replay','eval_run','release','domain_pack')),
    CONSTRAINT gates_enabled_bool
        CHECK (enabled IN (0, 1)),
    CONSTRAINT gates_cascade_bool
        CHECK (cascade_on_block IN (0, 1)),
    CONSTRAINT gates_remediation_round_cap_range
        CHECK (remediation_round_cap >= 1 AND remediation_round_cap <= 50),
    CONSTRAINT gates_draft_ttl_positive
        CHECK (draft_ttl_seconds >= 1),
    UNIQUE(project_id, name)
);

CREATE INDEX IF NOT EXISTS ix_gates_project_name
    ON gates(project_id, name);


-- ---- gate_stalled_state (VAL-W8-032, VAL-W8-034) --------------------------

CREATE TABLE IF NOT EXISTS gate_stalled_state (
    scope_type          TEXT    NOT NULL,
    scope_id            TEXT    NOT NULL,
    gate_id             TEXT    NOT NULL,
    terminal_round      INTEGER NOT NULL,
    reason              TEXT    NOT NULL,
    opened_at           TEXT    NOT NULL,
    reopened_at         TEXT,
    terminated_at       TEXT,
    PRIMARY KEY (scope_type, scope_id),
    CONSTRAINT gate_stalled_state_scope_enum
        CHECK (scope_type IN ('run','replay','eval_run','release','domain_pack')),
    CONSTRAINT gate_stalled_state_reason_enum
        CHECK (reason IN ('cap_exceeded', 'admin_paused', 'admin_terminated')),
    CONSTRAINT gate_stalled_state_round_positive
        CHECK (terminal_round >= 1)
);

CREATE INDEX IF NOT EXISTS ix_gate_stalled_state_gate
    ON gate_stalled_state(gate_id);


-- ---- audit_log_entries (VAL-W8-036, VAL-W8-037) ---------------------------

CREATE TABLE IF NOT EXISTS audit_log_entries (
    audit_id                TEXT    PRIMARY KEY NOT NULL,
    schema_version          TEXT    NOT NULL DEFAULT 'relay.audit_log_entry.v1',
    project_id              TEXT    NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    scope_type              TEXT    NOT NULL,
    scope_id                TEXT    NOT NULL,
    gate_id                 TEXT,
    action                  TEXT    NOT NULL,
    actor_kind              TEXT    NOT NULL,
    actor_identity_hash     TEXT    NOT NULL,
    actor_role              TEXT    NOT NULL,
    reason                  TEXT    NOT NULL DEFAULT '',
    prior_round_id          TEXT,
    new_round_id            TEXT,
    manifest_commit_hash    TEXT    NOT NULL,
    payload                 TEXT    NOT NULL DEFAULT '{}',
    occurred_at             TEXT    NOT NULL,
    CONSTRAINT audit_log_entries_scope_enum
        CHECK (scope_type IN ('run','replay','eval_run','release','domain_pack')),
    CONSTRAINT audit_log_entries_action_enum
        CHECK (action IN (
            'admin.reopen', 'admin.terminate', 'admin.pause',
            'admin.unpause', 'admin.override_command'
        )),
    CONSTRAINT audit_log_entries_actor_role_enum
        CHECK (actor_role IN ('org_owner', 'org_admin', 'member', 'service')),
    CONSTRAINT audit_log_entries_reason_max
        CHECK (length(reason) <= 2048),
    CONSTRAINT audit_log_entries_reopen_reason_required
        CHECK (action != 'admin.reopen' OR length(reason) > 0)
);

CREATE INDEX IF NOT EXISTS ix_audit_log_entries_scope
    ON audit_log_entries(scope_type, scope_id);

CREATE INDEX IF NOT EXISTS ix_audit_log_entries_action
    ON audit_log_entries(action, occurred_at);


-- ---- evidence_claims (spec A.16) ------------------------------------------

CREATE TABLE IF NOT EXISTS evidence_claims (
    evidence_claim_id            TEXT    PRIMARY KEY NOT NULL,
    schema_version               TEXT    NOT NULL DEFAULT 'relay.evidence_claim.v1',
    evidence_bundle_id           TEXT    NOT NULL,
    claim_type                   TEXT    NOT NULL,
    subject_kind                 TEXT    NOT NULL,
    subject_id                   TEXT    NOT NULL,
    claim_digest                 TEXT    NOT NULL,
    redaction_transform_version  TEXT    NOT NULL DEFAULT 'v1',
    manifest_commit_hash         TEXT    NOT NULL,
    signer_key_id                TEXT    NOT NULL,
    signature                    TEXT    NOT NULL,
    supersedes_claim_id          TEXT,
    created_at                   TEXT    NOT NULL,
    CONSTRAINT evidence_claims_type_enum
        CHECK (claim_type IN (
            'run_result','gate_decision','contract_result','replay_result',
            'human_oversight','incident','data_quality_check',
            'provider_compatibility'
        )),
    CONSTRAINT evidence_claims_digest_format
        CHECK (claim_digest LIKE 'sha256-%')
);

CREATE INDEX IF NOT EXISTS ix_evidence_claims_bundle
    ON evidence_claims(evidence_bundle_id);

CREATE INDEX IF NOT EXISTS ix_evidence_claims_subject
    ON evidence_claims(subject_kind, subject_id);


-- ---- evidence_x_relay_extensions (VAL-W8-037; contract gap #6) ------------

CREATE TABLE IF NOT EXISTS evidence_x_relay_extensions (
    extension_id            TEXT    PRIMARY KEY NOT NULL,
    schema_version          TEXT    NOT NULL DEFAULT 'relay.evidence_x_relay_extension.v1',
    evidence_bundle_id      TEXT    NOT NULL,
    extension_namespace     TEXT    NOT NULL,
    claim_digest            TEXT    NOT NULL,
    payload                 TEXT    NOT NULL DEFAULT '{}',
    manifest_commit_hash    TEXT    NOT NULL,
    signer_key_id           TEXT    NOT NULL,
    signature               TEXT    NOT NULL,
    created_at              TEXT    NOT NULL,
    CONSTRAINT evidence_x_relay_extensions_namespace_prefix
        CHECK (extension_namespace LIKE 'x-relay/%'),
    CONSTRAINT evidence_x_relay_extensions_digest_format
        CHECK (claim_digest LIKE 'sha256-%')
);

CREATE INDEX IF NOT EXISTS ix_evidence_x_relay_extensions_bundle
    ON evidence_x_relay_extensions(evidence_bundle_id);

CREATE INDEX IF NOT EXISTS ix_evidence_x_relay_extensions_namespace
    ON evidence_x_relay_extensions(extension_namespace);
