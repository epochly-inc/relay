-- W2.4 migration 0004: gate_decision_drafts (worker submission table).
--
-- Mirrors spec A.3 schema. Drafts are NOT authoritative -- they are the
-- worker's request for a gate decision; the gate engine resolves a draft
-- into a gate_decision exactly once (or to a non-resolved terminal state:
-- expired, cancelled, rejected_handoff, duplicate_submission).
--
-- VAL-W2-033 asserts that on a failed three-anchor handoff, the
-- ``resolution_state`` MUST become ``'rejected_handoff'`` AND zero rows
-- are written to ``gate_decisions``. This table holds the rejected-handoff
-- evidence.
--
-- Per spec A.3 cross-field constraints:
--   - dry_run_unsigned drafts can NEVER resolve to a gate_decision
--     (constraint ``dry_run_never_resolves`` + ``dry_run_no_decision``).
--   - resolution_state is restricted to the enum below.
--
-- Idempotent.

CREATE TABLE IF NOT EXISTS gate_decision_drafts (
    draft_id                     TEXT    PRIMARY KEY NOT NULL,
    gate_id                      TEXT    NOT NULL,
    scope_type                   TEXT    NOT NULL,
    scope_id                     TEXT    NOT NULL,
    round                        INTEGER NOT NULL,
    release_sha                  TEXT,
    eval_run_ids                 TEXT    NOT NULL DEFAULT '[]',
    evidence_refs                TEXT    NOT NULL DEFAULT '[]',
    worker_id                    TEXT    NOT NULL,
    manifest_commit_hash         TEXT    NOT NULL,
    actor_identity_hash          TEXT    NOT NULL,
    submitted_at                 TEXT    NOT NULL,
    resolved_gate_decision_id    TEXT,
    draft_kind                   TEXT    NOT NULL DEFAULT 'submitted',
    resolution_state             TEXT    NOT NULL DEFAULT 'pending',
    cancelled_at                 TEXT,
    cancellation_reason          TEXT,
    CONSTRAINT gate_decision_drafts_kind_enum
        CHECK (draft_kind IN ('submitted','dry_run_unsigned')),
    CONSTRAINT gate_decision_drafts_resolution_enum
        CHECK (resolution_state IN (
            'pending',
            'resolved',
            'rejected_handoff',
            'expired',
            'cancelled',
            'duplicate_submission'
        )),
    -- Spec A.3 cross-field constraint: dry_run drafts cannot reach 'resolved'.
    CONSTRAINT dry_run_never_resolves CHECK (
        draft_kind = 'submitted'
        OR resolution_state IN ('pending','expired','cancelled','rejected_handoff','duplicate_submission')
    ),
    -- Spec A.3 cross-field constraint: dry_run drafts cannot bind a gate_decision.
    CONSTRAINT dry_run_no_decision CHECK (
        draft_kind = 'submitted' OR resolved_gate_decision_id IS NULL
    ),
    UNIQUE(gate_id, scope_type, scope_id, round, worker_id)
);

CREATE INDEX IF NOT EXISTS ix_gate_decision_drafts_state
    ON gate_decision_drafts(gate_id, resolution_state, submitted_at);
