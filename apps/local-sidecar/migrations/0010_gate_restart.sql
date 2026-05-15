-- W8.3 migration 0010: gate restart on failure.
--
-- Adds the bookkeeping surface the restart coordinator needs:
--
--   1. ``gate_round_inputs`` table. Records the per-(scope, round)
--      digest of the worker-submitted draft inputs:
--        - inputs_digest        sha256-<hex> over canonical JSON of
--                                the draft's command_hash + manifest
--                                + release_sha + evidence_refs
--                                (the four anchors enumerated by
--                                VAL-W8-027 and contract gap #7).
--        - command_hash         manifest-resolved command_hash.
--        - manifest_commit_hash three-anchor manifest hash.
--        - release_sha          worker-supplied release sha (NULL if
--                                the draft did not declare one).
--        - draft_id             the draft that produced the digest.
--
--      Populated by the restart coordinator after a draft resolves;
--      consulted by ``check_unchanged_resubmission`` to detect a
--      worker that retried a remediate round without changing anything
--      (returns ``RELAY-GATE-041`` and does NOT consume a round per
--      VAL-W8-027).
--
-- The W8.3 coordinator also emits a canonical ``gate.restarted`` event
-- (VAL-W8-025) into ``event_log_entries`` via the existing open-schema
-- event_type column declared in 0001. We do NOT add a CHECK on
-- event_kind values (existing callers stay untouched); the coordinator
-- code is the canonical source of the event_kind strings it emits.
--
-- ASCII-only. Idempotent (CREATE ... IF NOT EXISTS).

CREATE TABLE IF NOT EXISTS gate_round_inputs (
    gate_round_inputs_id  TEXT    PRIMARY KEY NOT NULL,
    scope_type            TEXT    NOT NULL,
    scope_id              TEXT    NOT NULL,
    round                 INTEGER NOT NULL,
    draft_id              TEXT    NOT NULL,
    inputs_digest         TEXT    NOT NULL,
    command_hash          TEXT    NOT NULL,
    manifest_commit_hash  TEXT    NOT NULL,
    release_sha           TEXT,
    recorded_at           TEXT    NOT NULL,
    CONSTRAINT gate_round_inputs_scope_enum
        CHECK (scope_type IN ('run','replay','eval_run','release','domain_pack')),
    CONSTRAINT gate_round_inputs_round_positive
        CHECK (round >= 1),
    CONSTRAINT gate_round_inputs_digest_format
        CHECK (inputs_digest LIKE 'sha256-%'),
    UNIQUE(scope_type, scope_id, round, draft_id)
);

CREATE INDEX IF NOT EXISTS ix_gate_round_inputs_scope_round
    ON gate_round_inputs(scope_type, scope_id, round);
