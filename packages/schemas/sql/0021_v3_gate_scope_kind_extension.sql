-- 0021_v3_gate_scope_kind_extension.sql
--
-- V3M3-F05 (2026-05-19): extend the canonical scope_state.scope_kind
-- enumeration to admit the new ``gate`` scope_kind introduced by spec
-- section AD line 5468.
--
-- Spec authority (verbatim, section AD lines 5468-5488):
--   "States extension to ``gate`` scope (section C.1):
--     gate: open -> draft_received -> evaluating -> decision_written
--           -> restarted -> ... -> stalled | terminal"
--
--   "| From                  | Event                | Guard                                                | To             | Side effect                |
--    | ``gate.restarted``    | ``round.cap_exceeded`` | ``current_round + 1 > gate.remediation_round_cap`` | ``gate.stalled`` | open sev2 incident         |
--    | ``gate.stalled``      | ``admin.reopen``       | actor.role IN ('org_owner','org_admin')            | ``gate.open``    | requires reason; logged    |
--    | ``gate.stalled``      | ``admin.terminate``    | actor.role IN ('org_owner','org_admin')            | ``gate.terminal``| sealed evidence bundle ..  |
--    | ``gate.decision_written`` (action=block) | (auto)       | NOT ``cascade_on_block``                | ``gate.terminal``| terminal block without restart |"
--
-- What this migration does
-- ------------------------
-- 1. DROP the ``scope_state_scope_kind_check`` constraint installed by
--    packages/schemas/sql/0008_scope_state_extension.sql lines 76-93 and
--    re-add it with seven values (the existing six + ``gate``).
-- 2. DROP the ``scope_state_state_per_kind`` constraint installed by
--    packages/schemas/sql/0008_scope_state_extension.sql lines 107-133
--    and re-add it with the new ``gate`` per-kind state set:
--      {open, draft_received, evaluating, decision_written, restarted,
--       stalled, terminal}.
-- 3. Update the ``relay_scope_state_initial_state_check`` PL/pgSQL
--    function installed by 0008 lines 158-190 to add the
--    ``gate -> open`` initial-state mapping (spec section AD line 5471).
--
-- Sidecar mirror: apps/local-sidecar/migrations/0032_v3_gate_scope_kind_extension.sql
-- (SQLite cannot ALTER TABLE DROP/ADD CHECK so the sidecar rebuilds the
-- ``scope_state`` table; the canonical Postgres profile supports
-- ALTER TABLE DROP/ADD CONSTRAINT directly).
--
-- Idempotency
-- -----------
-- This is a one-shot migration applied via the canonical Postgres
-- migration runner. The DROP CONSTRAINT IF EXISTS clauses make the file
-- safe to re-run if the runner has not yet recorded an apply.
--
-- ASCII-only per CLAUDE.md "ASCII-Safe Source".

-- ---------------------------------------------------------------------------
-- Step 1: extend scope_state.scope_kind CHECK to admit ``gate``.
-- ---------------------------------------------------------------------------
--
-- The constraint name installed by 0008 line 89 is
-- ``scope_state_scope_kind_check``; 0008 also DROPs the system-generated
-- ``scope_state_scope_kind1_check`` defensively. We mirror that
-- discipline here for both names.

ALTER TABLE scope_state
    DROP CONSTRAINT IF EXISTS scope_state_scope_kind_check;

ALTER TABLE scope_state
    DROP CONSTRAINT IF EXISTS scope_state_scope_kind1_check;

ALTER TABLE scope_state
    ADD CONSTRAINT scope_state_scope_kind_check
    CHECK (scope_kind IN (
        'run', 'replay_case', 'gate_round', 'evidence_bundle',
        'eval_run', 'release', 'gate'
    ));

-- ---------------------------------------------------------------------------
-- Step 2: extend the per-kind state CHECK to include ``gate``.
-- ---------------------------------------------------------------------------
--
-- The canonical legal-state set for the gate scope is sourced from spec
-- section AD line 5471:
--   open -> draft_received -> evaluating -> decision_written
--        -> restarted -> ... -> stalled | terminal
--
-- The state ``terminal`` is the canonical end state; ``stalled`` is the
-- cap-exceeded / admin-paused state per spec section AD line 5488.

ALTER TABLE scope_state
    DROP CONSTRAINT IF EXISTS scope_state_state_per_kind;

ALTER TABLE scope_state
    ADD CONSTRAINT scope_state_state_per_kind CHECK (
        (scope_kind = 'run' AND state IN (
            'pending', 'captured', 'validating', 'gated',
            'result_written', 'terminal'
        ))
        OR (scope_kind = 'replay_case' AND state IN (
            'proposed', 'fixtures_ready', 'executing', 'analyzed',
            'terminal'
        ))
        OR (scope_kind = 'gate_round' AND state IN (
            'open', 'draft_received', 'evaluating', 'decision_written',
            'restarted', 'terminal'
        ))
        OR (scope_kind = 'evidence_bundle' AND state IN (
            'building', 'signed', 'published', 'superseded', 'revoked'
        ))
        OR (scope_kind = 'eval_run' AND state IN (
            'pending', 'running', 'scored', 'terminal'
        ))
        OR (scope_kind = 'release' AND state IN (
            'open', 'gated', 'released', 'rolled_back', 'terminal'
        ))
        OR (scope_kind = 'gate' AND state IN (
            'open', 'draft_received', 'evaluating', 'decision_written',
            'restarted', 'stalled', 'terminal'
        ))
    );

-- ---------------------------------------------------------------------------
-- Step 3: extend the initial-state policy trigger for ``gate``.
-- ---------------------------------------------------------------------------
--
-- The trigger function ``relay_scope_state_initial_state_check`` at
-- 0008 lines 158-190 enumerates 6 scope_kinds via a CASE expression and
-- raises RELAY-STATE-001 when an epoch=0 INSERT lands with an unknown
-- scope_kind. We CREATE OR REPLACE the function to add the gate mapping:
--   gate -> open  (spec section AD line 5471).
--
-- Per CLAUDE.md keystone invariant #1 (control plane writes the result),
-- callers may NOT insert scope_state rows directly; the canonical write
-- path is the state-engine ``compare_and_set_state`` / ``init_scope``
-- primitive. The trigger is defense-in-depth.

CREATE OR REPLACE FUNCTION relay_scope_state_initial_state_check()
    RETURNS trigger AS $$
DECLARE
    expected_initial text;
BEGIN
    -- Only validate true initial rows (epoch = 0). UPDATEs and engine
    -- transitions arrive with epoch > 0 and are out of scope here.
    IF NEW.epoch != 0 THEN
        RETURN NEW;
    END IF;
    expected_initial := CASE NEW.scope_kind
        WHEN 'run'             THEN 'pending'
        WHEN 'replay_case'     THEN 'proposed'
        WHEN 'gate_round'      THEN 'open'
        WHEN 'evidence_bundle' THEN 'building'
        WHEN 'eval_run'        THEN 'pending'
        WHEN 'release'         THEN 'open'
        WHEN 'gate'            THEN 'open'
        ELSE NULL
    END;
    IF expected_initial IS NULL THEN
        -- scope_kind CHECK above will reject; this is defence-in-depth.
        RAISE EXCEPTION
            'RELAY-STATE-001: unknown scope_kind % for initial state',
            NEW.scope_kind;
    END IF;
    IF NEW.state != expected_initial THEN
        RAISE EXCEPTION
            'RELAY-STATE-001: initial state % invalid for scope_kind %; '
            'expected %', NEW.state, NEW.scope_kind, expected_initial;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- The trigger object itself was installed by 0008 line 192-196; no
-- recreation needed because CREATE OR REPLACE FUNCTION above swaps the
-- implementation behind the same trigger binding.
