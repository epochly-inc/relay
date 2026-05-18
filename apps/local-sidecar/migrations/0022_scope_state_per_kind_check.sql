-- 0022_scope_state_per_kind_check.sql
--
-- Audit fix (2026-05-17 whole-codebase audit, P1): enforce the per-kind
-- state set on the sidecar's ``scope_state`` table as defense-in-depth
-- (VAL-W1-011 mirror).
--
-- Spec anchors:
--   sectionW lines 5067-5113      scope_state DDL + six scope_kinds
--   sectionW lines 5101-5111      per-kind initial-state mapping
--   packages/schemas/sql/0008_scope_state_extension.sql lines 110-133
--                                 canonical Postgres per-kind state CHECK
--
-- The canonical Postgres profile carries a cross-column CHECK constraint
-- ``scope_state_state_per_kind`` that rejects any (scope_kind, state)
-- pair outside the per-kind legal set. The sidecar profile's
-- ``0005_scope_state.sql`` declared only the scope_kind enumeration
-- CHECK and the ``0016_scope_state_extension.sql`` initial-state trigger
-- (which fires on epoch=0 INSERTs only); together they let post-initial
-- transitions land on ANY state value, defeating the defense-in-depth
-- the canonical CHECK is meant to provide.
--
-- This migration installs BEFORE INSERT and BEFORE UPDATE triggers that
-- mirror the canonical per-kind state set and abort with
-- ``RELAY-STATE-003`` on any violation. The two triggers together cover:
--
--   * INSERT path with epoch > 0 (the existing 0016 initial-state
--     trigger handles epoch = 0). For epoch > 0 the per-kind state set
--     must be the constraint, since the initial-state policy does not
--     apply.
--   * UPDATE path (the state engine transitions live states by issuing
--     UPDATE scope_state SET state = ...). The trigger fires when the
--     new state is outside the per-kind set.
--
-- Per-kind legal state sets (mirror of canonical CHECK at
-- packages/schemas/sql/0008_scope_state_extension.sql lines 111-133):
--
--   run             -> {pending, captured, validating, gated,
--                       result_written, terminal}
--   replay_case     -> {proposed, fixtures_ready, executing, analyzed,
--                       terminal}
--   gate_round      -> {open, draft_received, evaluating,
--                       decision_written, restarted, terminal}
--   evidence_bundle -> {building, signed, published, superseded, revoked}
--   eval_run        -> {pending, running, scored, terminal}
--   release         -> {open, gated, released, rolled_back, terminal}
--
-- Per CLAUDE.md keystone invariant #1 (control plane writes the result):
-- this migration extends scope_state's enforcement surface; it does not
-- grant any new write role. The state-engine module remains the only
-- caller that may transition scope_state rows.
--
-- ASCII-only per CLAUDE.md "ASCII-Safe Source".

-- ---------------------------------------------------------------------------
-- BEFORE INSERT: per-kind state check on epoch > 0 INSERTs.
-- ---------------------------------------------------------------------------
--
-- Initial inserts (epoch = 0) are validated by the existing 0016
-- ``scope_state_initial_state_check_trg`` trigger; the WHEN clause here
-- intentionally excludes them so we don't double-fire.

DROP TRIGGER IF EXISTS scope_state_per_kind_state_check_insert_trg;
CREATE TRIGGER scope_state_per_kind_state_check_insert_trg
BEFORE INSERT ON scope_state
FOR EACH ROW
WHEN NEW.epoch > 0
    AND NOT (
        (NEW.scope_kind = 'run' AND NEW.state IN (
            'pending', 'captured', 'validating', 'gated',
            'result_written', 'terminal'
        ))
        OR (NEW.scope_kind = 'replay_case' AND NEW.state IN (
            'proposed', 'fixtures_ready', 'executing', 'analyzed',
            'terminal'
        ))
        OR (NEW.scope_kind = 'gate_round' AND NEW.state IN (
            'open', 'draft_received', 'evaluating',
            'decision_written', 'restarted', 'terminal'
        ))
        OR (NEW.scope_kind = 'evidence_bundle' AND NEW.state IN (
            'building', 'signed', 'published', 'superseded', 'revoked'
        ))
        OR (NEW.scope_kind = 'eval_run' AND NEW.state IN (
            'pending', 'running', 'scored', 'terminal'
        ))
        OR (NEW.scope_kind = 'release' AND NEW.state IN (
            'open', 'gated', 'released', 'rolled_back', 'terminal'
        ))
    )
BEGIN
    SELECT RAISE(ABORT, 'RELAY-STATE-003: invalid (scope_kind, state) combination on INSERT; spec section W requires state to belong to the scope_kind per-kind legal set (run/replay_case/gate_round/evidence_bundle/eval_run/release)');
END;

-- ---------------------------------------------------------------------------
-- BEFORE UPDATE: per-kind state check on every state mutation.
-- ---------------------------------------------------------------------------
--
-- Fires on UPDATE OF state. The state engine's compare_and_set_state
-- transitions issue UPDATE scope_state SET state = <new>, epoch =
-- epoch + 1 WHERE ... ; this trigger is the defense-in-depth that
-- rejects engine bugs that would otherwise set state to a value outside
-- the per-kind legal set.

DROP TRIGGER IF EXISTS scope_state_per_kind_state_check_update_trg;
CREATE TRIGGER scope_state_per_kind_state_check_update_trg
BEFORE UPDATE OF state ON scope_state
FOR EACH ROW
WHEN NOT (
    (NEW.scope_kind = 'run' AND NEW.state IN (
        'pending', 'captured', 'validating', 'gated',
        'result_written', 'terminal'
    ))
    OR (NEW.scope_kind = 'replay_case' AND NEW.state IN (
        'proposed', 'fixtures_ready', 'executing', 'analyzed',
        'terminal'
    ))
    OR (NEW.scope_kind = 'gate_round' AND NEW.state IN (
        'open', 'draft_received', 'evaluating',
        'decision_written', 'restarted', 'terminal'
    ))
    OR (NEW.scope_kind = 'evidence_bundle' AND NEW.state IN (
        'building', 'signed', 'published', 'superseded', 'revoked'
    ))
    OR (NEW.scope_kind = 'eval_run' AND NEW.state IN (
        'pending', 'running', 'scored', 'terminal'
    ))
    OR (NEW.scope_kind = 'release' AND NEW.state IN (
        'open', 'gated', 'released', 'rolled_back', 'terminal'
    ))
)
BEGIN
    SELECT RAISE(ABORT, 'RELAY-STATE-003: invalid (scope_kind, state) combination on UPDATE; spec section W requires state to belong to the scope_kind per-kind legal set (run/replay_case/gate_round/evidence_bundle/eval_run/release)');
END;
