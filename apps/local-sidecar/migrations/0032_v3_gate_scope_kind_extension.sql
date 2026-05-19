-- 0032_v3_gate_scope_kind_extension.sql
--
-- V3M3-F05 (2026-05-19): sidecar mirror of the canonical
-- packages/schemas/sql/0021_v3_gate_scope_kind_extension.sql migration.
-- Extends the SQLite ``scope_state`` table's scope_kind enumeration to
-- admit the new ``gate`` scope_kind introduced by spec section AD
-- line 5468, and extends the per-kind state CHECK triggers installed by
-- migration 0022_scope_state_per_kind_check.sql to include the gate
-- scope's legal state set.
--
-- Spec authority (verbatim, section AD line 5471):
--   "gate: open -> draft_received -> evaluating -> decision_written
--         -> restarted -> ... -> stalled | terminal"
--
-- Three sidecar enforcement sites are touched
-- -------------------------------------------
-- 1. apps/local-sidecar/migrations/0005_scope_state.sql:28-30
--    -- the table-level ``scope_state_kind_enum`` CHECK enumerating
--    six kinds. SQLite cannot ALTER TABLE DROP/ADD CHECK, so this
--    migration rebuilds the table.
-- 2. apps/local-sidecar/migrations/0022_scope_state_per_kind_check.sql:62-93
--    -- the BEFORE INSERT trigger enumerating six per-kind state sets;
--    we DROP and recreate with seven (existing six + gate).
-- 3. apps/local-sidecar/migrations/0022_scope_state_per_kind_check.sql:104-133
--    -- the BEFORE UPDATE OF state trigger; same DROP+recreate.
--
-- Why the table rebuild
-- ---------------------
-- SQLite has no ALTER TABLE DROP CONSTRAINT or ALTER TABLE ADD CHECK
-- (https://www.sqlite.org/lang_altertable.html). The accepted recipe to
-- change a CHECK constraint is the standard
--   (a) create a new table with the desired CHECK,
--   (b) copy data,
--   (c) drop the old table,
--   (d) rename the new table.
-- Per the SQLite docs the operation is transactional under the runner's
-- outer BEGIN..COMMIT (see apps/local-sidecar/relay_sidecar/db.py
-- _run_migrations); no PRAGMA disable is required at the application
-- layer because foreign_keys defaults to OFF on the sidecar's sqlite3
-- connection and no FOREIGN KEY references this table.
--
-- Sister Postgres migration: packages/schemas/sql/0021_v3_gate_scope_kind_extension.sql
-- (Postgres supports ALTER TABLE DROP/ADD CONSTRAINT directly; no table
-- rebuild needed there).
--
-- Idempotency
-- -----------
-- Each migration is recorded in ``__schema_migrations`` by the runner
-- (apps/local-sidecar/relay_sidecar/db.py _run_migrations). On first
-- apply: rebuild + recreate triggers. On subsequent restart the runner
-- skips this file outright. No internal CREATE IF NOT EXISTS / DROP IF
-- EXISTS guards are needed for correctness but several are kept to keep
-- the script robust if invoked outside the runner (e.g., direct
-- sqlite3.executescript in a test bootstrap that mirrors the runner).
--
-- ASCII-only per CLAUDE.md "ASCII-Safe Source".

-- ---------------------------------------------------------------------------
-- Atomicity: the migration runner wraps each migration in BEGIN..COMMIT;
-- this script must NOT issue its own BEGIN/COMMIT.
-- ---------------------------------------------------------------------------

-- ---------------------------------------------------------------------------
-- Step 1: drop every trigger that references the ``scope_state`` table by
-- name. SQLite trigger SQL is stored as text in sqlite_master, and a
-- naive ALTER TABLE ... RENAME would leave the trigger pointing at the
-- old table name. Dropping triggers first, then rebuilding them after
-- the rename, is the canonical recipe.
-- ---------------------------------------------------------------------------
--
-- 0005 -- no triggers on scope_state itself.
-- 0016 -- scope_state_initial_state_check_trg (BEFORE INSERT on scope_state)
--         and six paired-check triggers on the object tables (runs,
--         replay_cases, gate_rounds, evidence_bundles, eval_runs,
--         releases) whose WHEN clause SELECTs from scope_state.
-- 0022 -- scope_state_per_kind_state_check_{insert,update}_trg.
--
-- The paired-check triggers reference scope_state in their WHEN clause;
-- SQLite's NOT EXISTS subquery is bound at parse time and the
-- subsequent table swap would invalidate the binding (sqlite raises
-- "no such table: main.scope_state" on the next INSERT into the object
-- table). We DROP them all here and re-CREATE them after the rename
-- using the same WHEN-clause text from 0016.

DROP TRIGGER IF EXISTS scope_state_per_kind_state_check_insert_trg;
DROP TRIGGER IF EXISTS scope_state_per_kind_state_check_update_trg;
DROP TRIGGER IF EXISTS scope_state_initial_state_check_trg;
DROP TRIGGER IF EXISTS runs_scope_state_paired_check;
DROP TRIGGER IF EXISTS replay_cases_scope_state_paired_check;
DROP TRIGGER IF EXISTS gate_rounds_scope_state_paired_check;
DROP TRIGGER IF EXISTS evidence_bundles_scope_state_paired_check;
DROP TRIGGER IF EXISTS eval_runs_scope_state_paired_check;
DROP TRIGGER IF EXISTS releases_scope_state_paired_check;

-- ---------------------------------------------------------------------------
-- Step 2: rebuild scope_state with the extended scope_kind enumeration.
-- ---------------------------------------------------------------------------
--
-- The new CHECK admits seven values (the existing six + ``gate``). The
-- other columns are byte-identical to the 0005 declaration so the
-- INSERT ... SELECT data copy preserves every row.

CREATE TABLE scope_state_new_v3m3_f05 (
    scope_kind       TEXT    NOT NULL,
    scope_id         TEXT    NOT NULL,
    project_id       TEXT    NOT NULL,
    state            TEXT    NOT NULL,
    epoch            INTEGER NOT NULL DEFAULT 0,
    created_at       TEXT    NOT NULL,
    updated_at       TEXT    NOT NULL,
    PRIMARY KEY (scope_kind, scope_id),
    CONSTRAINT scope_state_kind_enum CHECK (scope_kind IN (
        'run','replay_case','gate_round','evidence_bundle','eval_run',
        'release','gate'
    )),
    CONSTRAINT scope_state_epoch_nonneg CHECK (epoch >= 0)
);

INSERT INTO scope_state_new_v3m3_f05
    (scope_kind, scope_id, project_id, state, epoch, created_at, updated_at)
SELECT
    scope_kind, scope_id, project_id, state, epoch, created_at, updated_at
FROM scope_state;

DROP TABLE scope_state;

ALTER TABLE scope_state_new_v3m3_f05 RENAME TO scope_state;

-- Re-create the project_id index installed by 0005 line 34-35.
CREATE INDEX IF NOT EXISTS ix_scope_state_project_kind_state
    ON scope_state(project_id, scope_kind, state);

-- ---------------------------------------------------------------------------
-- Step 3: recreate the initial-state policy trigger from migration 0016,
-- now extended with the gate -> open mapping (spec section AD line 5471).
-- ---------------------------------------------------------------------------
--
-- Migration 0016 (apps/local-sidecar/migrations/0016_scope_state_extension.sql)
-- installed a BEFORE INSERT trigger that aborts an epoch=0 INSERT whose
-- state does not match the canonical initial state for the scope kind.
-- The original trigger's CASE enumerates 6 scope_kinds; we recreate it
-- with the gate scope's initial state added (open per spec line 5471).
--
-- The trigger fires only when NEW.epoch = 0; subsequent transitions go
-- through compare_and_set_state which uses UPDATE OF state and is
-- validated by the per-kind state CHECK trigger below.

CREATE TRIGGER scope_state_initial_state_check_trg
BEFORE INSERT ON scope_state
FOR EACH ROW
WHEN NEW.epoch = 0
    AND NEW.state != (
        CASE NEW.scope_kind
            WHEN 'run'             THEN 'pending'
            WHEN 'replay_case'     THEN 'proposed'
            WHEN 'gate_round'      THEN 'open'
            WHEN 'evidence_bundle' THEN 'building'
            WHEN 'eval_run'        THEN 'pending'
            WHEN 'release'         THEN 'open'
            WHEN 'gate'            THEN 'open'
        END
    )
BEGIN
    SELECT RAISE(ABORT, 'RELAY-STATE-001: initial state invalid for scope_kind; spec section W requires the initial state to match the transition-table origin state for the scope kind (run->pending, replay_case->proposed, gate_round->open, evidence_bundle->building, eval_run->pending, release->open, gate->open)');
END;

-- ---------------------------------------------------------------------------
-- Step 4: recreate the per-kind state CHECK triggers from migration 0022,
-- now extended with the gate scope's legal state set.
-- ---------------------------------------------------------------------------
--
-- Gate per-kind legal state set (spec section AD line 5471):
--   gate -> {open, draft_received, evaluating, decision_written,
--            restarted, stalled, terminal}
--
-- The state machine flows through:
--   open -> draft_received -> evaluating -> decision_written
--        -> restarted -> ... -> stalled | terminal
--
-- ``stalled`` and ``terminal`` are reachable from multiple predecessors
-- per spec section AD lines 5474-5485.

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
        OR (NEW.scope_kind = 'gate' AND NEW.state IN (
            'open', 'draft_received', 'evaluating', 'decision_written',
            'restarted', 'stalled', 'terminal'
        ))
    )
BEGIN
    SELECT RAISE(ABORT, 'RELAY-STATE-003: invalid (scope_kind, state) combination on INSERT; spec section W requires state to belong to the scope_kind per-kind legal set (run/replay_case/gate_round/evidence_bundle/eval_run/release/gate)');
END;

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
    OR (NEW.scope_kind = 'gate' AND NEW.state IN (
        'open', 'draft_received', 'evaluating', 'decision_written',
        'restarted', 'stalled', 'terminal'
    ))
)
BEGIN
    SELECT RAISE(ABORT, 'RELAY-STATE-003: invalid (scope_kind, state) combination on UPDATE; spec section W requires state to belong to the scope_kind per-kind legal set (run/replay_case/gate_round/evidence_bundle/eval_run/release/gate)');
END;

-- ---------------------------------------------------------------------------
-- Step 5: recreate the six object-table paired-row triggers from 0016.
-- ---------------------------------------------------------------------------
--
-- SQLite binds a trigger's WHEN/BODY table references at parse time;
-- the ALTER TABLE ... RENAME TO scope_state above swapped a different
-- table object behind the same name, leaving the paired-check triggers
-- with stale bindings ("no such table: main.scope_state" at next
-- object-table INSERT). We re-create each trigger verbatim from the
-- 0016 definitions so the spec section W line 5112 paired-row
-- invariant remains DB-enforced.
--
-- Body and RAISE message text are byte-identical to the 0016
-- definitions; the only deltas are intra-migration ordering.

CREATE TRIGGER runs_scope_state_paired_check
BEFORE INSERT ON runs
FOR EACH ROW
WHEN NOT EXISTS (
    SELECT 1 FROM scope_state
    WHERE scope_kind = 'run' AND scope_id = NEW.run_id
)
BEGIN
    SELECT RAISE(ABORT, 'RELAY-STATE-002: runs row inserted without matching scope_state(scope_kind=run, scope_id=NEW.run_id); spec section W requires the paired scope_state row in the same transaction');
END;

CREATE TRIGGER replay_cases_scope_state_paired_check
BEFORE INSERT ON replay_cases
FOR EACH ROW
WHEN NOT EXISTS (
    SELECT 1 FROM scope_state
    WHERE scope_kind = 'replay_case' AND scope_id = NEW.replay_case_id
)
BEGIN
    SELECT RAISE(ABORT, 'RELAY-STATE-002: replay_cases row inserted without matching scope_state(scope_kind=replay_case, scope_id=NEW.replay_case_id); spec section W requires the paired scope_state row in the same transaction');
END;

CREATE TRIGGER gate_rounds_scope_state_paired_check
BEFORE INSERT ON gate_rounds
FOR EACH ROW
WHEN NOT EXISTS (
    SELECT 1 FROM scope_state
    WHERE scope_kind = 'gate_round' AND scope_id = NEW.gate_round_id
)
BEGIN
    SELECT RAISE(ABORT, 'RELAY-STATE-002: gate_rounds row inserted without matching scope_state(scope_kind=gate_round, scope_id=NEW.gate_round_id); spec section W requires the paired scope_state row in the same transaction');
END;

CREATE TRIGGER evidence_bundles_scope_state_paired_check
BEFORE INSERT ON evidence_bundles
FOR EACH ROW
WHEN NOT EXISTS (
    SELECT 1 FROM scope_state
    WHERE scope_kind = 'evidence_bundle' AND scope_id = NEW.bundle_id
)
BEGIN
    SELECT RAISE(ABORT, 'RELAY-STATE-002: evidence_bundles row inserted without matching scope_state(scope_kind=evidence_bundle, scope_id=NEW.bundle_id); spec section W requires the paired scope_state row in the same transaction');
END;

CREATE TRIGGER eval_runs_scope_state_paired_check
BEFORE INSERT ON eval_runs
FOR EACH ROW
WHEN NOT EXISTS (
    SELECT 1 FROM scope_state
    WHERE scope_kind = 'eval_run' AND scope_id = NEW.eval_run_id
)
BEGIN
    SELECT RAISE(ABORT, 'RELAY-STATE-002: eval_runs row inserted without matching scope_state(scope_kind=eval_run, scope_id=NEW.eval_run_id); spec section W requires the paired scope_state row in the same transaction');
END;

CREATE TRIGGER releases_scope_state_paired_check
BEFORE INSERT ON releases
FOR EACH ROW
WHEN NOT EXISTS (
    SELECT 1 FROM scope_state
    WHERE scope_kind = 'release' AND scope_id = NEW.release_id
)
BEGIN
    SELECT RAISE(ABORT, 'RELAY-STATE-002: releases row inserted without matching scope_state(scope_kind=release, scope_id=NEW.release_id); spec section W requires the paired scope_state row in the same transaction');
END;
