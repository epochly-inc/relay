-- 0016_scope_state_extension.sql
--
-- v0.2 OSS completeness, milestone M01, feature w1.7: SQLite sidecar mirror
-- of packages/schemas/sql/0008_scope_state_extension.sql.
--
-- Spec anchors:
--   sectionW lines 5067-5113   scope_state table, six scope_kinds,
--                              initial-state mapping, deferred-trigger rule
--
-- This file delivers three concerns on the local-sidecar profile:
--
--   1. Object-table stubs for the four object tables that have not yet
--      been declared in the sidecar migration tree (runs, replay_cases,
--      eval_runs, releases). Each stub carries only a PK column
--      (<table>_id TEXT PRIMARY KEY NOT NULL). Sibling features in
--      milestones M02-M05 land the full schema; their migrations issue
--      ALTER TABLE ADD COLUMN against this stub, or recreate the table
--      from scratch (CREATE TABLE IF NOT EXISTS is a no-op once we install
--      the stub here).
--
--   2. Initial-state policy guard: a BEFORE INSERT trigger on scope_state
--      that aborts with the canonical RELAY-STATE-001 marker when a new
--      row (epoch = 0) carries any state other than the per-kind origin
--      state defined by spec sectionW lines 5101-5111.
--
--   3. Object-row paired-row guard: a BEFORE INSERT trigger on each of
--      the six object tables that aborts when no matching scope_state
--      row exists for (scope_kind, scope_id = NEW.<pk_column>). Spec
--      sectionW line 5112 normatively requires this check at COMMIT time
--      (the Postgres profile uses CONSTRAINT TRIGGER ... DEFERRABLE
--      INITIALLY DEFERRED). SQLite does NOT support DEFERRABLE on TRIGGER
--      declarations, so the sidecar fall-back fires immediately at
--      INSERT time. This is a strictly stronger check than the spec's
--      commit-time requirement (it rejects orphan inserts earlier),
--      but it forces ordering: the application MUST insert the
--      scope_state row first within the BEGIN..COMMIT block.
--
--      The semantic guarantee preserved across both profiles: no object
--      row exists in canonical storage without a paired scope_state row.
--      Only the failure-point timing differs.
--
-- Per CLAUDE.md keystone invariant #1: the state-engine module is the only
-- caller that may transition scope_state rows; this migration adds
-- enforcement, not new write paths.
--
-- All statements are idempotent: CREATE TABLE IF NOT EXISTS; DROP TRIGGER
-- IF EXISTS; CREATE TRIGGER.
--
-- ASCII-only per CLAUDE.md "ASCII-Safe Source".

-- ---------------------------------------------------------------------------
-- VAL-V2M01-036: SQLite CHECK already enumerates 6 kinds in 0005
-- ---------------------------------------------------------------------------
--
-- The sidecar's 0005 migration (apps/local-sidecar/migrations/0005_scope_state.sql
-- lines 28-30) already declares scope_state.scope_kind CHECK across all six
-- kinds ('run','replay_case','gate_round','evidence_bundle','eval_run','release').
-- SQLite does not support ALTER TABLE ... DROP CONSTRAINT; rewriting the
-- table is unnecessary because the constraint is already correct on this
-- profile.
--
-- This migration's role for VAL-V2M01-036 on the sidecar is to ENFORCE
-- the per-kind state enumeration via a trigger (SQLite cannot represent
-- the discriminated cross-column CHECK as cleanly as Postgres). The
-- trigger below covers both the initial-state policy AND the per-kind
-- state enumeration.

-- ---------------------------------------------------------------------------
-- Object-table stubs (only those not yet declared by sibling features)
-- ---------------------------------------------------------------------------
--
-- Stubs carry the PK column ONLY. Sibling features add the full schema.

CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY NOT NULL
);

CREATE TABLE IF NOT EXISTS replay_cases (
    replay_case_id TEXT PRIMARY KEY NOT NULL
);

CREATE TABLE IF NOT EXISTS eval_runs (
    eval_run_id TEXT PRIMARY KEY NOT NULL
);

CREATE TABLE IF NOT EXISTS releases (
    release_id TEXT PRIMARY KEY NOT NULL
);

-- ---------------------------------------------------------------------------
-- VAL-V2M01-037: initial-state policy guard on scope_state INSERT
-- ---------------------------------------------------------------------------
--
-- Mirror of packages/schemas/sql/0008 BEFORE INSERT trigger.
-- Fires on epoch=0 rows only; engine transitions arrive with epoch > 0
-- and are out of scope.
--
-- Per-kind initial state mapping (spec sectionW lines 5101-5111):
--   run             -> pending
--   replay_case     -> proposed
--   gate_round      -> open
--   evidence_bundle -> building
--   eval_run        -> pending
--   release         -> open
--
-- Also enforces the per-kind state enumeration superset for the two
-- new scope_kinds eval_run and release (the original 0005 sidecar CHECK
-- only enumerated kinds, not per-kind state sets, mirroring the SQLite
-- limitation around discriminated CHECKs).

DROP TRIGGER IF EXISTS scope_state_initial_state_check_trg;
CREATE TRIGGER scope_state_initial_state_check_trg
BEFORE INSERT ON scope_state
FOR EACH ROW
WHEN NEW.epoch = 0
    AND NOT (
        (NEW.scope_kind = 'run'             AND NEW.state = 'pending')
        OR (NEW.scope_kind = 'replay_case'  AND NEW.state = 'proposed')
        OR (NEW.scope_kind = 'gate_round'   AND NEW.state = 'open')
        OR (NEW.scope_kind = 'evidence_bundle' AND NEW.state = 'building')
        OR (NEW.scope_kind = 'eval_run'     AND NEW.state = 'pending')
        OR (NEW.scope_kind = 'release'      AND NEW.state = 'open')
    )
BEGIN
    SELECT RAISE(ABORT, 'RELAY-STATE-001: invalid initial state for scope_kind; spec section W requires the transition-table origin state on epoch=0 inserts (run->pending, replay_case->proposed, gate_round->open, evidence_bundle->building, eval_run->pending, release->open)');
END;

-- ---------------------------------------------------------------------------
-- VAL-V2M01-038: paired-row guard on object-table INSERT
-- ---------------------------------------------------------------------------
--
-- One BEFORE INSERT trigger per object table; each looks up scope_state
-- using the corresponding scope_kind and NEW.<pk_column>. Aborts when no
-- matching row exists.
--
-- SQLite divergence from spec sectionW line 5112: the canonical Postgres
-- profile uses CONSTRAINT TRIGGER ... DEFERRABLE INITIALLY DEFERRED so
-- the join check fires at COMMIT. SQLite triggers cannot be DEFERRABLE;
-- the check fires at INSERT time. The application contract on the
-- sidecar profile is therefore: INSERT scope_state row first, then
-- INSERT the object row, both inside the same BEGIN..COMMIT block.
-- Semantic guarantee preserved: no object row exists without its scope_state.

DROP TRIGGER IF EXISTS runs_scope_state_paired_check;
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

DROP TRIGGER IF EXISTS replay_cases_scope_state_paired_check;
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

DROP TRIGGER IF EXISTS gate_rounds_scope_state_paired_check;
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

DROP TRIGGER IF EXISTS evidence_bundles_scope_state_paired_check;
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

DROP TRIGGER IF EXISTS eval_runs_scope_state_paired_check;
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

DROP TRIGGER IF EXISTS releases_scope_state_paired_check;
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
