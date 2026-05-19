-- 0022_v3_snapshot_gate_scope_check_extension.sql
--
-- V3M3 structural-review-r1 finding SR-M3-R1-001 (P1) follow-up:
-- extend the ``scope_state_snapshots.scope_kind`` CHECK enumeration to
-- admit the ``gate`` scope_kind added to ``scope_state`` by m3-f05
-- (packages/schemas/sql/0021_v3_gate_scope_kind_extension.sql,
-- apps/local-sidecar/migrations/0032_v3_gate_scope_kind_extension.sql).
--
-- Drift
-- -----
-- m3-f04 installed the ``scope_state_snapshots`` table with a 6-kind
-- CHECK enumeration (packages/schemas/sql/0018_v3_scope_state_snapshots.sql
-- lines 71-74):
--   ('run', 'replay_case', 'gate_round', 'evidence_bundle',
--    'eval_run', 'release')
-- m3-f05 then extended ``scope_state.scope_kind`` to seven kinds (adding
-- ``gate``) but did NOT sync the snapshots table. The first time a
-- ``gate`` scope_state row exists when ``write_daily_snapshot`` runs,
-- the INSERT into ``scope_state_snapshots`` fails the CHECK and the
-- snapshot txn rolls back -- a P1 daily-cron break.
--
-- Spec authority (spec section AD line 5468): ``gate`` is one of the
-- canonical scope_kinds; the snapshot is a derived view of scope_state
-- and MUST admit every kind that scope_state admits.
--
-- What this migration does
-- ------------------------
-- DROP the existing ``scope_state_snapshots_kind_enum`` CHECK and re-ADD
-- it with seven values (the existing six + ``gate``). Postgres supports
-- ALTER TABLE DROP/ADD CONSTRAINT directly; no table rebuild is needed.
--
-- Sidecar mirror: apps/local-sidecar/migrations/0033_v3_snapshot_gate_scope_check_extension.sql
-- (SQLite cannot ALTER TABLE DROP/ADD CHECK so the sidecar rebuilds the
-- ``scope_state_snapshots`` table; the canonical Postgres profile supports
-- ALTER TABLE DROP/ADD CONSTRAINT directly).
--
-- Idempotency
-- -----------
-- One-shot migration applied via the canonical Postgres migration runner.
-- The DROP CONSTRAINT IF EXISTS clause makes the file safe to re-run if
-- the runner has not yet recorded an apply. The constraint name installed
-- by 0018 line 71 is ``scope_state_snapshots_kind_enum``; we also DROP
-- the system-generated ``scope_state_snapshots_scope_kind_check`` name
-- defensively in case any environment was created with the table-
-- generated default name.
--
-- ASCII-only per CLAUDE.md "ASCII-Safe Source".

ALTER TABLE scope_state_snapshots
    DROP CONSTRAINT IF EXISTS scope_state_snapshots_kind_enum;

ALTER TABLE scope_state_snapshots
    DROP CONSTRAINT IF EXISTS scope_state_snapshots_scope_kind_check;

ALTER TABLE scope_state_snapshots
    ADD CONSTRAINT scope_state_snapshots_scope_kind_check
    CHECK (scope_kind IN (
        'run', 'replay_case', 'gate_round', 'evidence_bundle',
        'eval_run', 'release', 'gate'
    ));
