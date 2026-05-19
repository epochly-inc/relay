-- 0033_v3_snapshot_gate_scope_check_extension.sql
--
-- V3M3 structural-review-r1 finding SR-M3-R1-001 (P1) follow-up:
-- sidecar mirror of the canonical PG migration
-- packages/schemas/sql/0022_v3_snapshot_gate_scope_check_extension.sql.
-- Extends the SQLite ``scope_state_snapshots`` table's
-- ``scope_kind`` CHECK enumeration to admit the ``gate`` scope_kind
-- added to ``scope_state`` by m3-f05
-- (apps/local-sidecar/migrations/0032_v3_gate_scope_kind_extension.sql).
--
-- Drift
-- -----
-- m3-f04 installed ``scope_state_snapshots`` with a 6-kind CHECK
-- (apps/local-sidecar/migrations/0030_v3_scope_state_snapshots.sql
-- lines 45-47):
--   ('run','replay_case','gate_round','evidence_bundle','eval_run','release')
-- m3-f05 extended ``scope_state.scope_kind`` to seven kinds (adding
-- ``gate``) but did NOT sync the snapshots table. ``write_daily_snapshot``
-- (apps/local-sidecar/relay_sidecar/state_engine/retention.py lines
-- 476-490) INSERTs one row per active ``scope_state`` row into
-- ``scope_state_snapshots``; the first ``gate`` row trips the CHECK and
-- rolls the snapshot txn back.
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
-- This mirrors the m3-f05 sister migration
-- apps/local-sidecar/migrations/0032_v3_gate_scope_kind_extension.sql
-- which performed the same recipe against ``scope_state``.
--
-- Per the SQLite docs the operation is transactional under the runner's
-- outer BEGIN..COMMIT (see apps/local-sidecar/relay_sidecar/db.py
-- _run_migrations); no PRAGMA disable is required at the application
-- layer because foreign_keys defaults to OFF on the sidecar's sqlite3
-- connection and no FOREIGN KEY references this table.
--
-- Sister Postgres migration:
-- packages/schemas/sql/0022_v3_snapshot_gate_scope_check_extension.sql
-- (Postgres supports ALTER TABLE DROP/ADD CONSTRAINT directly; no table
-- rebuild needed there).
--
-- Idempotency
-- -----------
-- Each migration is recorded in ``__schema_migrations`` by the runner
-- (apps/local-sidecar/relay_sidecar/db.py _run_migrations). On first
-- apply: rebuild + recreate the snapshot_date index. On subsequent
-- restart the runner skips this file outright.
--
-- ASCII-only per CLAUDE.md "ASCII-Safe Source".

-- ---------------------------------------------------------------------------
-- Atomicity: the migration runner wraps each migration in BEGIN..COMMIT;
-- this script must NOT issue its own BEGIN/COMMIT.
-- ---------------------------------------------------------------------------

-- ---------------------------------------------------------------------------
-- Step 1: rebuild scope_state_snapshots with the extended scope_kind
-- enumeration.
-- ---------------------------------------------------------------------------
--
-- The new CHECK admits seven values (the existing six + ``gate``). The
-- other columns are byte-identical to the 0030 declaration so the
-- INSERT ... SELECT data copy preserves every existing snapshot row,
-- preserves the composite PK (snapshot_date, scope_kind, scope_id), and
-- preserves the snapshot_id UNIQUE constraint.
--
-- The base 0030 schema is:
--   snapshot_id     TEXT NOT NULL,
--   snapshot_date   TEXT NOT NULL,
--   scope_kind      TEXT NOT NULL,
--   scope_id        TEXT NOT NULL,
--   state           TEXT NOT NULL,
--   epoch           INTEGER NOT NULL,
--   PRIMARY KEY (snapshot_date, scope_kind, scope_id),
--   CONSTRAINT scope_state_snapshots_kind_enum CHECK (...),
--   CONSTRAINT scope_state_snapshots_epoch_nonneg CHECK (epoch >= 0)
--
-- Note: 0030 did NOT declare snapshot_id UNIQUE on the sidecar (the
-- canonical PG migration does, but the sidecar PRAGMA table_info /
-- PRIMARY KEY is sufficient for the f04 idempotency contract). The
-- rebuild preserves the original column declarations byte-for-byte.

CREATE TABLE scope_state_snapshots_new_v3m3_sr_r1 (
    snapshot_id     TEXT NOT NULL,
    snapshot_date   TEXT NOT NULL,
    scope_kind      TEXT NOT NULL,
    scope_id        TEXT NOT NULL,
    state           TEXT NOT NULL,
    epoch           INTEGER NOT NULL,
    PRIMARY KEY (snapshot_date, scope_kind, scope_id),
    CONSTRAINT scope_state_snapshots_kind_enum CHECK (scope_kind IN (
        'run','replay_case','gate_round','evidence_bundle','eval_run',
        'release','gate'
    )),
    CONSTRAINT scope_state_snapshots_epoch_nonneg CHECK (epoch >= 0)
);

INSERT INTO scope_state_snapshots_new_v3m3_sr_r1
    (snapshot_id, snapshot_date, scope_kind, scope_id, state, epoch)
SELECT
    snapshot_id, snapshot_date, scope_kind, scope_id, state, epoch
FROM scope_state_snapshots;

DROP TABLE scope_state_snapshots;

ALTER TABLE scope_state_snapshots_new_v3m3_sr_r1
    RENAME TO scope_state_snapshots;

-- ---------------------------------------------------------------------------
-- Step 2: recreate the snapshot_date index that 0030 installed.
-- ---------------------------------------------------------------------------
--
-- SQLite drops indexes when their parent table is dropped (the table's
-- DROP cascades to its indexes per
-- https://www.sqlite.org/lang_droptable.html). Re-create the
-- ``ix_scope_state_snapshots_snapshot_date`` index that the retention
-- sweep (prune_old_scope_state_snapshots) depends on for O(log N)
-- range scans.

CREATE INDEX IF NOT EXISTS ix_scope_state_snapshots_snapshot_date
    ON scope_state_snapshots(snapshot_date);
