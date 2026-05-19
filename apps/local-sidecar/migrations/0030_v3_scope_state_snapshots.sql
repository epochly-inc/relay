-- 0030_v3_scope_state_snapshots.sql
--
-- V3M3-F04: sidecar mirror of the spec AP.5.b scope_state_snapshots
-- forensic / audit / DR table.
--
-- Spec anchor: planning/epochly-replay-spec.md AP.5.b (lines 6347-6390).
--
-- Per spec AP.5.b the hosted Postgres edition stores only metadata in
-- the row (snapshot_id, project_id, snapshot_at, pinned_ingest_sequence,
-- row_count, body_ref, body_digest, signature, signer_key_id) and the
-- snapshot BODY (one entry per active scope) in object storage
-- (R2/S3). The OSS local-sidecar has no companion object store, so it
-- stores the snapshot rows directly: one row per (snapshot_date,
-- scope_kind, scope_id) describing the (state, epoch) of that scope on
-- that day. The PK is the idempotency anchor for the daily snapshot
-- helper -- re-running the cron after a crash is a no-op.
--
-- The 90-day retention sweep is implemented by
-- ``prune_old_scope_state_snapshots`` in
-- apps/local-sidecar/relay_sidecar/state_engine/retention.py; the
-- ``ix_scope_state_snapshots_snapshot_date`` index makes that sweep
-- O(log N) instead of a full table scan.
--
-- The state-engine writer guard in
-- apps/local-sidecar/tests/test_state_engine_writes_only.py whitelists
-- INSERTs / UPDATEs only on (scope_state, run_results, event_log_entries);
-- the snapshot table name (scope_state_snapshots) does NOT collide with
-- those patterns (regex uses \\b word boundaries) so the helper does not
-- need to live in state_engine/ for guard compliance. We co-locate it
-- there anyway because it is a state-engine-adjacent retention pass
-- (same module as run_retention_pass).
--
-- Idempotent (CREATE TABLE IF NOT EXISTS + CREATE INDEX IF NOT EXISTS).
--
-- ASCII-only per CLAUDE.md "ASCII-Safe Source".

CREATE TABLE IF NOT EXISTS scope_state_snapshots (
    snapshot_id     TEXT NOT NULL,
    snapshot_date   TEXT NOT NULL,
    scope_kind      TEXT NOT NULL,
    scope_id        TEXT NOT NULL,
    state           TEXT NOT NULL,
    epoch           INTEGER NOT NULL,
    PRIMARY KEY (snapshot_date, scope_kind, scope_id),
    CONSTRAINT scope_state_snapshots_kind_enum CHECK (scope_kind IN (
        'run','replay_case','gate_round','evidence_bundle','eval_run','release'
    )),
    CONSTRAINT scope_state_snapshots_epoch_nonneg CHECK (epoch >= 0)
);

CREATE INDEX IF NOT EXISTS ix_scope_state_snapshots_snapshot_date
    ON scope_state_snapshots(snapshot_date);
