-- 0018_v3_scope_state_snapshots.sql
--
-- V3M3-F04: spec AP.5.b scope_state_snapshots forensic / audit / DR table.
--
-- Spec anchor: planning/epochly-replay-spec.md AP.5.b (lines 6347-6390).
--
-- AP.5.b answers the operational question "what was every active scope's
-- state at midnight UTC on day X?" without scanning the entire event
-- log. A daily cron job ``scope_state_snapshot_daily`` runs at 00:05 UTC,
-- freezes the current scope_state per project as of the highest
-- ingest_sequence strictly before midnight, and stores the snapshot.
--
-- The spec's full hosted shape carries a JCS-canonicalised body in
-- object storage (R2/S3) plus row-level signature metadata
-- (signer_key_id, signature, body_ref, body_digest, pinned_ingest_sequence,
-- row_count). For this OSS migration we adopt the storage shape called
-- out by the V3M3 audit-resolution work order:
--
--   scope_state_snapshots (
--     snapshot_id   PRIMARY KEY,
--     snapshot_date DATE,
--     scope_kind    TEXT,
--     scope_id      UUID,
--     state         TEXT,
--     epoch         BIGINT
--   )
--   PRIMARY KEY (snapshot_date, scope_kind, scope_id)
--   INDEX ON snapshot_date
--
-- One row per active scope_state row per snapshot day. The PK is the
-- idempotency anchor: re-running the daily helper after a crash is a
-- no-op (INSERT ... ON CONFLICT DO NOTHING). The retention sweep is the
-- 90-day window defined in the helper module (see below) and matched
-- by the index on ``snapshot_date``:
--
--   DELETE FROM scope_state_snapshots
--    WHERE snapshot_date < CURRENT_DATE - INTERVAL '90 days';
--
-- ``snapshot_id`` is a primary identifier for the row (uuid; useful for
-- correlation in the event_log and for the hosted upgrade path where a
-- single signed snapshot may carry many per-scope rows). It is declared
-- UNIQUE NOT NULL but NOT the table primary key -- the AP.5.b
-- idempotency contract requires the natural key
-- (snapshot_date, scope_kind, scope_id) to be the PK so PK collisions
-- on re-run absorb cleanly.
--
-- Per CLAUDE.md keystone invariant #1: the state engine remains the
-- only writer of scope_state. ``scope_state_snapshots`` is a derived /
-- forensic table populated by the snapshot helper (state-engine-
-- adjacent). The VAL-W2-024 / -058 grep guard (regex with \b word
-- boundary) does NOT collide with the snapshots table name.
--
-- Per CLAUDE.md keystone invariant #10: schema_version is unchanged
-- (relay.scope_state.v1) because the snapshot table is a NEW persisted
-- shape; the envelope additions land separately in
-- packages/schemas/raw/envelopes.yaml when the hosted full-body shape is
-- introduced.
--
-- Idempotent.
--
-- ASCII-only per CLAUDE.md "ASCII-Safe Source".

CREATE TABLE IF NOT EXISTS scope_state_snapshots (
    snapshot_id     uuid        NOT NULL UNIQUE,
    snapshot_date   date        NOT NULL,
    scope_kind      text        NOT NULL,
    scope_id        uuid        NOT NULL,
    state           text        NOT NULL,
    epoch           bigint      NOT NULL,
    PRIMARY KEY (snapshot_date, scope_kind, scope_id),
    CONSTRAINT scope_state_snapshots_kind_enum CHECK (scope_kind IN (
        'run', 'replay_case', 'gate_round', 'evidence_bundle',
        'eval_run', 'release'
    )),
    CONSTRAINT scope_state_snapshots_epoch_nonneg CHECK (epoch >= 0)
);

CREATE INDEX IF NOT EXISTS ix_scope_state_snapshots_snapshot_date
    ON scope_state_snapshots(snapshot_date);
