-- 0024_audit_r4_actors_kind_alignment.sql
--
-- Audit-R4 (2026-05-18): align sidecar SQLite ``actors.kind`` CHECK with
-- the canonical 14-value enum locked in by envelopes.yaml + openapi.yaml
-- during audit-R3.
--
-- The audit-R3 batch widened the wire-format Actor.kind enum from 4
-- values {human, bot, worker, reviewer} to 14 values: {human, bot,
-- reviewer, sdk, machine, worker, gate_engine, result_writer,
-- evidence_signer, cron, control_plane, validation_worker,
-- ingest_worker, replay_worker} -- see envelopes.yaml line 234-251 and
-- openapi.yaml schemas/Actor/properties/kind/enum.
--
-- The audit-R3 sidecar migration (0023_audit_r3_schema_alignment.sql
-- section D9b, line 217-225) DOCUMENTED that the sidecar enum was
-- already "correct relative to the broadened wire set", but the
-- assertion was wrong: the sidecar CHECK in 0006_manifest_versions.sql
-- line 44-45 enumerates only 12 values and is MISSING ``bot`` and
-- ``reviewer``. Wire payloads with kind="bot" or kind="reviewer" pass
-- codegen validation but fail sidecar INSERT with a SQLite CHECK
-- constraint violation -- a silent rejection path that breaks the
-- three-anchor handoff guarantee (CLAUDE.md keystone #4) because the
-- handoff result depends on whether the actor row is INSERTable.
--
-- SQLite cannot ALTER an existing CHECK constraint. The portable
-- pattern is: create a new table with the corrected CHECK, copy rows,
-- drop the old table, rename the new one. Wrapped in BEGIN..COMMIT so
-- the rebuild is atomic.
--
-- Idempotency: the migration runner at
-- apps/local-sidecar/relay_sidecar/db.py:580 records each .sql filename
-- in __schema_migrations and skips already-applied files, so the
-- destructive DROP/RENAME pattern is safe -- it runs exactly once.
--
-- ASCII-only per CLAUDE.md "ASCII-Safe Source".

BEGIN;

-- ---------------------------------------------------------------------------
-- Step 1: create the new actors table with the 14-value CHECK.
-- ---------------------------------------------------------------------------
--
-- All non-CHECK constraints, defaults, and the PK shape are preserved
-- byte-for-byte from 0006_manifest_versions.sql line 37-50. Only the
-- ``actors_kind_enum`` CHECK is widened.

CREATE TABLE actors_audit_r4_new (
    identity_hash        TEXT    PRIMARY KEY NOT NULL,
    kind                 TEXT    NOT NULL,
    display_name         TEXT,
    org_admin            INTEGER NOT NULL DEFAULT 0,
    registered_at        TEXT    NOT NULL,
    revoked_at           TEXT,
    CONSTRAINT actors_kind_enum
        CHECK (kind IN (
            'human',
            'bot',
            'reviewer',
            'sdk',
            'machine',
            'worker',
            'gate_engine',
            'result_writer',
            'evidence_signer',
            'cron',
            'control_plane',
            'validation_worker',
            'ingest_worker',
            'replay_worker'
        )),
    CONSTRAINT actors_identity_hash_format
        CHECK (identity_hash LIKE 'sha256-%'),
    CONSTRAINT actors_org_admin_bool
        CHECK (org_admin IN (0, 1))
);

-- ---------------------------------------------------------------------------
-- Step 2: copy existing rows. All 12 values in the prior CHECK are a
-- subset of the new 14-value CHECK, so every existing row remains valid.
-- ---------------------------------------------------------------------------

INSERT INTO actors_audit_r4_new
    (identity_hash, kind, display_name, org_admin, registered_at, revoked_at)
SELECT
    identity_hash, kind, display_name, org_admin, registered_at, revoked_at
FROM actors;

-- ---------------------------------------------------------------------------
-- Step 3: drop the old table and rename the new one into place.
-- ---------------------------------------------------------------------------

DROP TABLE actors;
ALTER TABLE actors_audit_r4_new RENAME TO actors;

COMMIT;
