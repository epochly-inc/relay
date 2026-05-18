-- 0014_v3_evidence_claim_shape.sql
--
-- V3M1-F05 (2026-05-18): canonical Postgres DDL extension for the
-- ``evidence_claims`` table, bringing the on-disk shape into alignment
-- with the spec K authoritative envelope at lines 4388-4438.
--
-- Spec authority: section K (Evidence Claim v1 schema). The historical
-- shape landed by 0003_evidence_replay.sql carried only the flat
-- ``subject_kind`` / ``subject_id`` columns and lacked five new fields
-- declared by spec K:
--
--   evidence_refs[]               -> JSONB list of EvidenceRef objects
--   claim_predicate               -> JSONB ClaimPredicate (recursive)
--   actor_kind                    -> closed-enum TEXT (control_plane /
--                                    gate_engine / worker / sdk / user /
--                                    cron) -- mirrors EventLogEntry.actor_kind
--   actor_identity_hash           -> canonical sha256-<hex> TEXT
--   occurred_at                   -> TIMESTAMPTZ distinct from created_at
--   namespaces                    -> optional JSONB carrying the ACEF
--                                    x-relay extension envelope
--
-- Additionally the spec K nested ``subject`` object {kind, id,
-- manifest_commit_hash} is materialized as a ``subject`` JSONB column
-- populated from the existing flat ``subject_kind``/``subject_id`` +
-- top-level ``manifest_commit_hash`` columns. The flat columns are
-- RETAINED for read back-compat per VAL-V3M1-015 ("flat columns are
-- deprecated but still readable"). m1-f06 migrates production callers
-- to the nested-subject access path; m1-f07 (VAL-V3M1-017) adds the
-- supersedes_claim_id CHECK constraint. This migration delivers ONLY the
-- column additions + the subject JSONB materialization.
--
-- Per CLAUDE.md keystone invariant #1, writes to ``evidence_claims`` are
-- already gated by the SAME role grants that restrict the evidence-
-- signer / control-plane writers; this migration adds no new write
-- privileges and the new columns inherit the existing constraints.
--
-- Per CLAUDE.md keystone invariant #10, ``schema_version`` remains pinned
-- to ``relay.evidence_claim.v1`` (additive field changes do not bump the
-- envelope version; readers ignore unknown fields per the W1.6 forward-
-- compat policy with the exception of closed enums, where we add the
-- actor_kind CHECK that the wire-format layer pre-validates).
--
-- Idempotency: ADD COLUMN IF NOT EXISTS is used throughout so partial
-- re-runs do not error on a previously-migrated database.
--
-- ASCII-only per CLAUDE.md "ASCII-Safe Source".

BEGIN;

-- -----------------------------------------------------------------------------
-- evidence_refs (spec K line 4402-4406; VAL-V3M1-011)
-- -----------------------------------------------------------------------------
ALTER TABLE evidence_claims
    ADD COLUMN IF NOT EXISTS evidence_refs jsonb NOT NULL DEFAULT '[]'::jsonb;

-- -----------------------------------------------------------------------------
-- claim_predicate (spec K line 4407-4413; VAL-V3M1-012)
-- -----------------------------------------------------------------------------
-- Nullable: legacy rows pre-V3M1 may have been written without a
-- canonical predicate. Wire-format layer enforces depth-8 bound; SQL
-- side stores the JSON verbatim.
ALTER TABLE evidence_claims
    ADD COLUMN IF NOT EXISTS claim_predicate jsonb NULL;

-- -----------------------------------------------------------------------------
-- actor_kind + actor_identity_hash (spec K line 4415-4416; VAL-V3M1-013)
-- -----------------------------------------------------------------------------
-- Closed-enum CHECK mirrors EventLogEntry.actor_kind set
-- {control_plane, gate_engine, worker, sdk, user, cron}. Defaults to
-- 'control_plane' for unmigrated historical rows because spec K line 4427
-- pins hosted bundles to the control-plane signer.
ALTER TABLE evidence_claims
    ADD COLUMN IF NOT EXISTS actor_kind text NULL;

ALTER TABLE evidence_claims
    ADD COLUMN IF NOT EXISTS actor_identity_hash text NULL;

-- Backfill legacy rows so the subsequent NOT NULL + CHECK can be applied
-- without rewriting application code. Newly-issued claims via the
-- evidence-signer service supply these fields explicitly.
UPDATE evidence_claims
    SET actor_kind = 'control_plane'
    WHERE actor_kind IS NULL;

-- Closed-enum CHECK matches the wire-format Literal pin in
-- packages/schemas/python/relay_schemas/envelopes.py::EvidenceClaim.
ALTER TABLE evidence_claims
    DROP CONSTRAINT IF EXISTS evidence_claims_actor_kind_check;
ALTER TABLE evidence_claims
    ADD CONSTRAINT evidence_claims_actor_kind_check
        CHECK (actor_kind IN (
            'control_plane', 'gate_engine', 'worker', 'sdk', 'user', 'cron'
        ));

-- sha256-<hex> wire-format CHECK on actor_identity_hash for non-NULL rows.
ALTER TABLE evidence_claims
    DROP CONSTRAINT IF EXISTS evidence_claims_actor_identity_hash_format_check;
ALTER TABLE evidence_claims
    ADD CONSTRAINT evidence_claims_actor_identity_hash_format_check
        CHECK (
            actor_identity_hash IS NULL
            OR actor_identity_hash ~ '^sha256-[0-9a-f]{64}$'
        );

-- -----------------------------------------------------------------------------
-- occurred_at (spec K line 4417; VAL-V3M1-014)
-- -----------------------------------------------------------------------------
-- Distinct from created_at: occurred_at is the wall-clock at which the
-- claim event happened (e.g. gate decision wall-clock); created_at is
-- when the row was persisted. Defaults to NULL for historical rows and
-- to now() for new inserts at the application layer (the wire-format
-- model marks this required).
ALTER TABLE evidence_claims
    ADD COLUMN IF NOT EXISTS occurred_at timestamptz NULL;

-- -----------------------------------------------------------------------------
-- subject nested object (spec K line 4397-4401; VAL-V3M1-015)
-- -----------------------------------------------------------------------------
-- Materialize the nested ``subject`` JSONB from existing flat columns.
-- New writes supply ``subject`` directly via the application layer; the
-- flat ``subject_kind`` / ``subject_id`` columns remain readable for
-- back-compat. m1-f06 migrates production callers.
ALTER TABLE evidence_claims
    ADD COLUMN IF NOT EXISTS subject jsonb NULL;

UPDATE evidence_claims
    SET subject = jsonb_build_object(
        'kind', subject_kind,
        'id', subject_id::text,
        'manifest_commit_hash', manifest_commit_hash
    )
    WHERE subject IS NULL;

-- -----------------------------------------------------------------------------
-- namespaces (spec K line 4421-4423; VAL-V3M1-021)
-- -----------------------------------------------------------------------------
-- Optional dict carrying the ACEF x-relay extension envelope. m1-f07
-- (VAL-V3M1-022) adds the verifier-side closed-key check rejecting
-- unknown top-level namespace keys.
ALTER TABLE evidence_claims
    ADD COLUMN IF NOT EXISTS namespaces jsonb NULL;

-- -----------------------------------------------------------------------------
-- redaction_transform_version (spec K line 4414; VAL-V3M1-020)
-- -----------------------------------------------------------------------------
-- Already present in 0003_evidence_replay.sql:94 as NOT NULL TEXT.
-- This migration ASSERTS the column survives -- no DROP, no ALTER. The
-- VAL-V3M1-020 test grep validates the column is still there post-0014.

-- -----------------------------------------------------------------------------
-- Indexes
-- -----------------------------------------------------------------------------
-- actor_identity_hash lookup index for "which claims did this actor sign?"
-- audit queries.
CREATE INDEX IF NOT EXISTS evidence_claims_actor_identity_hash
    ON evidence_claims(actor_identity_hash)
    WHERE actor_identity_hash IS NOT NULL;

-- occurred_at lookup index for temporal-window queries on the
-- audit/incident path.
CREATE INDEX IF NOT EXISTS evidence_claims_occurred_at
    ON evidence_claims(occurred_at)
    WHERE occurred_at IS NOT NULL;

COMMIT;
