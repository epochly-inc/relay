-- 0007_evidence_timestamps_log.sql
--
-- v0.2 OSS completeness, milestone M01, feature w1-6 scope: canonical
-- Postgres DDL for the two section-AB tables (trusted timestamping and
-- transparency log) surfaced by the 2026-05-16 spec audit as missing from
-- public relay/.
--
--   evidence_timestamps         (spec AB lines 5421-5429; VAL-V2M01-033)
--   transparency_log_entries    (spec AB lines 5431-5439; VAL-V2M01-035)
--
-- Plus the load-bearing invariant from spec AB line 5444:
--
--   A bundle whose evidence_timestamps row is missing cannot be marked
--   evidence_bundle_registry.state='active'; signer halts with
--   RELAY-EVID-031 (VAL-V2M01-034).
--
-- Per CLAUDE.md keystone invariant #2 ("Pass without evidence is not a
-- pass."), an evidence bundle without a trustworthy time anchor cannot be
-- the canonical accepted bundle. The trigger here enforces that invariant
-- at the persistence layer.
--
-- Per CLAUDE.md keystone invariant #11 (Trust anchor is the commercial
-- moat) and spec AB line 5445, the transparency log is append-only. The
-- application role grants are INSERT,SELECT only; no DELETE / UPDATE.
-- Admin tooling lives in private relay-platform/ and uses a separate
-- superuser-equivalent role under signed change control; it is not
-- granted via this file.
--
-- evidence_bundle_registry is owned by feature w1-5 (spec section Y; SQL
-- DDL at packages/schemas/sql/0007_legal_holds_and_registry.sql per the
-- contract preamble, or its successor). The active-guard trigger here is
-- gated on the target table existing (DO $$ ... IF EXISTS ... END$$);
-- running this migration in isolation against a fresh database where
-- evidence_bundle_registry is not yet present skips trigger creation
-- without error. When w1-5 lands, re-running this migration absorbs the
-- trigger.
--
-- ASCII-only per CLAUDE.md "ASCII-Safe Source".

-- -----------------------------------------------------------------------------
-- evidence_timestamps (spec AB lines 5421-5429; VAL-V2M01-033)
-- -----------------------------------------------------------------------------
--
-- One row per evidence bundle that has been timestamped by an RFC 3161
-- TSA. tsa_genTime is the parsed genTime from the TSA's TimeStampResp
-- (CMS SignerInfo); the canonical .tsr blob lives at tsa_response_ref
-- (R2 object on hosted; ~/.relay/evidence/<bundle>/timestamp.tsr on
-- local). tsa_response_digest is the sha256 over the canonical .tsr
-- bytes so verifiers can detect mutation. tsa_witness_signature is the
-- optional log-witness countersignature per spec AB line 5418 / Sigstore
-- Rekor convention.

CREATE TABLE evidence_timestamps (
    evidence_bundle_id uuid PRIMARY KEY
        REFERENCES evidence_bundles(evidence_bundle_id),
    tsa_url text NOT NULL,
    tsa_response_digest text NOT NULL,
    tsa_response_ref text NOT NULL,
    tsa_serial_number text,
    tsa_genTime timestamptz NOT NULL,
    tsa_witness_signature text
);

-- -----------------------------------------------------------------------------
-- transparency_log_entries (spec AB lines 5431-5439; VAL-V2M01-035)
-- -----------------------------------------------------------------------------
--
-- Append-only log of (bundle, digest, signer_key, time) tuples inspired
-- by Sigstore Rekor (spec AB line 5418). tree_root_after is the Merkle
-- root after this append; inclusion_proof_ref points at the served proof
-- JSON (R2 object on hosted; local file on OSS sidecar). log_index is
-- the canonical 1-based bigserial index.
--
-- Append-only enforcement:
--   1. Postgres path: REVOKE DELETE, UPDATE from PUBLIC; GRANT
--      INSERT, SELECT to the canonical application role. Admin tooling
--      that mutates the log lives in private relay-platform/ and uses a
--      separate superuser role gated by change control.
--   2. Sidecar SQLite path: BEFORE DELETE / BEFORE UPDATE triggers
--      abort with RELAY-EVID-031 (mirror migration
--      apps/local-sidecar/migrations/0015_evidence_timestamps_log.sql).

CREATE TABLE transparency_log_entries (
    log_index bigserial PRIMARY KEY,
    evidence_bundle_id uuid NOT NULL
        REFERENCES evidence_bundles(evidence_bundle_id),
    bundle_digest text NOT NULL,
    signer_key_id text NOT NULL,
    appended_at timestamptz NOT NULL DEFAULT now(),
    tree_root_after text NOT NULL,
    inclusion_proof_ref text
);

CREATE INDEX transparency_log_entries_bundle
    ON transparency_log_entries(evidence_bundle_id);

-- Append-only role grants. The canonical application role is named
-- 'relay_evidence_writer' (the runtime role is created by the hosted
-- ops bootstrap; on the OSS local profile the role grants are no-ops
-- because the sidecar runs as the database owner and the trigger-based
-- append-only enforcement in the sidecar mirror is what binds). The
-- grant block here is wrapped in a DO $$ block so absence of the role
-- on a fresh database does not abort the migration.
DO $$
BEGIN
    -- Revoke DELETE / UPDATE from PUBLIC first so they cannot be
    -- silently inherited. The transparency log is strictly append-only
    -- per spec AB line 5445 and CLAUDE.md keystone invariant #11.
    REVOKE DELETE, UPDATE ON transparency_log_entries FROM PUBLIC;
    IF EXISTS (
        SELECT 1 FROM pg_roles WHERE rolname = 'relay_evidence_writer'
    ) THEN
        GRANT INSERT, SELECT ON transparency_log_entries
            TO relay_evidence_writer;
        GRANT USAGE, SELECT ON SEQUENCE transparency_log_entries_log_index_seq
            TO relay_evidence_writer;
    END IF;
END$$;

-- -----------------------------------------------------------------------------
-- evidence_bundle_registry active-state guard (spec AB line 5444; VAL-V2M01-034)
-- -----------------------------------------------------------------------------
--
-- A bundle whose evidence_timestamps row is missing cannot be marked
-- evidence_bundle_registry.state='active'; the signer halts with
-- RELAY-EVID-031.
--
-- The guard is a BEFORE UPDATE trigger on evidence_bundle_registry that
-- fires only when the target state is 'active' and the predecessor
-- state was not 'active'. It checks for a matching evidence_timestamps
-- row by evidence_bundle_id and RAISEs with the canonical error code.
--
-- The trigger creation is gated on evidence_bundle_registry existing
-- because that table is created by feature w1-5 (spec section Y). When
-- w1-5 lands before this migration runs, the trigger is created
-- inline; when this migration runs first, the trigger is skipped and a
-- companion check in w1-5's migration (or in a re-run of this file)
-- absorbs it.

CREATE OR REPLACE FUNCTION evidence_bundle_registry_require_timestamp()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    -- Only fires for transitions INTO the 'active' state.
    IF NEW.state = 'active'
       AND (OLD.state IS NULL OR OLD.state <> 'active')
    THEN
        IF NOT EXISTS (
            SELECT 1 FROM evidence_timestamps
            WHERE evidence_bundle_id = NEW.evidence_bundle_id
        ) THEN
            RAISE EXCEPTION 'RELAY-EVID-031: evidence_bundle % cannot transition to active without an evidence_timestamps row (spec AB line 5444)',
                NEW.evidence_bundle_id
                USING ERRCODE = 'check_violation';
        END IF;
    END IF;
    RETURN NEW;
END
$$;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_name = 'evidence_bundle_registry'
    ) THEN
        -- Drop any pre-existing trigger of the same name so re-running
        -- this migration is idempotent.
        EXECUTE 'DROP TRIGGER IF EXISTS evidence_bundle_registry_active_guard ON evidence_bundle_registry';
        EXECUTE 'CREATE TRIGGER evidence_bundle_registry_active_guard '
            || 'BEFORE UPDATE OF state ON evidence_bundle_registry '
            || 'FOR EACH ROW '
            || 'EXECUTE FUNCTION evidence_bundle_registry_require_timestamp()';
    END IF;
END$$;
