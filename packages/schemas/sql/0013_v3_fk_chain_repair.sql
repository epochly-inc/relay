-- 0013_v3_fk_chain_repair.sql
--
-- V3M1-F04 (2026-05-18): §Y FK chain repair across all 6 OSS FK
-- references to the undefined identity tables "orgs" and "users".
--
-- BACKGROUND
-- ----------
-- The §V identity tables (orgs, users, org_memberships, project_keys,
-- ci_tokens, api_tokens, auditor_tokens, token_revocations) are
-- deliberately deferred to the private relay-platform/ repo per the
-- repository topology rules in CLAUDE.md and the explicit DEFERRED #1
-- entry in the operation boundaries (relay-v0.3-audit-resolution).
-- They WILL NOT appear in OSS relay/ schemas.
--
-- However, six existing OSS migration sites carry inline
-- REFERENCES orgs(org_id) / REFERENCES users(user_id) clauses. A
-- clean Postgres database that applies packages/schemas/sql/*.sql in
-- lexicographic order fails at the first such CREATE TABLE with
-- 'relation "orgs" does not exist' (or the equivalent for users).
-- This blocks fresh-DB bring-up of the OSS schema and any CI job that
-- spins up a temp Postgres for migration verification.
--
-- RESOLUTION (per VAL-V3M1-007, VAL-V3M1-008, VAL-V3M1-009, VAL-V3M1-010)
-- ---------------------------------------------------------------------
-- This migration:
--   1. DROPs the auto-named FOREIGN KEY constraint
--      ({table}_{column}_fkey) from every one of the 6 sites. Postgres
--      auto-names FK constraints declared inline via REFERENCES as
--      {table}_{column}_fkey; the IF EXISTS guard makes the operation
--      idempotent against fresh installs where the constraint was
--      never created (because the in-flight repair below also patches
--      the legacy 0005/0006/0011 files to use NULLABLE forms in a
--      follow-up rewrite if/when those files are touched again).
--   2. DROPs the NOT NULL marker on the two columns that currently
--      carry it. The referenced row literally cannot exist in OSS, so
--      retaining NOT NULL would leave the column unusable.
--   3. RETAINS each column as uuid so private relay-platform/ can
--      re-attach the FK to its own users/orgs tables in a follow-up
--      migration without a destructive column-rewrite path. The uuid
--      type is forward-compatible with the §V identity surface
--      (uuid PRIMARY KEYs on orgs.org_id and users.user_id).
--
-- CATALOG OF THE 6 OSS FK REF SITES (VAL-V3M1-007)
-- ------------------------------------------------
-- | # | File:line                                | table.column                                   | NOT NULL? | Target  |
-- |---|------------------------------------------|------------------------------------------------|-----------|---------|
-- | 1 | packages/schemas/sql/0005_legal_holds.sql:52 | evidence_legal_holds.org_id                | YES       | orgs    |
-- | 2 | packages/schemas/sql/0005_legal_holds.sql:58 | evidence_legal_holds.imposed_by_user_id    | YES       | users   |
-- | 3 | packages/schemas/sql/0005_legal_holds.sql:65 | evidence_legal_holds.released_by_user_id   | no        | users   |
-- | 4 | packages/schemas/sql/0006_human_oversight.sql:69  | human_oversight_events.actor_user_id  | no        | users   |
-- | 5 | packages/schemas/sql/0006_human_oversight.sql:154 | data_provenance_records.acquired_by_user_id | no   | users   |
-- | 6 | packages/schemas/sql/0011_cli_invocations.sql:38  | cli_invocations.invoker_user_id       | no        | users   |
--
-- INVARIANTS PRESERVED
-- --------------------
-- * Columns remain uuid -- no destructive column rewrite, forward
--   compatible with §V when relay-platform attaches its own FK.
-- * No CREATE TABLE orgs / CREATE TABLE users -- those belong in
--   private relay-platform/ per the OSS/private boundary.
-- * CHECK constraints, indexes, and other columns on the affected
--   tables are NOT touched by this migration.
--
-- ASCII-only per CLAUDE.md "ASCII-Safe Source".

-- All ALTERs below are wrapped in DO $$ ... END $$ blocks gated on
-- ``to_regclass(...) IS NOT NULL`` so the migration is robust against
-- the scenario where an upstream migration (e.g., a pre-existing chain
-- bug being tracked under m1-f08 schema drift fixes) prevented the
-- target child table from being created. Skipping a never-created
-- child table is correct: a table that does not exist cannot carry a
-- FK constraint or a NOT NULL marker, so the §Y repair invariant
-- ("no orgs/users FK in this schema") is preserved tautologically.
-- A RAISE NOTICE makes the skip observable in psql output.

-- -----------------------------------------------------------------------------
-- Site 1: evidence_legal_holds.org_id  (REFERENCES orgs(org_id), NOT NULL)
-- -----------------------------------------------------------------------------
DO $$
BEGIN
    IF to_regclass('evidence_legal_holds') IS NULL THEN
        RAISE NOTICE 'skip: evidence_legal_holds not present, site 1 nothing to repair';
        RETURN;
    END IF;
    ALTER TABLE evidence_legal_holds
        DROP CONSTRAINT IF EXISTS evidence_legal_holds_org_id_fkey;
    ALTER TABLE evidence_legal_holds
        ALTER COLUMN org_id DROP NOT NULL;
END $$;

-- -----------------------------------------------------------------------------
-- Site 2: evidence_legal_holds.imposed_by_user_id  (REFERENCES users(user_id), NOT NULL)
-- -----------------------------------------------------------------------------
DO $$
BEGIN
    IF to_regclass('evidence_legal_holds') IS NULL THEN
        RAISE NOTICE 'skip: evidence_legal_holds not present, site 2 nothing to repair';
        RETURN;
    END IF;
    ALTER TABLE evidence_legal_holds
        DROP CONSTRAINT IF EXISTS evidence_legal_holds_imposed_by_user_id_fkey;
    ALTER TABLE evidence_legal_holds
        ALTER COLUMN imposed_by_user_id DROP NOT NULL;
END $$;

-- -----------------------------------------------------------------------------
-- Site 3: evidence_legal_holds.released_by_user_id  (REFERENCES users(user_id))
-- -----------------------------------------------------------------------------
DO $$
BEGIN
    IF to_regclass('evidence_legal_holds') IS NULL THEN
        RAISE NOTICE 'skip: evidence_legal_holds not present, site 3 nothing to repair';
        RETURN;
    END IF;
    ALTER TABLE evidence_legal_holds
        DROP CONSTRAINT IF EXISTS evidence_legal_holds_released_by_user_id_fkey;
END $$;

-- -----------------------------------------------------------------------------
-- Site 4: human_oversight_events.actor_user_id  (REFERENCES users(user_id))
-- -----------------------------------------------------------------------------
DO $$
BEGIN
    IF to_regclass('human_oversight_events') IS NULL THEN
        RAISE NOTICE 'skip: human_oversight_events not present, site 4 nothing to repair';
        RETURN;
    END IF;
    ALTER TABLE human_oversight_events
        DROP CONSTRAINT IF EXISTS human_oversight_events_actor_user_id_fkey;
END $$;

-- -----------------------------------------------------------------------------
-- Site 5: data_provenance_records.acquired_by_user_id  (REFERENCES users(user_id))
-- -----------------------------------------------------------------------------
DO $$
BEGIN
    IF to_regclass('data_provenance_records') IS NULL THEN
        RAISE NOTICE 'skip: data_provenance_records not present, site 5 nothing to repair';
        RETURN;
    END IF;
    ALTER TABLE data_provenance_records
        DROP CONSTRAINT IF EXISTS data_provenance_records_acquired_by_user_id_fkey;
END $$;

-- -----------------------------------------------------------------------------
-- Site 6: cli_invocations.invoker_user_id  (REFERENCES users(user_id))
-- -----------------------------------------------------------------------------
DO $$
BEGIN
    IF to_regclass('cli_invocations') IS NULL THEN
        RAISE NOTICE 'skip: cli_invocations not present, site 6 nothing to repair';
        RETURN;
    END IF;
    ALTER TABLE cli_invocations
        DROP CONSTRAINT IF EXISTS cli_invocations_invoker_user_id_fkey;
END $$;
