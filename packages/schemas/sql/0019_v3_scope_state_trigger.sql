-- 0019_v3_scope_state_trigger.sql
--
-- V3M3-F06 (2026-05-19): re-assert the spec section W deferred
-- CONSTRAINT TRIGGER that guarantees every scope-creating object row
-- is co-inserted with its matching scope_state row.
--
-- Spec authority (verbatim, section W line 5112):
--   "A creating transaction that inserts an object row without the
--    matching scope_state row fails the integrity check at commit
--    (a deferred trigger validates the join). This guarantees that
--    every object the state engine can address has a state row from
--    the moment it exists."
--
-- Audit finding being resolved
-- ----------------------------
-- The original install lives at packages/schemas/sql/0008_scope_state_extension.sql
-- (V2M01 W1.7). 0008 wraps each CONSTRAINT TRIGGER creation in a
-- ``DO $$ ... IF EXISTS information_schema.tables ... END$$`` guard
-- that silently skips trigger installation when the target table is
-- not yet present in the catalog.
--
-- At 0008 apply time the canonical Postgres profile defines only four
-- of the six scope-creating tables:
--
--   * runs              -- packages/schemas/sql/0000_v2_parent_tables.sql:71
--   * evidence_bundles  -- packages/schemas/sql/0003_evidence_replay.sql:36
--   * replay_cases      -- packages/schemas/sql/0003_evidence_replay.sql:113
--   * gate_rounds       -- packages/schemas/sql/0003a_canonical_run_results_and_gates.sql:194
--
-- Neither ``eval_runs`` nor ``releases`` is created by any
-- ``packages/schemas/sql/*.sql`` migration. The 0008 DO $$ guards for
-- those two scope_kinds therefore complete without raising and without
-- installing the constraint trigger. The text-level grep guard at
-- packages/schemas/python/tests/test_v2m01_scope_state_extension.py
-- line 337-368 only verifies that the migration MENTIONS each of the
-- six table names; it does not verify that the corresponding trigger
-- object exists in the live catalog. The audit caught this gap and
-- assigned VAL-V3M3-017 to close it.
--
-- What this migration does
-- ------------------------
-- 1. Creates ``eval_runs`` and ``releases`` stub tables (UUID PK only)
--    so the CONSTRAINT TRIGGER has a valid target to attach to. Full
--    DDL for these tables lands in their owning section A.AM (eval_runs) /
--    section Q.2 (releases) feature work later in the V3 buildout; the stub
--    is forward-compatible (later migrations may add columns via
--    ALTER TABLE, but the PK column name stays).
--
-- 2. Re-installs all five scope_state-paired CONSTRAINT TRIGGERs
--    unconditionally (no DO $$ guard) on runs, replay_cases,
--    evidence_bundles, eval_runs, releases. gate_rounds is already
--    covered by 0008's conditional install (the gate_rounds table
--    exists at 0008 apply time, so its DO $$ block succeeded) AND by
--    the sidecar precedent at apps/local-sidecar/migrations/0016 and
--    re-attach at 0029 -- no fresh install is required here.
--
-- 3. Preserves the shared trigger function
--    ``relay_scope_state_paired_row_check`` introduced by 0008. This
--    migration does NOT redefine the function; it only attaches new
--    CONSTRAINT TRIGGERs that EXECUTE FUNCTION it. The function body
--    remains the canonical 0008:215-245 definition.
--
-- 4. Is idempotent: every CREATE CONSTRAINT TRIGGER is preceded by
--    DROP TRIGGER IF EXISTS, and the eval_runs/releases stub tables
--    use CREATE TABLE IF NOT EXISTS.
--
-- Error path
-- ----------
-- A failing trigger raises ``RELAY-STATE-002`` (defined by 0008:236-242)
-- carrying the offending table name, scope_kind, and scope_id so the
-- application error envelope can match the canonical error code.
-- Because the trigger is DEFERRABLE INITIALLY DEFERRED the abort
-- happens at COMMIT, not at the INSERT statement -- the same
-- BEGIN..COMMIT block may insert the object row and the scope_state
-- row in either order.
--
-- Per CLAUDE.md keystone invariant #1 (control plane writes the
-- result): this migration adds integrity-guard machinery only; no
-- new write role is granted. The state-engine module remains the
-- only caller authorised to transition scope_state rows.
--
-- Per CLAUDE.md keystone invariant #10 (schema versioning): no
-- envelope wire format changes here.
--
-- ASCII-only per CLAUDE.md "ASCII-Safe Source".

-- ---------------------------------------------------------------------------
-- VAL-V3M3-017: stub tables for eval_runs and releases so the
-- CONSTRAINT TRIGGER has a valid attach target.
-- ---------------------------------------------------------------------------
--
-- These are forward-compatible PK-only stubs. Future feature work in
-- section A.AM and section Q.2 may add NOT NULL columns via ALTER TABLE; the
-- ``CREATE TABLE IF NOT EXISTS`` form prevents this migration from
-- clobbering a richer schema if it lands first.

CREATE TABLE IF NOT EXISTS eval_runs (
    eval_run_id uuid PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS releases (
    release_id uuid PRIMARY KEY
);

-- ---------------------------------------------------------------------------
-- VAL-V3M3-017: re-attach the scope_state-paired CONSTRAINT TRIGGER on
-- every scope-creating table that lacks a guaranteed live trigger
-- post-0008.
-- ---------------------------------------------------------------------------
--
-- The shared function ``relay_scope_state_paired_row_check`` is owned
-- by 0008 (lines 215-245). We invoke it here via EXECUTE FUNCTION
-- passing ``(scope_kind, pk_column)`` through TG_ARGV. The function
-- looks up scope_state(scope_kind, scope_id) and raises
-- ``RELAY-STATE-002`` when the join row is absent.
--
-- DEFERRABLE INITIALLY DEFERRED means the check fires at COMMIT time.
-- AFTER INSERT means it sees the post-insert NEW row image.
-- FOR EACH ROW means it fires once per object row, which is what the
-- scope_state pairing semantic requires (one object row -> one
-- scope_state row, one-to-one keyed by scope_id).

-- runs
DROP TRIGGER IF EXISTS runs_scope_state_paired_check ON runs;
CREATE CONSTRAINT TRIGGER runs_scope_state_paired_check
    AFTER INSERT ON runs
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW
    EXECUTE FUNCTION relay_scope_state_paired_row_check('run', 'run_id');

-- replay_cases
DROP TRIGGER IF EXISTS replay_cases_scope_state_paired_check ON replay_cases;
CREATE CONSTRAINT TRIGGER replay_cases_scope_state_paired_check
    AFTER INSERT ON replay_cases
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW
    EXECUTE FUNCTION relay_scope_state_paired_row_check('replay_case', 'replay_case_id');

-- evidence_bundles
DROP TRIGGER IF EXISTS evidence_bundles_scope_state_paired_check ON evidence_bundles;
CREATE CONSTRAINT TRIGGER evidence_bundles_scope_state_paired_check
    AFTER INSERT ON evidence_bundles
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW
    EXECUTE FUNCTION relay_scope_state_paired_row_check('evidence_bundle', 'evidence_bundle_id');

-- eval_runs
DROP TRIGGER IF EXISTS eval_runs_scope_state_paired_check ON eval_runs;
CREATE CONSTRAINT TRIGGER eval_runs_scope_state_paired_check
    AFTER INSERT ON eval_runs
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW
    EXECUTE FUNCTION relay_scope_state_paired_row_check('eval_run', 'eval_run_id');

-- releases
DROP TRIGGER IF EXISTS releases_scope_state_paired_check ON releases;
CREATE CONSTRAINT TRIGGER releases_scope_state_paired_check
    AFTER INSERT ON releases
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW
    EXECUTE FUNCTION relay_scope_state_paired_row_check('release', 'release_id');
