-- 0016_v3_schema_drift_fixes.sql
--
-- V3M1-F08 (2026-05-18): three canonical-Postgres schema-drift fixes
-- against the authoritative spec sections, per contract assertions
-- VAL-V3M1-023 and VAL-V3M1-024. (VAL-V3M1-025 is a header annotation
-- on apps/local-sidecar/migrations/0017_explain.sql and is not a DDL
-- change; it lands in the same V3M1-F08 commit.)
--
-- DRIFT #1 (VAL-V3M1-023) -- failed_assertion_ids type alignment.
--   Spec authority: planning/epochly-replay-spec.md line 2958 declares
--     failed_assertion_ids text[] not null default '{}'
--   Pre-fix DDL: packages/schemas/sql/0003a_canonical_run_results_and_gates.sql:98
--     failed_assertion_ids jsonb NOT NULL DEFAULT '[]'::jsonb
--   The historical jsonb form was a 0003a-era shortcut (the jsonb type
--   accepts an array literal '[]' without a USING-clause conversion).
--   The spec types this as text[] because every value in the column is
--   an assertion-id string -- the relational array type is the
--   semantically-precise choice and is what the §A.2 canonical form
--   declares.
--
--   The migration uses ALTER COLUMN ... TYPE text[] with a USING clause
--   that unwraps the existing jsonb array via jsonb_array_elements_text.
--   The default literal also flips from '[]'::jsonb to '{}'::text[].
--   Existing rows survive: any jsonb array of strings round-trips into
--   a text[] of the same elements; the empty jsonb array '[]' becomes
--   the empty text[] '{}'.
--
-- DRIFT #2 (VAL-V3M1-024) -- gate_rounds.initiated_by enum restriction.
--   Spec authority: planning/epochly-replay-spec.md §A.4 line 3035
--     initiated_by text not null check (initiated_by in
--       ('control_plane','cron','user','remediation'))
--   Pre-fix DDL: packages/schemas/sql/0003a_canonical_run_results_and_gates.sql:209-213
--     initiated_by text NOT NULL CHECK (initiated_by IN (
--       'control_plane','cron','user','remediation',
--       'submission','admin_override'))
--   The two widened values ('submission','admin_override') were carried
--   over from the sidecar 0009 mirror as a "union of both" shortcut at
--   audit-R3 time. The spec is the floor AND the ceiling for the
--   canonical Postgres profile; the SQL CHECK must mirror the spec
--   enum exactly. The wire-format Pydantic model at
--   packages/schemas/python/relay_schemas/envelopes.py:381 already
--   declares the 4-value Literal, so the SQL is the only layer drifted.
--
--   Data migration: any pre-existing row carrying 'submission' or
--   'admin_override' is rewritten to 'control_plane' (the closest spec
--   value semantically -- 'submission' meant "first round opened by
--   the submitter via the gate engine" and 'admin_override' meant
--   "round opened by an admin via the control plane"; both map cleanly
--   to 'control_plane'). The UPDATE runs BEFORE the new CHECK is
--   added so the ADD CONSTRAINT does not violate.
--
-- DRIFT #3 (VAL-V3M1-025) -- 0017_explain.sql supersession header.
--   No DDL change here; the annotation lands directly in
--   apps/local-sidecar/migrations/0017_explain.sql in the same commit.
--
-- Per CLAUDE.md keystone invariant #1 (control plane writes the
-- result): gate_decisions is and remains a control-plane-only table.
-- This migration changes a column type and a CHECK constraint; it
-- does NOT add or relax any role grants.
--
-- ASCII-only per CLAUDE.md "ASCII-Safe Source".

-- =============================================================================
-- DRIFT #1: gate_decisions.failed_assertion_ids jsonb -> text[]
-- =============================================================================

-- Flip the default first so the post-ALTER column carries the canonical
-- empty-array literal '{}' rather than the jsonb-flavoured '[]'.
ALTER TABLE gate_decisions
    ALTER COLUMN failed_assertion_ids DROP DEFAULT;

-- ALTER the column type with a USING clause that unwraps the jsonb
-- array into a text[]. jsonb_array_elements_text returns a setof text
-- (one row per element); ARRAY(SELECT ...) aggregates back into a
-- text[]. NULL inputs are not possible because the column was NOT NULL
-- before this migration (default '[]'::jsonb), but COALESCE is added
-- defensively in case a future row carried a SQL NULL despite NOT
-- NULL (e.g., during a partial restore).
ALTER TABLE gate_decisions
    ALTER COLUMN failed_assertion_ids
    SET DATA TYPE text[]
    USING (
        COALESCE(
            ARRAY(
                SELECT jsonb_array_elements_text(failed_assertion_ids)
            ),
            '{}'::text[]
        )
    );

-- Restore NOT NULL and re-apply the canonical default in text[] flavour.
ALTER TABLE gate_decisions
    ALTER COLUMN failed_assertion_ids SET DEFAULT '{}'::text[];

ALTER TABLE gate_decisions
    ALTER COLUMN failed_assertion_ids SET NOT NULL;

-- =============================================================================
-- DRIFT #2: gate_rounds.initiated_by 6-value enum -> spec 4-value enum
-- =============================================================================

-- Step 1: data-migrate pre-existing widened rows BEFORE adding the
-- restrictive CHECK. The pre-fix DDL at 0003a:210-213 named the CHECK
-- constraint implicitly (PostgreSQL auto-names it
-- gate_rounds_initiated_by_check by combining table + column + suffix).
-- We DROP that auto-named constraint and ADD a new explicitly-named
-- constraint so future migrations can find it.
UPDATE gate_rounds
SET initiated_by = 'control_plane'
WHERE initiated_by IN ('submission', 'admin_override');

-- Step 2: drop the widened CHECK constraint. The auto-generated name
-- from PostgreSQL is gate_rounds_initiated_by_check (table_column_check
-- pattern). IF EXISTS guards re-runs.
ALTER TABLE gate_rounds
    DROP CONSTRAINT IF EXISTS gate_rounds_initiated_by_check;

-- Step 3: add the spec-aligned 4-value CHECK with an explicit name.
ALTER TABLE gate_rounds
    ADD CONSTRAINT gate_rounds_initiated_by_check
    CHECK (initiated_by IN ('control_plane','cron','user','remediation'));
