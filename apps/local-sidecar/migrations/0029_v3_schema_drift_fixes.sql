-- 0029_v3_schema_drift_fixes.sql
--
-- V3M1-F08 (2026-05-18): sidecar SQLite mirror of
-- packages/schemas/sql/0016_v3_schema_drift_fixes.sql. Locks in the
-- spec-aligned shapes on the OSS SQLite profile for contract
-- assertions VAL-V3M1-023 and VAL-V3M1-024. (VAL-V3M1-025 is a
-- header-only annotation on apps/local-sidecar/migrations/0017_explain.sql
-- and is not part of this DDL migration.)
--
-- DRIFT #1 (VAL-V3M1-023) -- failed_assertion_ids cross-tier mapping.
--   Spec authority: planning/epochly-replay-spec.md line 2958 types
--   gate_decisions.failed_assertion_ids as text[]. SQLite has no
--   native array type; the OSS sidecar mirror at
--   apps/local-sidecar/migrations/0003_gate_decisions.sql:24 declares
--   the column as TEXT with default '[]'.
--
--   Cross-tier mapping (DOCUMENTED -- no DDL change on this side):
--     * Postgres canonical (0016_v3_schema_drift_fixes.sql):
--         text[] not null default '{}'
--     * Sidecar SQLite     (0003_gate_decisions.sql:24):
--         TEXT not null default '[]' interpreted as a comma-separated
--         list when non-empty.
--   The Pydantic wire-format envelope at
--   packages/schemas/python/relay_schemas/envelopes.py:269 declares
--   list[str] which is the type both tiers serialize to and from. The
--   application layer is the source of truth for the list semantics;
--   the SQL-tier difference is purely a storage choice driven by
--   SQLite's lack of an array type. Test assertion VAL-V3M1-023 confirms
--   the cross-tier equivalence via the source-level DDL inspection.
--
--   NB: the historical '[]' default chosen by 0003 is JSON-flavoured
--   because the original mirror parsed the column as JSON in the
--   application layer; the comma-separated convention is the
--   forward-going contract per the cross-tier mapping above and is
--   what new readers should expect when joining the column directly.
--   We do NOT rewrite the default here -- existing rows already carry
--   '[]' and the application layer accepts either form.
--
-- DRIFT #2 (VAL-V3M1-024) -- gate_rounds.initiated_by enum restriction.
--   Spec authority: planning/epochly-replay-spec.md §A.4 line 3035
--   declares the 4-value enum {control_plane, cron, user, remediation}.
--   The sidecar 0009_gate_decision_writer.sql:127,132-133 declares a
--   3-value enum {submission, remediation, admin_override} with default
--   'submission'. SQLite cannot ALTER an existing CHECK constraint in
--   place; the migration uses the canonical rename-rebuild-drop idiom
--   (the same pattern 0023_audit_r3_schema_alignment.sql:128-174 uses
--   for root_cause_hypotheses):
--
--     1. RENAME the existing table to a temporary name. The OLD CHECK
--        travels with the table to the new name; we do NOT attempt an
--        in-place UPDATE because the OLD CHECK does not allow
--        'control_plane' as a value, so a pre-rebuild UPDATE would
--        fail with CHECK constraint failed.
--     2. CREATE the new gate_rounds with the spec-aligned 4-value
--        CHECK and default 'control_plane'.
--     3. INSERT SELECT all rows from the renamed-old table into the
--        new, using a CASE expression that rewrites widened values
--        ('submission','admin_override') to 'control_plane' AT INSERT
--        TIME. The INSERT is validated against the NEW table's CHECK
--        (which accepts the rewritten values).
--     4. DROP the renamed-old table.
--     5. Recreate ix_gate_rounds_scope (the index attached to the
--        renamed-old table was dropped along with that table in
--        step 4).
--
--   The application layer at
--   packages/schemas/python/relay_schemas/envelopes.py:381 already
--   declares the 4-value Literal. The CASE-driven data migration
--   rewrites 'submission' (first-round submission) and 'admin_override'
--   (admin-forced restart) to 'control_plane' (the closest spec value
--   semantically -- both events are initiated by the control plane).
--
-- Per CLAUDE.md keystone invariant #1 (control plane writes the
-- result): gate_decisions and gate_rounds remain control-plane-only.
-- This migration changes a CHECK constraint via table rebuild; it
-- does NOT add or relax any application-layer write paths. The
-- _allowed_tables() allowlist in db.py already includes both tables.
--
-- Per CLAUDE.md keystone invariant #8 (atomic primitives): SQLite
-- DDL operations bypass the four atomic primitives by design (DDL is
-- the migration runner's job, not the application's), so this
-- migration runs through apps/local-sidecar/relay_sidecar/db.py
-- :_run_migrations under the migration runner's exclusive lock. The
-- single-writer queue (transactional_db_write_raw) is not used for
-- DDL; the precedent is 0023's identical DROP-CREATE pattern.
--
-- Idempotency: the migration runner at db.py:580 applies each
-- migration exactly once and records the filename in
-- __schema_migrations, so the non-idempotent RENAME / INSERT SELECT /
-- DROP statements are safe.
--
-- ASCII-only per CLAUDE.md "ASCII-Safe Source".

-- =============================================================================
-- DRIFT #1: failed_assertion_ids -- DOCUMENTATION ONLY.
-- =============================================================================
--
-- No DDL change on the SQLite side. The cross-tier mapping
-- (Postgres text[] -- comma-separated TEXT on SQLite, list[str] in
-- Pydantic) is documented in the migration header above. The
-- source-level cross-tier alignment is asserted by
-- packages/schemas/python/tests/test_v3m1_schema_drift_fixes.py
-- VAL-V3M1-023 sidecar mapping test.

-- =============================================================================
-- DRIFT #2: gate_rounds.initiated_by -- rebuild table with 4-value CHECK.
-- =============================================================================

-- Step 1: rename the existing table out of the way. The OLD CHECK at
-- 0009:132-133 travels with the table; we do NOT UPDATE in place
-- because the OLD CHECK does not allow 'control_plane'.
ALTER TABLE gate_rounds RENAME TO gate_rounds__pre_v3m1_f08;

-- Step 2: create the new gate_rounds with the spec-aligned 4-value
-- CHECK and default 'control_plane'. Column order, types, and the
-- other CHECK constraints exactly mirror the 0009 declaration so the
-- rebuild is shape-preserving aside from the CHECK we are tightening
-- and the default we are flipping.
CREATE TABLE gate_rounds (
    gate_round_id          TEXT    PRIMARY KEY NOT NULL,
    schema_version         TEXT    NOT NULL DEFAULT 'relay.gate_round.v1',
    scope_type             TEXT    NOT NULL,
    scope_id               TEXT    NOT NULL,
    round                  INTEGER NOT NULL,
    initiated_by           TEXT    NOT NULL DEFAULT 'control_plane',
    restart_predecessor    TEXT,
    gate_decision_id       TEXT,
    opened_at              TEXT    NOT NULL,
    closed_at              TEXT,
    CONSTRAINT gate_rounds_initiated_by_enum
        CHECK (initiated_by IN ('control_plane','cron','user','remediation')),
    CONSTRAINT gate_rounds_round_positive
        CHECK (round >= 1),
    CONSTRAINT gate_rounds_scope_enum
        CHECK (scope_type IN ('run','replay','eval_run','release','domain_pack')),
    UNIQUE(scope_type, scope_id, round)
);

-- Step 3: copy all rows from the renamed-old table into the new,
-- rewriting widened values to the closest spec value at INSERT time.
-- The CASE expression maps:
--   'submission'      -> 'control_plane'  (first-round opens by the
--                                          control-plane gate engine)
--   'admin_override'  -> 'control_plane'  (admin-forced restart via
--                                          the control plane)
--   'remediation'     -> 'remediation'    (spec-aligned; passes through)
-- The INSERT is validated against the NEW table's CHECK and succeeds
-- for every rewritten value.
INSERT INTO gate_rounds (
    gate_round_id, schema_version, scope_type, scope_id, round,
    initiated_by, restart_predecessor, gate_decision_id,
    opened_at, closed_at
)
SELECT
    gate_round_id,
    schema_version,
    scope_type,
    scope_id,
    round,
    CASE initiated_by
        WHEN 'submission'     THEN 'control_plane'
        WHEN 'admin_override' THEN 'control_plane'
        ELSE initiated_by
    END AS initiated_by,
    restart_predecessor,
    gate_decision_id,
    opened_at,
    closed_at
FROM gate_rounds__pre_v3m1_f08;

-- Step 4: drop the renamed-old table. The index ix_gate_rounds_scope
-- attached to the renamed-old table is dropped along with it.
DROP TABLE gate_rounds__pre_v3m1_f08;

-- Step 5: recreate the index that lived on the original table
-- (ix_gate_rounds_scope from 0009:141-142).
CREATE INDEX IF NOT EXISTS ix_gate_rounds_scope
    ON gate_rounds(scope_type, scope_id, round);
