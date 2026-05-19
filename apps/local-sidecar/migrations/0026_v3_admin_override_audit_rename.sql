-- 0026_v3_admin_override_audit_rename.sql
--
-- V3M1-F03 (2026-05-18): rename sidecar ``audit_log_entries`` ->
-- ``admin_override_audit`` (VAL-V3M1-005, VAL-V3M1-006).
--
-- Rationale (spec §V): the canonical hosted-plane name
-- ``audit_log_entries`` is reserved for the §V identity / org-level
-- audit table (deferred to private relay-platform per boundaries.md).
-- The sidecar's current ``audit_log_entries`` table is the
-- gate-admin override audit (writes from
-- packages/gate/src/relay_gate_engine/admin_actions.py for
-- admin.reopen / admin.terminate transitions). Renaming it now frees
-- the canonical §V name before the hosted plane lands.
--
-- The rename preserves every column, default, CHECK constraint, and
-- index from the 0011 + 0023 combined state byte-for-byte. After
-- audit-R3 dropped the ``schema_version`` column (0023 line 60), the
-- table carries 15 columns; this migration carries those 15 forward
-- under the new name.
--
-- SQLite has ``ALTER TABLE ... RENAME TO``, which would be the
-- minimal-change form. However, the table's CHECK constraints were
-- declared with names prefixed ``audit_log_entries_*``; a plain
-- RENAME leaves the constraint names referencing the OLD table name,
-- which (a) confuses operators reading the schema and (b) breaks the
-- test at packages/gate/tests/test_w8_4_admin_actions.py:696 which
-- asserts the constraint name ``audit_log_entries_reopen_reason_required``
-- appears in the IntegrityError text. The CREATE-COPY-DROP-RENAME
-- pattern (precedent: 0024_audit_r4_actors_kind_alignment.sql) lets
-- us rename the constraints alongside the table and update the
-- test's expected constraint name in the same V3M1-F03 batch.
--
-- The wrapping BEGIN..COMMIT mirrors the 0024 idiom. The migration
-- runner at apps/local-sidecar/relay_sidecar/db.py:638 itself opens
-- a BEGIN before invoking executescript(); aiosqlite's
-- executescript() implicitly COMMITs any pending transaction before
-- running the script (sqlite3 module behaviour), so the explicit
-- BEGIN..COMMIT here owns the atomic CREATE/COPY/DROP/RENAME
-- sequence and the runner's wrapper does not collide.
--
-- Idempotency: the runner records each .sql filename in
-- ``__schema_migrations`` and skips already-applied files
-- (db.py:580), so the non-IF-NOT-EXISTS destructive statements
-- (DROP TABLE / RENAME) run exactly once.
--
-- ASCII-only per CLAUDE.md "ASCII-Safe Source".

BEGIN;

-- ---------------------------------------------------------------------------
-- Step 1: create the new admin_override_audit table.
-- ---------------------------------------------------------------------------
--
-- Columns + defaults + CHECKs are preserved byte-for-byte from the
-- 0011 declaration (apps/local-sidecar/migrations/0011_gate_circuit_breaker.sql
-- lines 155-185) with the audit-R3 ``schema_version`` column dropped
-- (0023 line 60). CHECK constraint names are reprefixed
-- ``admin_override_audit_*`` to keep diagnostics aligned with the new
-- table name.

CREATE TABLE admin_override_audit (
    audit_id                TEXT    PRIMARY KEY NOT NULL,
    project_id              TEXT    NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    scope_type              TEXT    NOT NULL,
    scope_id                TEXT    NOT NULL,
    gate_id                 TEXT,
    action                  TEXT    NOT NULL,
    actor_kind              TEXT    NOT NULL,
    actor_identity_hash     TEXT    NOT NULL,
    actor_role              TEXT    NOT NULL,
    reason                  TEXT    NOT NULL DEFAULT '',
    prior_round_id          TEXT,
    new_round_id            TEXT,
    manifest_commit_hash    TEXT    NOT NULL,
    payload                 TEXT    NOT NULL DEFAULT '{}',
    occurred_at             TEXT    NOT NULL,
    CONSTRAINT admin_override_audit_scope_enum
        CHECK (scope_type IN ('run','replay','eval_run','release','domain_pack')),
    CONSTRAINT admin_override_audit_action_enum
        CHECK (action IN (
            'admin.reopen', 'admin.terminate', 'admin.pause',
            'admin.unpause', 'admin.override_command'
        )),
    CONSTRAINT admin_override_audit_actor_role_enum
        CHECK (actor_role IN ('org_owner', 'org_admin', 'member', 'service')),
    CONSTRAINT admin_override_audit_reason_max
        CHECK (length(reason) <= 2048),
    CONSTRAINT admin_override_audit_reopen_reason_required
        CHECK (action != 'admin.reopen' OR length(reason) > 0)
);

-- ---------------------------------------------------------------------------
-- Step 2: copy existing rows. Column order matches the source table
-- one-for-one so a positional INSERT preserves data.
-- ---------------------------------------------------------------------------

INSERT INTO admin_override_audit (
    audit_id,
    project_id,
    scope_type,
    scope_id,
    gate_id,
    action,
    actor_kind,
    actor_identity_hash,
    actor_role,
    reason,
    prior_round_id,
    new_round_id,
    manifest_commit_hash,
    payload,
    occurred_at
)
SELECT
    audit_id,
    project_id,
    scope_type,
    scope_id,
    gate_id,
    action,
    actor_kind,
    actor_identity_hash,
    actor_role,
    reason,
    prior_round_id,
    new_round_id,
    manifest_commit_hash,
    payload,
    occurred_at
FROM audit_log_entries;

-- ---------------------------------------------------------------------------
-- Step 3: drop the old table and recreate its indexes under the new name.
-- ---------------------------------------------------------------------------
--
-- The old indexes (``ix_audit_log_entries_scope`` and
-- ``ix_audit_log_entries_action``) vanish with the old table; recreate
-- them on admin_override_audit with the new prefix.

DROP TABLE audit_log_entries;

CREATE INDEX ix_admin_override_audit_scope
    ON admin_override_audit(scope_type, scope_id);

CREATE INDEX ix_admin_override_audit_action
    ON admin_override_audit(action, occurred_at);

COMMIT;
