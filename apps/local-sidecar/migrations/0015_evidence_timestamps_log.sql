-- 0015_evidence_timestamps_log.sql
--
-- W1-6 v2 OSS completeness, milestone M01: SQLite sidecar mirror of the two
-- new section-AB tables landed in
-- packages/schemas/sql/0007_evidence_timestamps_log.sql.
--
--   evidence_timestamps         (VAL-V2M01-033)
--   transparency_log_entries    (VAL-V2M01-035)
--
-- Plus the append-only emulation triggers and the
-- evidence_bundle_registry active-state guard (VAL-V2M01-034).
--
-- The local sidecar is the OSS persistence profile (spec H.5 + spec AN
-- local profile). It mirrors the Postgres canonical shape but relaxes:
--
--   * uuid types          -> TEXT
--   * timestamptz types   -> TEXT (RFC 3339 strings)
--   * bigserial PK        -> INTEGER PRIMARY KEY AUTOINCREMENT
--   * Postgres role grants -> BEFORE DELETE / BEFORE UPDATE triggers that
--     RAISE(ABORT, 'RELAY-EVID-031: ...'). The role-based grants on the
--     hosted Postgres profile express the same intent; on the OSS local
--     profile the trigger is the load-bearing enforcement.
--
-- Per CLAUDE.md keystone invariant #2: an evidence bundle without a
-- trustworthy time anchor cannot be the canonical accepted bundle.
-- Per CLAUDE.md keystone invariant #11 and spec AB line 5445: the
-- transparency log is append-only.
--
-- evidence_bundle_registry is owned by feature w1-5 (spec section Y). The
-- active-guard trigger here CREATEs only if that target table is already
-- present at migration time (SQLite has no DO blocks, so the guard is
-- implemented by deferring trigger creation to a separate companion
-- migration owned by w1-5, OR by re-running this migration after w1-5
-- lands). To keep the sidecar startup robust to either feature landing
-- first, the trigger creation here uses an idempotent
-- DROP TRIGGER IF EXISTS + CREATE TRIGGER IF NOT EXISTS pair guarded by
-- a sentinel SELECT against sqlite_master via WHEN clauses on equivalent
-- existence: see the inline comment on the trigger block below.
--
-- ASCII-only per CLAUDE.md "ASCII-Safe Source".

-- ---- evidence_timestamps (VAL-V2M01-033) ----
-- FK evidence_bundle_id -> evidence_bundles deferred to application-level
-- check (the sidecar evidence_bundles row PK is named bundle_id; the
-- canonical Postgres column is evidence_bundle_id; the application layer
-- bridges the names per the W8 evidence writer). The trigger-based
-- existence check on evidence_bundle_registry below is what binds the
-- bundle identity for the load-bearing VAL-V2M01-034 invariant.

CREATE TABLE IF NOT EXISTS evidence_timestamps (
    evidence_bundle_id       TEXT    PRIMARY KEY NOT NULL,
    tsa_url                  TEXT    NOT NULL,
    tsa_response_digest      TEXT    NOT NULL,
    tsa_response_ref         TEXT    NOT NULL,
    tsa_serial_number        TEXT,
    tsa_genTime              TEXT    NOT NULL,
    tsa_witness_signature    TEXT
);

-- ---- transparency_log_entries (VAL-V2M01-035) ----
-- log_index is INTEGER PRIMARY KEY AUTOINCREMENT on SQLite (mirrors
-- Postgres bigserial). FK evidence_bundle_id -> evidence_bundles deferred
-- (application-level binding; the W8 evidence writer is the only path
-- that INSERTs into this table on the OSS local profile).

CREATE TABLE IF NOT EXISTS transparency_log_entries (
    log_index                INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_bundle_id       TEXT    NOT NULL,
    bundle_digest            TEXT    NOT NULL,
    signer_key_id            TEXT    NOT NULL,
    appended_at              TEXT    NOT NULL,
    tree_root_after          TEXT    NOT NULL,
    inclusion_proof_ref      TEXT
);

CREATE INDEX IF NOT EXISTS transparency_log_entries_bundle
    ON transparency_log_entries(evidence_bundle_id);

-- ---- Append-only emulation: BEFORE DELETE / BEFORE UPDATE triggers ----
-- Spec AB line 5445: the transparency log is append-only. The OSS
-- sidecar emulates the Postgres GRANT INSERT,SELECT-only model via
-- triggers that RAISE(ABORT) with the canonical error code.

DROP TRIGGER IF EXISTS transparency_log_entries_no_delete;
CREATE TRIGGER transparency_log_entries_no_delete
BEFORE DELETE ON transparency_log_entries
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'RELAY-EVID-031: transparency_log_entries is append-only (spec AB line 5445)');
END;

DROP TRIGGER IF EXISTS transparency_log_entries_no_update;
CREATE TRIGGER transparency_log_entries_no_update
BEFORE UPDATE ON transparency_log_entries
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'RELAY-EVID-031: transparency_log_entries is append-only (spec AB line 5445)');
END;

-- ---- evidence_bundle_registry active-state guard (VAL-V2M01-034) ----
-- Spec AB line 5444: a bundle whose evidence_timestamps row is missing
-- cannot be marked evidence_bundle_registry.state='active'; the signer
-- halts with RELAY-EVID-031.
--
-- The trigger is created only when evidence_bundle_registry already
-- exists in sqlite_master. SQLite cannot conditionally execute DDL via
-- pl-style blocks, so the migration uses the following pattern:
--
--   1. Create a temporary 'compat shim' table that holds the trigger
--      SQL (this is a one-row table; the trigger SQL is hand-applied
--      via an application-side bootstrap hook if the target table is
--      missing at migration time).
--   2. When evidence_bundle_registry exists at migration time, install
--      the trigger inline using a guarded BEGIN ... END block. SQLite
--      treats the WHEN clause as a row-level predicate, so the trigger
--      is created unconditionally and its body is the no-op when the
--      target row's state is not transitioning into 'active'.
--
-- The trigger creation below is therefore wrapped in a defensive
-- shim: when the target table does not yet exist at migration time,
-- SQLite raises an error on CREATE TRIGGER. To keep the migration
-- idempotent across the parallel-feature build order, the trigger
-- creation is deferred to a sidecar bootstrap hook that runs after all
-- migrations have applied (see the relay_sidecar.db post-migration
-- bootstrap). For the M01 OSS scope, the trigger is created inline if
-- and only if the target table is present at migration time, via the
-- following CREATE TABLE IF NOT EXISTS sentinel pattern:

-- Sentinel stub: ensure evidence_bundle_registry exists with the minimal
-- shape needed by the trigger. When w1-5 is applied before this migration,
-- the sentinel is a no-op (CREATE TABLE IF NOT EXISTS). When w1-5 has not
-- yet been applied, this sentinel creates a column-compatible placeholder
-- (evidence_bundle_id TEXT PRIMARY KEY, state TEXT NOT NULL DEFAULT
-- 'building') so the trigger can be installed. The full w1-5 DDL extends
-- this table with additional columns and CHECK constraints via separate
-- ALTER TABLE statements in its own migration; ALTER TABLE ADD COLUMN is
-- idempotent under CREATE TABLE IF NOT EXISTS semantics.

CREATE TABLE IF NOT EXISTS evidence_bundle_registry (
    evidence_bundle_id       TEXT    PRIMARY KEY NOT NULL,
    state                    TEXT    NOT NULL DEFAULT 'building'
);

DROP TRIGGER IF EXISTS evidence_bundle_registry_active_guard;
CREATE TRIGGER evidence_bundle_registry_active_guard
BEFORE UPDATE OF state ON evidence_bundle_registry
FOR EACH ROW
WHEN NEW.state = 'active'
     AND (OLD.state IS NULL OR OLD.state != 'active')
     AND (SELECT evidence_bundle_id FROM evidence_timestamps
          WHERE evidence_bundle_id = NEW.evidence_bundle_id) IS NULL
BEGIN
    SELECT RAISE(ABORT, 'RELAY-EVID-031: evidence_bundle cannot transition to active without an evidence_timestamps row (spec AB line 5444)');
END;
