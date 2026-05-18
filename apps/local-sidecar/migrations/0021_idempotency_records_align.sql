-- 0021_idempotency_records_align.sql
--
-- Audit fix (2026-05-17 whole-codebase audit, P0): align the sidecar
-- ``idempotency_records`` table with the canonical Postgres shape
-- declared at packages/schemas/sql/0002_control_plane.sql lines 107-126.
--
-- Spec anchors:
--   sectionA.12 lines 3216-3232   IdempotencyRecord canonical envelope
--   sectionB.2 lines 3517-3520    ULID (Crockford-base32, 26 chars) and
--                                 sha256-<hex> wire-format requirements
--   sectionB.7                    schema_version literal pin discipline
--
-- The legacy sidecar table (apps/local-sidecar/migrations/0019_idempotency_records.sql)
-- used a composite PK ``(key, surface)`` and was missing project_id,
-- schema_version, the ULID grammar CHECK on the key, and the
-- sha256-<hex> CHECK on the request_digest. None of those rows could
-- round-trip to canonical Postgres. This migration rebuilds the table
-- with the canonical shape while preserving the sidecar-specific
-- columns the runtime still needs for HTTP replay semantics
-- (``surface``, ``response_body``, ``response_headers``) as non-PK
-- informational columns.
--
-- Idempotency: this script is one-shot. The migration runner at
-- apps/local-sidecar/relay_sidecar/db.py _run_migrations records every
-- applied migration's filename in ``__schema_migrations`` and skips
-- already-applied files on subsequent sidecar restarts. The test
-- bootstrap helper at apps/local-sidecar/tests/_v2m02_w25_helpers.py
-- bootstrap_db mirrors the same tracker so test-fixture re-runs also
-- skip applied migrations. This frees the script to use ALTER/DROP/
-- RENAME without needing internal idempotency guards.
--
-- Data-migration policy:
--   Legacy rows are transient 24h HTTP idempotency-cache entries. Every
--   legacy row's ``request_digest`` carries the LEGACY ``sha256:<hex>``
--   colon-form prefix (set by the pre-fix ``runtime._digest_of_bytes``
--   helper), which fails the canonical ``sha256-<hex>`` CHECK. Even if
--   we copied legacy rows into the canonical table, every row would be
--   filtered out by the CHECK constraint. We therefore drop legacy
--   rows on first migration; the canonical state-engine
--   ``compare_and_set_state`` primitives still dedup the underlying
--   state transitions independently of the HTTP idempotency cache, so
--   at most one duplicate HTTP submission re-executes the success-path
--   response write -- no double-mutation, no canonical-layer drift.
--
-- ASCII-only per CLAUDE.md "ASCII-Safe Source".

-- ---------------------------------------------------------------------------
-- Atomicity: the migration runner (or the test bootstrap helper, which
-- mirrors it) wraps each migration's executescript AND the
-- ``__schema_migrations`` INSERT in a single explicit transaction
-- (BEGIN ... COMMIT), so a mid-migration crash rolls back the entire
-- rebuild AND the tracker record together. This script therefore does
-- NOT issue its own BEGIN/COMMIT: doing so would conflict with the
-- runner's outer transaction (SQLite raises "cannot start a transaction
-- within a transaction").
-- ---------------------------------------------------------------------------

-- ---------------------------------------------------------------------------
-- Step 1: drop the legacy table (transient 24h cache; safe to discard).
-- ---------------------------------------------------------------------------

DROP TABLE IF EXISTS idempotency_records;

-- ---------------------------------------------------------------------------
-- Step 2: create the canonical-shape table.
-- ---------------------------------------------------------------------------
--
-- SQLite has no native regex; the CHECK constraints use GLOB with the
-- character-class atoms expanded to the required length (26 atoms for
-- the ULID, 64 atoms for the sha256 hex tail).

CREATE TABLE idempotency_records (
    idempotency_key  TEXT    NOT NULL
        CHECK (idempotency_key GLOB '[0-9A-HJKMNP-TV-Z][0-9A-HJKMNP-TV-Z][0-9A-HJKMNP-TV-Z][0-9A-HJKMNP-TV-Z][0-9A-HJKMNP-TV-Z][0-9A-HJKMNP-TV-Z][0-9A-HJKMNP-TV-Z][0-9A-HJKMNP-TV-Z][0-9A-HJKMNP-TV-Z][0-9A-HJKMNP-TV-Z][0-9A-HJKMNP-TV-Z][0-9A-HJKMNP-TV-Z][0-9A-HJKMNP-TV-Z][0-9A-HJKMNP-TV-Z][0-9A-HJKMNP-TV-Z][0-9A-HJKMNP-TV-Z][0-9A-HJKMNP-TV-Z][0-9A-HJKMNP-TV-Z][0-9A-HJKMNP-TV-Z][0-9A-HJKMNP-TV-Z][0-9A-HJKMNP-TV-Z][0-9A-HJKMNP-TV-Z][0-9A-HJKMNP-TV-Z][0-9A-HJKMNP-TV-Z][0-9A-HJKMNP-TV-Z][0-9A-HJKMNP-TV-Z]'),
    schema_version   TEXT    NOT NULL DEFAULT 'relay.idempotency_record.v1'
        CHECK (schema_version = 'relay.idempotency_record.v1'),
    project_id       TEXT    NOT NULL,
    request_digest   TEXT    NOT NULL
        CHECK (request_digest GLOB 'sha256-[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]'),
    response_status  INTEGER NOT NULL
        CHECK (response_status >= 0),
    response_ref     TEXT,
    first_seen_at    TEXT    NOT NULL,
    expires_at       TEXT    NOT NULL,
    -- Sidecar-only informational columns (non-canonical, retained for
    -- HTTP-layer replay semantics).
    surface          TEXT,
    response_body    TEXT,
    response_headers TEXT    NOT NULL DEFAULT '{}',
    PRIMARY KEY (idempotency_key)
);

-- ---------------------------------------------------------------------------
-- Step 3: indexes on the canonical table.
-- ---------------------------------------------------------------------------

CREATE INDEX ix_idempotency_records_expires_at
    ON idempotency_records (expires_at);

CREATE INDEX ix_idempotency_records_project_first_seen
    ON idempotency_records (project_id, first_seen_at DESC);

CREATE INDEX ix_idempotency_records_surface
    ON idempotency_records (surface);
