-- 0034_side_effect_markers_expires_at_canonical.sql
--
-- VAL-CANON-004 follow-up (2026-05-31): restore the index-backed range
-- scan of the worker-boot resurrection check
-- (relay_sidecar/side_effect_markers.py::scan_orphan_markers) WITHOUT
-- weakening the canon-004 correctness fix.
--
-- Background:
--   canon-004 fixed a real defect: ``expires_at`` was serialized with a
--   ``Z`` suffix (``_now_plus_seconds_iso``) while the resurrection cutoff
--   used a ``+00:00`` suffix (``_now_iso``). A lexicographic SQLite TEXT
--   compare (``expires_at < cutoff``) mis-ordered the two forms (``Z``
--   0x5A sorts after ``+`` 0x2B and ``.`` 0x2E), so an expired marker was
--   wrongly classified as live. The fix changed the query to
--   ``WHERE state = ?`` and re-compared in Python -- correct, but it
--   dropped the ``(state, expires_at)`` composite-index range bound and
--   pulled every in_flight marker into Python.
--
-- This follow-up makes ``expires_at`` (and the cutoff, in code) use ONE
-- canonical, lexicographically-sortable UTC form so the SQL
-- ``expires_at < cutoff`` compare is BOTH correct AND index-backed:
--
--   YYYY-MM-DDTHH:MM:SS.ffffff+00:00
--
-- (fixed width, microsecond precision, explicit ``+00:00`` offset). Every
-- value shares the same width and the same suffix, so SQLite's
-- lexicographic TEXT compare on the composite index sorts EXACTLY in
-- chronological order. The marker writer
-- (``_canonical_expires_at`` / ``_now_plus_seconds_iso``) now emits only
-- this form; the scan canonicalizes the cutoff to the same form and keeps
-- a Python ``_parse_iso_to_aware_utc`` re-check so any legacy /
-- non-canonical row remains correctly classified (SQL narrows by the
-- index; Python confirms). See side_effect_markers.py::_orphan_scan_sql.
--
-- What this migration does:
--   1. Normalizes EXISTING ``side_effect_markers.expires_at`` values to
--      the canonical form so legacy rows also benefit from the index
--      range bound (and are correct under the string compare). The
--      rewrite is LOSSLESS to microsecond precision -- it does NOT use
--      ``strftime('%f', ...)`` (which truncates to milliseconds). It
--      strips the timezone suffix, right-pads/truncates the fractional
--      seconds to exactly 6 digits, and re-appends ``+00:00``.
--   2. Confirms the ``(state, expires_at)`` composite index exists (it was
--      created in 0018_side_effects.sql; CREATE INDEX IF NOT EXISTS makes
--      this a no-op when present and self-heals a DB that somehow lacks
--      it).
--
-- SUPPORTED_SCHEMA_VERSION consistency (VAL-ISO-001): the schema version
-- is migration-count-driven (relay_sidecar/recovery.py::_count_migration_files).
-- Adding this 0034 file advances both ``SUPPORTED_SCHEMA_VERSION`` (the
-- count of shipped .sql files) and the live ``__schema_migrations`` row
-- count (one row recorded per applied file by db.py::_run_migrations) by
-- exactly one, so the recovery gate stays consistent with no hand-edited
-- constant.
--
-- Idempotency: the runner records this filename in ``__schema_migrations``
-- and skips it on subsequent restarts. The UPDATE is additionally
-- self-idempotent (it only rewrites rows not already in canonical form),
-- and CREATE INDEX IF NOT EXISTS is a no-op when the index is present.
--
-- The migration runner (db.py::_run_migrations) wraps every .sql file in a
-- BEGIN..COMMIT, and migration scripts MUST NOT issue their own
-- BEGIN/COMMIT (SQLite forbids nested transactions). This file therefore
-- contains only bare statements.
--
-- ASCII-only per CLAUDE.md "ASCII-Safe Source".

-- ---------------------------------------------------------------------------
-- Step 1: normalize existing expires_at to the canonical sortable form.
-- ---------------------------------------------------------------------------
-- LOSSLESS string canonicalization (microsecond precision preserved):
--   a. ``bt`` = value with a trailing 'Z'/'z' OR a '+00:00' offset
--      stripped, leaving date+time[.frac].
--   b. when ``bt`` has a fractional part: <seconds>.<frac padded/truncated
--      to 6>+00:00; else <seconds>.000000+00:00.
-- Only rows NOT already in canonical form are touched, so the pass is a
-- no-op on a fully-canonical table.

UPDATE side_effect_markers
SET expires_at = (
    WITH base AS (
        SELECT
            CASE
                WHEN expires_at LIKE '%Z' OR expires_at LIKE '%z'
                    THEN substr(expires_at, 1, length(expires_at) - 1)
                WHEN expires_at LIKE '%+00:00'
                    THEN substr(expires_at, 1, length(expires_at) - 6)
                ELSE expires_at
            END AS bt
    )
    SELECT
        CASE
            WHEN instr(bt, '.') > 0 THEN
                substr(bt, 1, instr(bt, '.') - 1) || '.' ||
                substr(substr(bt, instr(bt, '.') + 1) || '000000', 1, 6) ||
                '+00:00'
            ELSE
                bt || '.000000' || '+00:00'
        END
    FROM base
)
WHERE expires_at IS NOT NULL
  AND expires_at NOT GLOB
      '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]+00:00';

-- ---------------------------------------------------------------------------
-- Step 2: confirm the (state, expires_at) composite index exists.
-- ---------------------------------------------------------------------------
-- Created in 0018_side_effects.sql; this is a no-op when present and
-- self-heals a DB that somehow lacks it. The scan's index range bound
-- (state = ? AND expires_at < ?) depends on this index.

CREATE INDEX IF NOT EXISTS side_effect_markers_state
    ON side_effect_markers (state, expires_at);
