"""W2.7 sidecar startup recovery + structured exit codes.

Invoked at lifespan startup BEFORE the SidecarDatabase is opened for
normal operation. Five responsibilities, mapping to VAL-W2-049..055:

  1. ``quick_check_with_budget`` -- run ``PRAGMA quick_check`` in a
     worker thread with a strict 2-second wall-clock budget. Returns
     ``("ok", None)``, ``("error", <stdout>)``, or ``("timeout", None)``.
     The fast-path check; clean DBs MUST complete inside the budget
     (VAL-W2-051 evidence).
  2. ``full_integrity_check`` -- the slow-path ``PRAGMA integrity_check``
     diagnostic. Runs only when the fast-path failed or timed out. No
     wall-clock bound -- diagnostic clarity takes precedence.
  3. ``recover_or_refuse`` -- top-level orchestrator. Runs the fast-path
     -> slow-path -> exit-code logic; emits ``sidecar.crash_recovered``
     on the recovery-success branch (after WAL replay completes). Exits
     with the appropriate structured error on the corruption /
     schema-mismatch / WAL-checkpoint-failure branches.
  4. ``recover_partial_lockfile`` -- VAL-W2-050 helper. Detects an
     orphan ``<lockfile>.tmp`` left by an interrupted atomic-rename
     (rare but possible if the process died after ``os.fsync`` but
     before ``os.replace``). Removes the orphan; the caller then
     proceeds through the four-state classifier as normal.
  5. ``emit_crash_recovery_event`` -- after WAL recovery has been
     observed (a known-clean ``PRAGMA quick_check`` AFTER the previous
     run crashed mid-transaction), writes ONE ``sidecar.crash_recovered``
     event_log row carrying the recovery summary (recovered transaction
     count, time spent, db path).

Exit codes (per spec P.1 mapping; contract.md preamble line 63-74):

  - exit 3 = corrupt (RELAY-SIDECAR-DB-CORRUPT)         -> VAL-W2-051
  - exit 5 = 5xx + network transient (also used for SCHEMA-VERSION-UNKNOWN
              per VAL-W2-054; see recovery contract anchor)
  - exit 6 = WAL/storage error (RELAY-SIDECAR-WAL-CHECKPOINT-FAILED) -> VAL-W2-053

Determinism: every recovery decision is logged via stderr JSON BEFORE
``sys.exit`` so subprocess-based tests can capture the structured
envelope without parsing log lines.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import contextlib
import json
import os
import sqlite3
import sys
import threading
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import NoReturn

from .errors import (
    RELAY_SIDECAR_DB_CORRUPT,
    RELAY_SIDECAR_DB_CORRUPT_CODE,
    RELAY_SIDECAR_SCHEMA_VERSION_UNKNOWN,
    RELAY_SIDECAR_SCHEMA_VERSION_UNKNOWN_CODE,
    RELAY_SIDECAR_WAL_CHECKPOINT_FAILED,
    RELAY_SIDECAR_WAL_CHECKPOINT_FAILED_CODE,
)

# Exit codes per spec P.1 (contract.md preamble line 63-74).
EXIT_CODE_DB_CORRUPT: int = 3
EXIT_CODE_SCHEMA_VERSION_UNKNOWN: int = 5
EXIT_CODE_WAL_CHECKPOINT_FAILED: int = 6

# Fast-path quick_check wall-clock budget (seconds). VAL-W2-051 evidence
# requires <= 2000 ms on a clean DB.
QUICK_CHECK_BUDGET_S: float = 2.0

# Default migrations directory, resolved relative to this module:
# ``<repo>/apps/local-sidecar/migrations``. Mirrors db.py's resolution
# (SidecarDatabase._run_migrations). Kept as a module-level constant so
# the schema-version derivation and the runner agree on the same set.
_DEFAULT_MIGRATIONS_DIR: Path = Path(__file__).resolve().parent.parent / "migrations"


def _shipped_migration_filenames(
    migrations_dir: Path = _DEFAULT_MIGRATIONS_DIR,
) -> set[str]:
    """Return the SET of ``*.sql`` migration filenames shipped with the binary.

    This is the authoritative SHIPPED set. It reuses the EXACT same glob the
    runner uses (``SidecarDatabase._run_migrations`` iterates
    ``sorted(migrations.glob("*.sql"))`` and records ``sql_file.name`` into
    ``__schema_migrations``), so the shipped set and the runner's applied
    set cannot drift apart in their notion of what a migration "is".

    Returns an empty set when the directory is absent (e.g. a packaged
    distribution that resolves the path differently); callers treat an
    empty shipped set as "cannot determine", never refusing on it.
    """
    if not migrations_dir.is_dir():
        return set()
    return {p.name for p in migrations_dir.glob("*.sql")}


def _count_migration_files(migrations_dir: Path = _DEFAULT_MIGRATIONS_DIR) -> int:
    """Return the number of ``*.sql`` migration files shipped with the binary.

    This is the LIVE, authoritative schema version: each new migration
    file advances it automatically with no hand-edited constant to forget
    (the prior frozen ``= 8`` was the root cause of VAL-ISO-001). The
    runner (``SidecarDatabase._run_migrations``) applies exactly these
    files in lex order and records each by filename in
    ``__schema_migrations``; the count of applied rows therefore equals
    this number on a fully-migrated DB.

    Retained for the LEGACY fallback path (``__schema_migrations`` absent),
    where only the numeric ``_sidecar_schema_version`` row is available and
    no filename set exists to compare. The primary drift decision is driven
    by ``_shipped_migration_filenames`` (the filename SET), which COUNT
    alone cannot express (a foreign filename can match the count yet differ
    in identity -- the codex-review schema-drift-filename-set fail-open).

    Falls back to ``0`` if the directory is absent (e.g. a packaged
    distribution that resolves the path differently); callers treat a
    derived supported version of 0 as "cannot determine", never refusing
    on it.
    """
    return len(_shipped_migration_filenames(migrations_dir))


# Schema version constant. LIVE, derived from the count of migration
# ``.sql`` files shipped with this binary (VAL-ISO-001). Previously this
# was frozen at the literal 8 while 25 later migrations existed, so a DB
# migrated past 0008 read observed=8 == SUPPORTED=8 and the drift went
# undetected. Driving it from the migration count means every new
# migration advances the supported version with no manual bump.
SUPPORTED_SCHEMA_VERSION: int = _count_migration_files()

# Sentinel UUIDs for sidecar-internal event_log rows (matches db.py
# convention for non-tenant observability rows).
_SENTINEL_PROJECT_ID: str = "00000000-0000-0000-0000-000000000000"
_SENTINEL_SCOPE_ID: str = "00000000-0000-0000-0000-000000000000"


def _now_rfc3339_utc() -> str:
    """RFC 3339 UTC timestamp with explicit ``Z`` offset."""
    return (
        datetime.now(tz=UTC)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def quick_check_with_budget(
    db_path: Path,
    *,
    budget_s: float = QUICK_CHECK_BUDGET_S,
) -> tuple[str, str | None]:
    """Run ``PRAGMA quick_check`` against ``db_path`` with a wall-clock budget.

    Args:
        db_path: Absolute path to the SQLite database file.
        budget_s: Wall-clock budget in seconds. Default 2.0 (VAL-W2-051).

    Returns:
        One of:
          - ``("ok", None)`` -- PRAGMA returned ``ok``.
          - ``("error", <result>)`` -- PRAGMA returned a non-ok value;
            <result> is the raw text from ``cur.fetchone()[0]``.
          - ``("timeout", None)`` -- the budget elapsed before the
            PRAGMA returned. The connection thread is left to finish
            naturally (best-effort) so we do not block startup forever.

    The PRAGMA runs in a worker thread because sqlite3 is synchronous
    and we need a true wall-clock timeout. Cancellation of the
    underlying sqlite3 query is impossible without ``conn.interrupt()``
    (which we DO call on timeout to encourage the worker to exit).
    """
    if not db_path.exists():
        # Empty DB path = no corruption to detect; treat as ok.
        return ("ok", None)

    result_holder: dict[str, object] = {"status": None, "value": None}
    completed = threading.Event()

    def _worker() -> None:
        try:
            conn = sqlite3.connect(str(db_path))
            try:
                cur = conn.execute("PRAGMA quick_check")
                row = cur.fetchone()
                value = row[0] if row else None
                if value == "ok":
                    result_holder["status"] = "ok"
                    result_holder["value"] = None
                else:
                    result_holder["status"] = "error"
                    result_holder["value"] = str(value) if value is not None else ""
            finally:
                with contextlib.suppress(Exception):
                    conn.close()
        except sqlite3.DatabaseError as e:
            # SQLite refused to even open (file not a database, etc.).
            result_holder["status"] = "error"
            result_holder["value"] = f"sqlite3.DatabaseError: {e}"
        except Exception as e:  # noqa: BLE001
            # Any other failure surfaces as error (file missing, permission).
            result_holder["status"] = "error"
            result_holder["value"] = f"{type(e).__name__}: {e}"
        finally:
            completed.set()

    worker_thread = threading.Thread(
        target=_worker,
        name="quick-check-budgeted",
        daemon=True,
    )
    worker_thread.start()
    completed.wait(timeout=budget_s)

    if not completed.is_set():
        # Timed out. Best-effort: do not block on the worker thread on
        # exit. Mark the holder so any late update from the worker
        # is ignored.
        return ("timeout", None)

    status = result_holder["status"]
    value = result_holder["value"]
    if status == "ok":
        return ("ok", None)
    if status == "error":
        return ("error", str(value) if value is not None else "")
    # Defensive: should not reach here if the worker set status.
    return ("error", "unknown quick_check outcome")


def full_integrity_check(db_path: Path) -> str:
    """Run ``PRAGMA integrity_check`` (untimed) and return the full output.

    Used as the slow-path diagnostic when ``quick_check_with_budget``
    returned ``error`` or ``timeout``. Returns a multi-line string when
    SQLite reports more than one integrity violation.

    Returns the literal string ``"ok"`` when the database passes, or a
    diagnostic string otherwise. Never raises -- a sqlite-side failure
    is captured as the diagnostic itself.
    """
    if not db_path.exists():
        return "missing-db-file"
    try:
        conn = sqlite3.connect(str(db_path))
        try:
            cur = conn.execute("PRAGMA integrity_check")
            rows = cur.fetchall()
        finally:
            with contextlib.suppress(Exception):
                conn.close()
    except sqlite3.DatabaseError as e:
        return f"sqlite3.DatabaseError: {e}"
    except Exception as e:  # noqa: BLE001
        return f"{type(e).__name__}: {e}"

    if not rows:
        return "no-output"
    if len(rows) == 1:
        return str(rows[0][0])
    # SQLite emits one row per integrity violation when it disagrees.
    return "\n".join(str(r[0]) for r in rows)


def recover_partial_lockfile(lockfile_path: Path) -> bool:
    """VAL-W2-050: detect and clear an orphan ``<lockfile>.tmp``.

    ``local_atomic_file_write`` writes to a sibling tempfile via
    ``tempfile.mkstemp(prefix=destination.name + ".", dir=parent)``
    and then ``os.replace(tmp, destination)``. If the process dies
    BETWEEN the fsync and the rename, the tmp file is left behind. The
    next ``acquire_or_attach`` MUST detect the orphan, remove it, and
    proceed normally. Detection: any file in the lockfile directory
    whose name starts with ``<lockfile-name>.`` (the mkstemp prefix).

    Returns True if at least one orphan was removed, False otherwise.

    Idempotent and safe to call before/after the four-state classifier.
    """
    parent = lockfile_path.parent
    if not parent.is_dir():
        return False
    prefix = lockfile_path.name + "."
    removed = False
    for entry in parent.iterdir():
        if entry.name == lockfile_path.name:
            continue
        if not entry.name.startswith(prefix):
            continue
        # Treat any file with the mkstemp prefix as an orphan tmp.
        with contextlib.suppress(OSError):
            entry.unlink()
            removed = True
    return removed


def _read_schema_version(db_path: Path) -> int | None:
    """Return the integer ``version`` from ``_sidecar_schema_version``.

    Returns ``None`` if the table does not yet exist (pristine DB created
    by an older sidecar without migration 0008) OR if the row is missing
    (empty table). Returns the raw integer otherwise -- the caller
    compares against ``SUPPORTED_SCHEMA_VERSION``.

    Never raises; SQL errors collapse to ``None``.
    """
    if not db_path.exists():
        return None
    try:
        conn = sqlite3.connect(str(db_path))
        try:
            # Probe the table existence first to keep the error path quiet
            # for pristine DBs.
            cur = conn.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name='_sidecar_schema_version'"
            )
            if cur.fetchone() is None:
                return None
            cur = conn.execute(
                "SELECT version FROM _sidecar_schema_version WHERE id = 0"
            )
            row = cur.fetchone()
            if row is None:
                return None
            return int(row[0])
        finally:
            with contextlib.suppress(Exception):
                conn.close()
    except sqlite3.DatabaseError:
        return None


def _read_applied_migration_filenames(db_path: Path) -> set[str] | None:
    """Return the SET of applied migration filenames in ``__schema_migrations``.

    ``__schema_migrations`` is the runner's authoritative record: it holds
    exactly one row per applied migration filename keyed on a
    ``filename TEXT PRIMARY KEY`` column (``SidecarDatabase._run_migrations``
    -- db.py:609-616). The SET of those filenames is the LIVE identity of
    the database's schema, and is what the recovery gate compares against
    the SHIPPED set -- NOT the row COUNT, which is identity-blind (a foreign
    filename can match the count yet differ in identity; the codex-review
    schema-drift-filename-set fail-open).

    Returns ``None`` when the ``__schema_migrations`` table is absent
    (pristine DB created before the runner, or a unit-test fixture that
    seeds only the legacy ``_sidecar_schema_version`` row); the caller then
    falls back to the legacy numeric ``_read_schema_version``. Returns an
    empty set when the table exists but holds no rows. Never raises; SQL
    errors collapse to ``None``.
    """
    if not db_path.exists():
        return None
    try:
        conn = sqlite3.connect(str(db_path))
        try:
            cur = conn.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name='__schema_migrations'"
            )
            if cur.fetchone() is None:
                return None
            cur = conn.execute("SELECT filename FROM __schema_migrations")
            return {str(row[0]) for row in cur.fetchall()}
        finally:
            with contextlib.suppress(Exception):
                conn.close()
    except sqlite3.DatabaseError:
        return None


def _read_applied_migration_count(db_path: Path) -> int | None:
    """Return the number of rows in the live ``__schema_migrations`` table.

    ``__schema_migrations`` is the runner's authoritative record: it holds
    exactly one row per applied migration filename
    (``SidecarDatabase._run_migrations``). The row count is therefore the
    LIVE schema version of the database, and is what VAL-ISO-001 requires
    the recovery gate to surface against -- not the frozen
    ``_sidecar_schema_version`` row, which migration 0008 seeds with
    INSERT OR IGNORE and which no later migration ever advances.

    Retained for the ``schema_version`` summary field and the envelope's
    ``observed_version`` (a human-facing count). The drift DECISION is now
    made on the filename SET (``_read_applied_migration_filenames`` vs
    ``_shipped_migration_filenames``), which COUNT cannot express.

    Returns ``None`` when the ``__schema_migrations`` table is absent
    (pristine DB created before the runner, or a unit-test fixture that
    seeds only the legacy row); the caller then falls back to the legacy
    ``_read_schema_version``. Never raises; SQL errors collapse to
    ``None``.
    """
    applied = _read_applied_migration_filenames(db_path)
    if applied is None:
        return None
    return len(applied)


def _read_observed_schema_version(db_path: Path) -> int | None:
    """Resolve the database's observed schema version, LIVE source first.

    Precedence (VAL-ISO-001):
      1. The count of applied migrations in ``__schema_migrations`` -- the
         runner's authoritative live record.
      2. Fallback to the legacy ``_sidecar_schema_version`` row only when
         ``__schema_migrations`` is absent (pre-runner DBs and unit-test
         fixtures that seed only the legacy row).
      3. ``None`` (pristine DB) when neither source is present; the caller
         tolerates this because the lifespan startup then runs migrations.
    """
    live = _read_applied_migration_count(db_path)
    if live is not None:
        return live
    return _read_schema_version(db_path)


def emit_crash_recovery_event(
    db_path: Path,
    *,
    summary: dict[str, object],
) -> bool:
    """Write ONE ``sidecar.crash_recovered`` event_log row.

    Called by ``recover_or_refuse`` after WAL recovery has demonstrably
    completed (the post-recovery integrity check returned ``ok`` AND the
    previous shutdown left a crash-marker file, or the WAL file at
    startup contained uncheckpointed frames). Writes through a fresh
    short-lived ``sqlite3.connect`` rather than the asyncio writer
    queue (which is not yet open at this point in the lifespan).

    Per W2.5 ``event_log_entries`` constraints (migration 0007), the row
    MUST set ``schema_version='relay.event_log_entry.v1'``. The CHECK
    constraint and append-only triggers honour any role -- this insert
    runs under the default ``relay_state_engine`` role which is
    permitted to INSERT (the no-update / no-delete triggers do not
    apply to INSERT).

    Returns True on success, False on best-effort failure (caller does
    not block startup on a missed forensic row).
    """
    if not db_path.exists():
        return False
    event_id = str(uuid.uuid4())
    occurred_at = _now_rfc3339_utc()
    payload = json.dumps(
        {
            "summary": summary,
            "recovery_kind": "wal_replay",
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    try:
        conn = sqlite3.connect(str(db_path))
        try:
            conn.execute("PRAGMA busy_timeout = 5000")
            conn.execute("BEGIN IMMEDIATE")
            try:
                cur = conn.execute(
                    "SELECT COALESCE(MAX(ingest_sequence), -1) + 1 "
                    "FROM event_log_entries"
                )
                next_seq_row = cur.fetchone()
                next_seq = int(next_seq_row[0]) if next_seq_row is not None else 0
                conn.execute(
                    "INSERT INTO event_log_entries ("
                    "  event_id, schema_version, project_id, scope_type, "
                    "  scope_id, event_type, actor_kind, payload, "
                    "  occurred_at, ingest_sequence, event_kind"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        event_id,
                        "relay.event_log_entry.v1",
                        _SENTINEL_PROJECT_ID,
                        "other",
                        _SENTINEL_SCOPE_ID,
                        "sidecar.crash_recovered",
                        "control_plane",
                        payload,
                        occurred_at,
                        next_seq,
                        "sidecar_crash_recovered",
                    ),
                )
                conn.execute("COMMIT")
            except BaseException:
                with contextlib.suppress(Exception):
                    conn.execute("ROLLBACK")
                raise
        finally:
            with contextlib.suppress(Exception):
                conn.close()
    except (sqlite3.DatabaseError, sqlite3.IntegrityError):
        return False
    return True


def exit_with_structured_error(
    code: int,
    error_envelope: dict[str, object],
) -> NoReturn:
    """Emit ``error_envelope`` as a single JSON line to stderr; sys.exit(code).

    The JSON form lets subprocess-based tests parse the envelope without
    splitting log lines. The envelope is single-line JSON terminated by
    a newline so readers can split on ``\\n`` safely.
    """
    line = json.dumps(error_envelope, sort_keys=True, separators=(",", ":"))
    sys.stderr.write(line + "\n")
    sys.stderr.flush()
    sys.exit(code)


def _wal_present_with_frames(db_path: Path) -> bool:
    """Return True if a sibling ``<db>-wal`` (or preserved sentinel) exists.

    Used as the heuristic for "the previous run crashed mid-transaction
    and left WAL frames behind". A clean shutdown via the W2.6 quiesce
    protocol always runs ``PRAGMA wal_checkpoint(TRUNCATE)`` which
    truncates the WAL to size 0 (or removes the file entirely). A
    non-zero WAL at startup therefore implies the previous run did NOT
    shut down gracefully.

    W2.7 VAL-W2-053: when the previous run's checkpoint failed, the
    lifespan tear-down copies the WAL bytes to ``<db>-wal.preserved``
    BEFORE closing connections (sqlite would otherwise remove the WAL
    on the last connection close). We therefore inspect both paths.
    """
    candidates = [
        db_path.parent / (db_path.name + "-wal"),
        db_path.parent / (db_path.name + "-wal.preserved"),
    ]
    for candidate in candidates:
        if not candidate.exists():
            continue
        try:
            if candidate.stat().st_size > 0:
                return True
        except OSError:
            continue
    return False


def recover_or_refuse(db_path: Path) -> dict[str, object]:
    """Top-level startup recovery orchestrator.

    Sequence:

      1. Detect whether WAL recovery will run on the next ``sqlite3.connect``
         (heuristic: ``<db>-wal`` exists with size > 0).
      2. Run ``quick_check_with_budget`` (fast-path).
      3. On error or timeout: run ``full_integrity_check`` and exit 3.
      4. On ok: open the database briefly to trigger WAL replay (sqlite
         performs replay automatically on the first connection that
         opens the journal in read+write mode).
      5. Re-run ``quick_check_with_budget`` after WAL replay to confirm
         the post-recovery state is also clean.
      6. Read the LIVE schema version (``__schema_migrations`` count,
         legacy ``_sidecar_schema_version`` row as fallback) and compare
         to ``SUPPORTED_SCHEMA_VERSION`` (the migration-file count).
         Refuse (exit 5) ONLY when the DB is AHEAD of the binary
         (``observed > supported``): that is a genuine DOWNGRADE -- a
         newer binary applied migrations this older binary cannot undo
         (no down-migrations exist; destructive ALTER/DROP/RENAME
         migrations would leave this binary referencing a schema it does
         not understand). A DB BEHIND the binary (``observed < supported``)
         is the NORMAL UPGRADE path: the binary ships migrations not yet
         applied, so boot proceeds and ``SidecarDatabase.open`` ->
         ``_run_migrations`` reconciles the count to ``supported``
         (VAL-ISO-001, schema-drift upgrade-gate fix).
      7. If WAL was present at startup, emit a single
         ``sidecar.crash_recovered`` event_log row.

    Returns a structured summary dict on success (no exit). Calls
    ``exit_with_structured_error`` (NoReturn) on the failure paths.

    The returned dict carries:
      - ``recovery_invoked``: True if WAL replay ran.
      - ``quick_check_status``: "ok" | "error" | "timeout".
      - ``quick_check_elapsed_s``: float wall-clock for the fast-path.
      - ``schema_version``: the integer read from the DB.
      - ``crash_recovery_event_written``: True if the row landed.
    """
    started_at = time.monotonic()
    wal_indicates_crash = _wal_present_with_frames(db_path)

    # Step 2: fast-path quick_check.
    qc_start = time.monotonic()
    qc_status, qc_payload = quick_check_with_budget(db_path)
    qc_elapsed = time.monotonic() - qc_start

    if qc_status != "ok":
        # Step 3: slow-path diagnostic + exit.
        diagnostic = full_integrity_check(db_path)
        envelope = {
            "code": RELAY_SIDECAR_DB_CORRUPT_CODE,
            "error_class": RELAY_SIDECAR_DB_CORRUPT,
            "message": (
                "sidecar refuses to start: SQLite database failed integrity check"
            ),
            "details": {
                "db_path": str(db_path),
                "quick_check_status": qc_status,
                "quick_check_payload": qc_payload,
                "integrity_check": diagnostic,
                "quick_check_elapsed_s": qc_elapsed,
            },
        }
        exit_with_structured_error(EXIT_CODE_DB_CORRUPT, envelope)

    # Step 4: open the DB briefly to trigger WAL replay (sqlite does this
    # automatically on the first read+write open). The connection close
    # below leaves the WAL file in whatever state SQLite considers
    # canonical post-replay.
    if wal_indicates_crash:
        try:
            conn = sqlite3.connect(str(db_path))
            with contextlib.suppress(Exception):
                conn.execute("PRAGMA journal_mode=WAL")
                # Touching the DB (cheap PRAGMA) ensures the journal
                # replay path runs.
                conn.execute("PRAGMA wal_checkpoint(PASSIVE)").fetchall()
            with contextlib.suppress(Exception):
                conn.close()
        except sqlite3.DatabaseError:
            # If WAL replay itself fails, the slow-path will catch it.
            pass

    # Step 5: schema-drift gate (VAL-W2-054 + VAL-ISO-001 + codex-review
    # schema-drift-filename-set).
    #
    # The drift DECISION is driven by the migration-filename SET, NOT the
    # row COUNT. COUNT is identity-blind: a production DB can have
    # ``COUNT(__schema_migrations) == SUPPORTED`` while one applied row is
    # a FOREIGN/UNKNOWN migration filename and one shipped migration is
    # absent. The count matches, the old directional ``observed >
    # supported`` check sees ``observed == supported`` and PASSES, and the
    # OLD binary boots against an UNKNOWN schema -- a fail-open. The
    # filename-set comparison closes it and SUBSUMES the directional count
    # check.
    #
    #   - ``applied - shipped`` NON-EMPTY -> the DB has migrations this
    #     binary does NOT ship (a newer binary's migration, a foreign /
    #     out-of-band migration, or a genuine downgrade). There are no
    #     down-migrations and destructive ALTER/DROP/RENAME migrations
    #     leave this binary facing a schema it does not understand. REFUSE
    #     (exit 5 / RELAY-SIDECAR-SCHEMA-VERSION-UNKNOWN).
    #   - ``applied`` is a SUBSET of (or equal to) ``shipped`` -> the DB is
    #     BEHIND-or-CURRENT. The NORMAL UPGRADE path: the binary ships
    #     migrations not yet applied. Proceed so ``SidecarDatabase.open``
    #     -> ``_run_migrations`` applies the pending migrations and
    #     reconciles the live set to ``shipped``. Do NOT refuse.
    #
    # ``observed_version`` (a human-facing COUNT) is still surfaced in the
    # summary and the refuse envelope for diagnostics, but it is NOT the
    # decision input.
    observed_version = _read_observed_schema_version(db_path)
    applied_migrations = _read_applied_migration_filenames(db_path)

    if applied_migrations is not None:
        # LIVE filename-set path: ``__schema_migrations`` is present.
        # ``shipped`` is the SET of ``*.sql`` files this binary carries,
        # enumerated by the SAME glob the runner uses, so the two notions
        # of "a migration" cannot drift. An empty shipped set means the
        # migrations dir could not be located (packaged-distribution edge
        # case); we cannot determine drift, so we never refuse on it.
        shipped_migrations = _shipped_migration_filenames()
        unknown_migrations = applied_migrations - shipped_migrations
        if shipped_migrations and unknown_migrations:
            envelope = {
                "code": RELAY_SIDECAR_SCHEMA_VERSION_UNKNOWN_CODE,
                "error_class": RELAY_SIDECAR_SCHEMA_VERSION_UNKNOWN,
                "message": (
                    "sidecar refuses to start: database has applied "
                    "migrations this binary does not ship (foreign / ahead "
                    "of binary); no down-migrations exist"
                ),
                "details": {
                    "db_path": str(db_path),
                    "observed_version": observed_version,
                    "supported_version": SUPPORTED_SCHEMA_VERSION,
                    "unknown_migrations": sorted(unknown_migrations),
                },
            }
            exit_with_structured_error(
                EXIT_CODE_SCHEMA_VERSION_UNKNOWN, envelope
            )
    elif (
        observed_version is not None
        and SUPPORTED_SCHEMA_VERSION > 0
        and observed_version > SUPPORTED_SCHEMA_VERSION
    ):
        # LEGACY numeric fallback: ``__schema_migrations`` is absent, so the
        # filename set is unavailable and only the numeric
        # ``_sidecar_schema_version`` row exists (pre-runner DBs and
        # unit-test fixtures that seed only the legacy row, VAL-W2-054).
        # We keep the DIRECTIONAL count check here: ``observed > supported``
        # is the AHEAD/downgrade case and still refuses (exit 5);
        # ``observed <= supported`` proceeds so the runner reconciles.
        envelope = {
            "code": RELAY_SIDECAR_SCHEMA_VERSION_UNKNOWN_CODE,
            "error_class": RELAY_SIDECAR_SCHEMA_VERSION_UNKNOWN,
            "message": (
                "sidecar refuses to start: database schema is AHEAD of this "
                "binary (downgrade); no down-migrations exist"
            ),
            "details": {
                "db_path": str(db_path),
                "observed_version": observed_version,
                "supported_version": SUPPORTED_SCHEMA_VERSION,
            },
        }
        exit_with_structured_error(EXIT_CODE_SCHEMA_VERSION_UNKNOWN, envelope)

    # Step 7: crash-recovery forensic row (only on the recovery branch).
    crash_event_written = False
    if wal_indicates_crash and observed_version is not None:
        # Only attempt the row if migrations have run before -- a
        # pristine DB has no event_log_entries table yet.
        summary = {
            "db_path": str(db_path),
            "quick_check_elapsed_s": qc_elapsed,
            "wal_size_at_startup": _wal_size(db_path),
            "started_at": _now_rfc3339_utc(),
            "total_recovery_elapsed_s": time.monotonic() - started_at,
        }
        crash_event_written = emit_crash_recovery_event(db_path, summary=summary)

    return {
        "recovery_invoked": wal_indicates_crash,
        "quick_check_status": qc_status,
        "quick_check_elapsed_s": qc_elapsed,
        "schema_version": observed_version,
        "crash_recovery_event_written": crash_event_written,
    }


def _wal_size(db_path: Path) -> int:
    """Return the on-disk size of the ``<db>-wal`` file (0 if absent)."""
    wal_path = db_path.parent / (db_path.name + "-wal")
    try:
        return wal_path.stat().st_size if wal_path.exists() else 0
    except OSError:
        return 0


def emit_wal_checkpoint_failed_and_exit(
    db_path: Path,
    *,
    underlying_error: str,
) -> NoReturn:
    """Emit ``RELAY-SIDECAR-WAL-CHECKPOINT-FAILED`` + exit 6 (VAL-W2-053).

    Called from the lifespan tear-down when ``PRAGMA wal_checkpoint(TRUNCATE)``
    fails (e.g., a reader holds an old snapshot beyond the timeout).
    Per VAL-W2-053 the WAL file MUST be preserved (do NOT delete) so
    the next-startup WAL replay path recovers cleanly.

    Note: the caller is responsible for NOT calling
    ``database.close()`` between the failed checkpoint and this exit;
    aiosqlite's close path may delete the WAL on a clean shutdown of
    its connections. The contract is: keep the WAL on disk.
    """
    wal_path = db_path.parent / (db_path.name + "-wal")
    envelope = {
        "code": RELAY_SIDECAR_WAL_CHECKPOINT_FAILED_CODE,
        "error_class": RELAY_SIDECAR_WAL_CHECKPOINT_FAILED,
        "message": (
            "sidecar shutdown: PRAGMA wal_checkpoint(TRUNCATE) failed; "
            "WAL preserved for next-startup recovery"
        ),
        "details": {
            "db_path": str(db_path),
            "wal_path": str(wal_path),
            "wal_present": wal_path.exists(),
            "wal_size_bytes": _wal_size(db_path),
            "underlying_error": underlying_error,
        },
    }
    exit_with_structured_error(EXIT_CODE_WAL_CHECKPOINT_FAILED, envelope)


__all__ = [
    "EXIT_CODE_DB_CORRUPT",
    "EXIT_CODE_SCHEMA_VERSION_UNKNOWN",
    "EXIT_CODE_WAL_CHECKPOINT_FAILED",
    "QUICK_CHECK_BUDGET_S",
    "SUPPORTED_SCHEMA_VERSION",
    "emit_crash_recovery_event",
    "emit_wal_checkpoint_failed_and_exit",
    "exit_with_structured_error",
    "full_integrity_check",
    "quick_check_with_budget",
    "recover_or_refuse",
    "recover_partial_lockfile",
]


# Suppress unused-import noise.
_ = os
