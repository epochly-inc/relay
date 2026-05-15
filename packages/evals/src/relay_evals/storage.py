"""SQLite migration loader and atomic transaction helper for evals.

This module is the SOLE SQL writer surface in ``packages/evals/``. Every
INSERT / UPDATE against ``eval_runs`` / ``eval_results`` /
``eval_run_deltas`` flows through ``eval_transaction`` here. Mirrors the
sidecar pattern at ``apps/local-sidecar/relay_sidecar/db.py:450-467``:
when the workspace-wide ``scripts/lint-no-bypass-primitives.py`` lands,
only this module needs to be whitelisted because the runner / delta
modules call into this surface rather than ``conn.execute`` directly.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

# packages/evals/src/relay_evals/storage.py
#   parents[0] == relay_evals
#   parents[1] == src
#   parents[2] == evals (the package root)
# migrations live at evals/migrations/.
_PACKAGE_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MIGRATIONS_DIR = _PACKAGE_ROOT / "migrations"


def apply_migrations(
    conn: sqlite3.Connection,
    *,
    migrations_dir: Path | None = None,
) -> list[str]:
    """Apply every .sql file under ``migrations_dir`` in lex order.

    Idempotent because every migration uses ``CREATE TABLE IF NOT
    EXISTS`` / ``CREATE INDEX IF NOT EXISTS``. Re-running on a populated
    database is a no-op for shape.

    Returns the list of applied migration filenames (sorted) for caller
    inspection.

    Raises:
        ``FileNotFoundError`` if ``migrations_dir`` is missing.
        ``sqlite3.OperationalError`` if a migration body is malformed.
    """
    if migrations_dir is None:
        migrations_dir = DEFAULT_MIGRATIONS_DIR
    if not migrations_dir.is_dir():
        raise FileNotFoundError(
            f"migrations directory not found: {migrations_dir}"
        )

    applied: list[str] = []
    for sql_file in sorted(migrations_dir.glob("*.sql")):
        sql_text = sql_file.read_text(encoding="utf-8")
        # executescript wraps the body in an implicit transaction and
        # commits on success. Per the CREATE TABLE IF NOT EXISTS shape,
        # a re-run is a no-op for tables that already exist.
        conn.executescript(sql_text)
        applied.append(sql_file.name)
    return applied


@contextmanager
def eval_transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """Atomic write context: BEGIN IMMEDIATE -> body -> COMMIT/ROLLBACK.

    If ``conn.in_transaction`` is already true on entry, this manager
    yields without starting a nested transaction; the outer caller is
    responsible for commit. This permits nested helpers without
    "cannot start a transaction within a transaction" errors.

    On any exception inside the body, ROLLBACK is issued before the
    exception re-raises.
    """
    if conn.in_transaction:
        # Outer caller owns the transaction lifecycle.
        yield conn
        return

    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.rollback()
        raise
    else:
        conn.commit()


def connect_memory() -> sqlite3.Connection:
    """Return an in-memory SQLite connection with sane defaults applied.

    Used by tests that don't need disk persistence. Enables
    foreign_keys (off by default in SQLite) and sets a short
    ``busy_timeout`` so deadlocks surface fast in tests.
    """
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn


def connect_file(path: Path) -> sqlite3.Connection:
    """Return a disk-backed SQLite connection with sane defaults applied."""
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn
