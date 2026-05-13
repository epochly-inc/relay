"""``transactional_db_write`` (atomic-persistence primitive #2).

Per CLAUDE.md keystone invariant #8 + spec H: the only sanctioned write
path for canonical SQLite rows in the local sidecar. Direct
``conn.execute("INSERT ...")`` outside the writer queue is a banned
pattern.

Behavior contract:

  - Submits the write request to the active ``SidecarDatabase``'s
    single-writer asyncio queue.
  - The writer coroutine opens ``BEGIN IMMEDIATE``, executes the
    parameterised INSERT, commits.
  - On ``SQLITE_BUSY``: exponential backoff (20ms, 40ms, 80ms, 160ms,
    320ms, 640ms; capped at 1000ms; total <= busy_timeout window 5000ms).
    Each retry emits one observable
    ``event_log_entries(event_kind='sqlite_busy_retry')`` row carrying
    ``(attempt_number, backoff_ms, scope_id, sql_statement_digest)``.
  - After exhaustion: raises ``RelaySQLiteBusyExhausted`` (mapped to HTTP
    503 by the FastAPI exception handler).
  - Idempotency: a non-None ``idempotency_key`` deduplicates writes on
    ``(scope_id, idempotency_key)``. The second call returns the first
    row's ``ingest_sequence`` with ``WriteResult.idempotent=True``.

This module exposes:

  - The async function ``transactional_db_write`` (module-level entry
    point). Requires a ``SidecarDatabase`` instance to be registered via
    ``set_active_database()`` -- the FastAPI lifespan does this in
    ``runtime.py`` during startup.
  - The ``WriteResult`` dataclass.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from typing import Any

from ..db import SidecarDatabase, WriteResult, build_event_log_row

# Module-level active database registry. The FastAPI lifespan sets this on
# startup and clears it on shutdown. Tests construct their own
# SidecarDatabase and register it via ``set_active_database``.
_active_database: SidecarDatabase | None = None


def set_active_database(db: SidecarDatabase | None) -> None:
    """Register (or clear) the process-wide SidecarDatabase instance."""
    global _active_database
    _active_database = db


def get_active_database() -> SidecarDatabase:
    """Return the active SidecarDatabase. Raises if not registered."""
    if _active_database is None:
        raise RuntimeError(
            "transactional_db_write: no active SidecarDatabase registered; "
            "call set_active_database(db) (handled by FastAPI lifespan in "
            "production)."
        )
    return _active_database


async def transactional_db_write(
    *,
    table: str,
    row: dict[str, Any],
    scope_id: str,
    idempotency_key: str | None = None,
) -> WriteResult:
    """Atomic single-row write through the sidecar's writer queue.

    Args:
        table: SQLite table name. Currently supported: ``event_log_entries``.
        row: Column -> value map. ``ingest_sequence`` and
            ``idempotency_key`` are added by the primitive itself; do
            NOT supply them here.
        scope_id: Scope correlation id (matches the table's ``scope_id``).
        idempotency_key: Optional dedupe key. When non-None, the write is
            deduplicated on ``(scope_id, idempotency_key)``.

    Returns:
        ``WriteResult`` carrying ``ok``, ``ingest_sequence``,
        ``idempotent``, ``retry_count``.

    Raises:
        RelaySQLiteBusyExhausted: when the busy_timeout + backoff budget
            is exhausted without acquiring the write lock.
    """
    db = get_active_database()
    return await db.transactional_db_write(
        table=table,
        row=row,
        scope_id=scope_id,
        idempotency_key=idempotency_key,
    )


__all__ = [
    "WriteResult",
    "build_event_log_row",
    "get_active_database",
    "set_active_database",
    "transactional_db_write",
]
