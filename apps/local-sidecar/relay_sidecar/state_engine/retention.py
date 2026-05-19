"""Rolling event-log retention (W2.5 / VAL-W2-040 + VAL-W2-042).

When the live ``event_log_entries`` table size exceeds the configured
threshold (default 1 GiB; tunable via ``RELAY_EVENT_LOG_MAX_BYTES``), the
retention pass:

  1. Reads the oldest rows from ``event_log_entries`` ordered by
     ``ingest_sequence`` ASC up to a high-water mark that brings the live
     table back under the threshold.
  2. Serializes each row as a single JSON line (matching the local JSONL
     event log shape used by W2.1's ``event_log.py``).
  3. Compresses the JSONL lines with zstandard and writes the bytes to
     ``${RELAY_HOME}/evidence/event-log-archive/<yyyy-mm>.jsonl.zst`` via
     ``local_atomic_file_write`` (atomic-persistence primitive #4).
  4. Computes the SHA-256 of the archive bytes and writes the hex digest
     to the sibling ``<yyyy-mm>.jsonl.zst.sha256`` via
     ``local_atomic_file_write``.
  5. Switches the connection role to ``relay_retention_archive`` and
     DELETEs the archived rows from ``event_log_entries``. The W2.5
     SQLite triggers ``event_log_entries_no_delete`` /
     ``_no_update`` permit the DELETE ONLY for this role.
  6. Restores the role to ``relay_state_engine``.

The retention pass shares the W2.4 ``_state_engine_writer_lock`` so it
serializes against canonical state-engine writes. This module lives under
``state_engine/`` so the VAL-W2-024 / -058 grep guards (which only allow
DML to ``event_log_entries`` from ``state_engine/``) accept the
``DELETE FROM event_log_entries`` site below.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

import aiosqlite
import zstandard as zstd

from ..db import SidecarDatabase
from ..lockfile import relay_home
from ..primitives import local_atomic_file_write

# Default retention threshold. Spec eng plan A5 (review pass 1 M-14):
# 1 GiB = 1024 * 1024 * 1024. Override via RELAY_EVENT_LOG_MAX_BYTES; default
# is also declared in packages/schemas/raw/sidecar-config.yaml for auditors.
DEFAULT_EVENT_LOG_MAX_BYTES: int = 1024 * 1024 * 1024

# Role-name constants. Single source of truth in the migration 0007
# _sidecar_role table.
ROLE_STATE_ENGINE: str = "relay_state_engine"
ROLE_RETENTION_ARCHIVE: str = "relay_retention_archive"

# Compression level. Zstandard's default level 3 is a known good
# CPU/ratio trade-off for JSON; we pin it explicitly for reproducibility.
_ZSTD_LEVEL: int = 3


def event_log_max_bytes() -> int:
    """Return the active retention threshold in bytes.

    Reads ``RELAY_EVENT_LOG_MAX_BYTES`` on every call so tests can
    monkeypatch via ``monkeypatch.setenv``. Falls back to the safe
    default on missing / non-integer / non-positive values; a
    misconfigured env var must not silently disable the bound.
    """
    raw = os.environ.get("RELAY_EVENT_LOG_MAX_BYTES")
    if raw is None:
        return DEFAULT_EVENT_LOG_MAX_BYTES
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return DEFAULT_EVENT_LOG_MAX_BYTES
    if value <= 0:
        return DEFAULT_EVENT_LOG_MAX_BYTES
    return value


def archive_dir(home: Path | None = None) -> Path:
    """Return the absolute archive directory under the resolved home."""
    base = home if home is not None else relay_home()
    return base / "evidence" / "event-log-archive"


@dataclass(frozen=True)
class RetentionResult:
    """Outcome of one retention pass.

    Attributes:
        archived_rows: Count of rows archived AND deleted from the live
            table.
        archive_path: The .jsonl.zst path written (or None when no archive
            was needed).
        digest_path: The .jsonl.zst.sha256 sibling path written.
        digest_hex: The sha256 hex digest of the archive bytes.
        live_bytes_before: The estimated live table size BEFORE the pass.
        live_bytes_after: The estimated live table size AFTER the pass.
        threshold_bytes: The active threshold (for evidence).
    """

    archived_rows: int = 0
    archive_path: Path | None = None
    digest_path: Path | None = None
    digest_hex: str | None = None
    live_bytes_before: int = 0
    live_bytes_after: int = 0
    threshold_bytes: int = 0


@contextlib.asynccontextmanager
async def set_sidecar_role(
    conn: aiosqlite.Connection,
    role: str,
) -> AsyncIterator[None]:
    """Set the connection's active role inside a BEGIN IMMEDIATE..COMMIT.

    The retention pass calls this around its DELETE so the BEFORE DELETE
    trigger sees role='relay_retention_archive' and permits the delete.
    On exit the role is restored to ``relay_state_engine``. The caller is
    responsible for being inside an asyncio lock so concurrent connections
    don't observe each other's role.
    """
    await conn.execute(
        "UPDATE _sidecar_role SET role = ? WHERE id = 0", (role,)
    )
    try:
        yield None
    finally:
        with contextlib.suppress(Exception):
            await conn.execute(
                "UPDATE _sidecar_role SET role = ? WHERE id = 0",
                (ROLE_STATE_ENGINE,),
            )


async def _live_table_byte_estimate(conn: aiosqlite.Connection) -> int:
    """Return an estimate of event_log_entries byte size.

    SQLite has no fast O(1) "table size" pragma; we approximate via
    SUM(LENGTH(payload) + LENGTH(event_id) + ...). The estimate is a
    lower bound (excludes index + row overhead) which is conservative:
    we err on the side of triggering retention slightly later. For the
    1 MiB CI test threshold the estimate is well within an order of
    magnitude of the real on-disk size.
    """
    async with conn.execute(
        "SELECT COALESCE("
        " SUM("
        "  COALESCE(LENGTH(event_id), 0)"
        "  + COALESCE(LENGTH(schema_version), 0)"
        "  + COALESCE(LENGTH(project_id), 0)"
        "  + COALESCE(LENGTH(scope_id), 0)"
        "  + COALESCE(LENGTH(event_type), 0)"
        "  + COALESCE(LENGTH(actor_kind), 0)"
        "  + COALESCE(LENGTH(actor_id), 0)"
        "  + COALESCE(LENGTH(manifest_commit_hash), 0)"
        "  + COALESCE(LENGTH(payload), 0)"
        "  + COALESCE(LENGTH(occurred_at), 0)"
        "  + COALESCE(LENGTH(event_kind), 0)"
        " ),"
        " 0)"
        " FROM event_log_entries"
    ) as cur:
        row = await cur.fetchone()
    return int(row[0]) if row is not None else 0


def _row_to_dict(row: aiosqlite.Row | tuple[Any, ...], columns: list[str]) -> dict[str, Any]:
    return {col: row[i] for i, col in enumerate(columns)}


def _archive_filename(now: datetime | None = None) -> str:
    """Return the yyyy-mm archive filename for the current month."""
    ts = now if now is not None else datetime.now(tz=UTC)
    return f"{ts.year:04d}-{ts.month:02d}.jsonl.zst"


async def run_retention_pass(
    database: SidecarDatabase,
    *,
    home: Path | None = None,
    threshold_bytes: int | None = None,
    now: datetime | None = None,
) -> RetentionResult:
    """Execute one retention pass synchronously (single shot).

    The caller is responsible for invocation cadence (typically a periodic
    asyncio.Task installed in the lifespan). This function is reentrant
    only across the W2.4 ``_state_engine_writer_lock`` boundary.

    Steps (matches module docstring):
      1. Compute live byte estimate.
      2. If under threshold -> no-op result.
      3. Read oldest rows to archive (enough to bring size under threshold).
      4. Serialize -> compress -> write archive + digest.
      5. Switch role -> DELETE archived rows -> restore role.
      6. Recompute live byte estimate -> return result.

    Args:
        database: Open SidecarDatabase. The writer connection is borrowed
            through the same lock the state engine uses.
        home: Override RELAY_HOME (tests).
        threshold_bytes: Override the env var (tests use 1 MiB for fast CI).
        now: Override datetime.now (tests; pin yyyy-mm for archive name).
    """
    limit = (
        threshold_bytes if threshold_bytes is not None else event_log_max_bytes()
    )

    # Acquire the shared writer lock (lazily attached by W2.4's
    # _borrow_writer; we reuse the exact attribute name to serialize
    # against compare_and_set_state).
    lock = getattr(database, "_state_engine_writer_lock", None)
    if lock is None:
        import asyncio as _asyncio

        lock = _asyncio.Lock()
        database._state_engine_writer_lock = lock

    async with lock:
        conn = database._writer
        if conn is None:
            raise RuntimeError(
                "run_retention_pass: SidecarDatabase is not open"
            )

        before = await _live_table_byte_estimate(conn)
        if before < limit:
            return RetentionResult(
                live_bytes_before=before,
                live_bytes_after=before,
                threshold_bytes=limit,
            )

        # Read all rows ordered by ingest_sequence ASC. We collect the
        # smallest set whose summed byte estimate carries the live table
        # back below the threshold. The estimate per row reuses the same
        # column-length sum used above so the math is internally consistent.
        columns = [
            "event_id",
            "schema_version",
            "project_id",
            "scope_type",
            "scope_id",
            "event_type",
            "actor_kind",
            "actor_id",
            "manifest_commit_hash",
            "payload",
            "occurred_at",
            "ingest_sequence",
            "event_kind",
            "attempt_number",
            "backoff_ms",
            "sql_statement_digest",
            "idempotency_key",
        ]
        select_cols = ", ".join(columns)
        async with conn.execute(
            f"SELECT {select_cols} FROM event_log_entries "
            f"ORDER BY ingest_sequence ASC"
        ) as cur:
            rows = await cur.fetchall()

        archived_rows: list[dict[str, Any]] = []
        archived_event_ids: list[str] = []
        running = before
        for raw in rows:
            row_dict = _row_to_dict(raw, columns)
            # Recompute this row's byte contribution to the live estimate
            # (same sum as _live_table_byte_estimate).
            row_bytes = sum(
                len(str(row_dict[c])) if row_dict[c] is not None else 0
                for c in (
                    "event_id",
                    "schema_version",
                    "project_id",
                    "scope_id",
                    "event_type",
                    "actor_kind",
                    "actor_id",
                    "manifest_commit_hash",
                    "payload",
                    "occurred_at",
                    "event_kind",
                )
            )
            archived_rows.append(row_dict)
            archived_event_ids.append(str(row_dict["event_id"]))
            running -= row_bytes
            if running < limit:
                break

        if not archived_rows:
            return RetentionResult(
                live_bytes_before=before,
                live_bytes_after=before,
                threshold_bytes=limit,
            )

        # Serialize rows to JSONL (one JSON object per line). Sorted keys
        # + compact separators match the rest of the canonical encoding.
        jsonl_lines: list[bytes] = []
        for r in archived_rows:
            jsonl_lines.append(
                json.dumps(
                    r, sort_keys=True, separators=(",", ":"), default=str
                ).encode("utf-8")
            )
        jsonl_bytes = b"\n".join(jsonl_lines) + b"\n"

        compressor = zstd.ZstdCompressor(level=_ZSTD_LEVEL)
        archive_bytes = compressor.compress(jsonl_bytes)
        digest_hex = hashlib.sha256(archive_bytes).hexdigest()

        archive_root = archive_dir(home)
        archive_root.mkdir(parents=True, exist_ok=True)
        archive_name = _archive_filename(now)
        archive_path = archive_root / archive_name
        digest_path = archive_root / f"{archive_name}.sha256"

        # Append-or-create semantics: if a prior pass already wrote this
        # month's archive, concatenate (zstandard frames concatenate
        # losslessly). Then re-hash the resulting bytes.
        if archive_path.exists():
            existing = archive_path.read_bytes()
            combined = existing + archive_bytes
            local_atomic_file_write(archive_path, combined, mode=0o600)
            final_digest = hashlib.sha256(combined).hexdigest()
        else:
            local_atomic_file_write(archive_path, archive_bytes, mode=0o600)
            final_digest = digest_hex

        # Atomic write of the digest sidecar (text form: "<hex>  <basename>\n"
        # matches the GNU coreutils sha256sum output).
        digest_line = f"{final_digest}  {archive_name}\n".encode("ascii")
        local_atomic_file_write(digest_path, digest_line, mode=0o600)

        # VAL-W2-042 verifier gate: re-read the archive and digest, confirm
        # they match BEFORE deleting live rows. If the disk write was
        # corrupted (truncated, partially flushed) the delete is skipped
        # and the operator sees a discrepancy on next sweep.
        on_disk_bytes = archive_path.read_bytes()
        on_disk_digest = hashlib.sha256(on_disk_bytes).hexdigest()
        if on_disk_digest != final_digest:
            return RetentionResult(
                archived_rows=0,
                archive_path=archive_path,
                digest_path=digest_path,
                digest_hex=final_digest,
                live_bytes_before=before,
                live_bytes_after=before,
                threshold_bytes=limit,
            )

        # Switch role -> DELETE the archived rows -> restore role. The
        # DELETE is bound by IN clause; SQLite has a default limit on the
        # number of parameters (999) so we batch.
        await conn.execute("BEGIN IMMEDIATE")
        try:
            async with set_sidecar_role(conn, ROLE_RETENTION_ARCHIVE):
                BATCH = 500
                for i in range(0, len(archived_event_ids), BATCH):
                    batch = archived_event_ids[i : i + BATCH]
                    placeholders = ",".join("?" for _ in batch)
                    await conn.execute(
                        f"DELETE FROM event_log_entries "
                        f"WHERE event_id IN ({placeholders})",
                        batch,
                    )
            await conn.execute("COMMIT")
        except BaseException:
            with contextlib.suppress(Exception):
                await conn.execute("ROLLBACK")
            raise

        after = await _live_table_byte_estimate(conn)
        return RetentionResult(
            archived_rows=len(archived_rows),
            archive_path=archive_path,
            digest_path=digest_path,
            digest_hex=final_digest,
            live_bytes_before=before,
            live_bytes_after=after,
            threshold_bytes=limit,
        )


# =============================================================================
# V3M3-F04: spec AP.5.b scope_state_snapshots daily helper + retention sweep.
#
# write_daily_snapshot(now): writes one row per active scope_state row to
# scope_state_snapshots, keyed on the UTC calendar date of ``now``. The PK
# (snapshot_date, scope_kind, scope_id) absorbs idempotent re-runs via
# INSERT ... ON CONFLICT DO NOTHING.
#
# prune_old_scope_state_snapshots(retention_days=90): deletes rows whose
# snapshot_date is strictly older than (today - retention_days). Default 90
# matches the spec AP.5.b operational retention discussion.
#
# Both helpers go through the shared _state_engine_writer_lock so they
# serialise against canonical state-engine writes. They are co-located in
# this module because they are state-engine-adjacent retention passes.
# =============================================================================

# Default retention window (spec AP.5.b: 90 days for forensic/audit reads).
DEFAULT_SCOPE_STATE_SNAPSHOT_RETENTION_DAYS: int = 90


async def write_daily_snapshot(
    database: SidecarDatabase,
    *,
    now: datetime | None = None,
) -> int:
    """Write one snapshot row per active scope_state row for the UTC date of ``now``.

    Per spec AP.5.b (lines 6347-6390): a daily cron job freezes the current
    ``scope_state`` per project and writes the (state, epoch) of every
    active scope at the snapshot date. The PK
    ``(snapshot_date, scope_kind, scope_id)`` is the idempotency anchor:
    re-running the helper for the same date after a crash is a no-op.

    Args:
        database: Open SidecarDatabase.
        now: Snapshot wall clock (defaults to ``datetime.now(tz=UTC)``).
            Only the UTC calendar date is used as the snapshot_date.

    Returns:
        The count of rows NEWLY inserted (idempotent re-runs return 0).
    """
    snapshot_ts = now if now is not None else datetime.now(tz=UTC)
    snapshot_date = snapshot_ts.astimezone(UTC).date().isoformat()

    lock = getattr(database, "_state_engine_writer_lock", None)
    if lock is None:
        import asyncio as _asyncio

        lock = _asyncio.Lock()
        database._state_engine_writer_lock = lock

    async with lock:
        conn = database._writer
        if conn is None:
            raise RuntimeError(
                "write_daily_snapshot: SidecarDatabase is not open"
            )

        # Read every active scope_state row. The state engine is the only
        # writer of scope_state (CLAUDE.md keystone #1); a stable SELECT
        # without locking matches the canonical reader pattern.
        async with conn.execute(
            "SELECT scope_kind, scope_id, state, epoch FROM scope_state"
        ) as cur:
            rows = await cur.fetchall()

        if not rows:
            return 0

        await conn.execute("BEGIN IMMEDIATE")
        try:
            inserted = 0
            for scope_kind, scope_id, state, epoch in rows:
                # ON CONFLICT DO NOTHING absorbs idempotent re-runs. The
                # changes() pragma reports per-statement row counts; we
                # accumulate the delta to compute "newly inserted".
                snapshot_id = str(uuid.uuid4())
                async with conn.execute(
                    "INSERT INTO scope_state_snapshots "
                    "(snapshot_id, snapshot_date, scope_kind, scope_id, "
                    " state, epoch) "
                    "VALUES (?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(snapshot_date, scope_kind, scope_id) "
                    "DO NOTHING",
                    (
                        snapshot_id,
                        snapshot_date,
                        scope_kind,
                        scope_id,
                        state,
                        int(epoch),
                    ),
                ) as ins:
                    inserted += ins.rowcount if ins.rowcount and ins.rowcount > 0 else 0
            await conn.execute("COMMIT")
        except BaseException:
            with contextlib.suppress(Exception):
                await conn.execute("ROLLBACK")
            raise

        return inserted


async def prune_old_scope_state_snapshots(
    database: SidecarDatabase,
    *,
    retention_days: int = DEFAULT_SCOPE_STATE_SNAPSHOT_RETENTION_DAYS,
    today: date | None = None,
) -> int:
    """Delete scope_state_snapshots rows older than ``today - retention_days``.

    Per spec AP.5.b: the 90-day forensic / audit retention window is the
    OSS default. The sweep is gated by the ``ix_scope_state_snapshots_snapshot_date``
    btree index so it is O(log N + matches) instead of a full scan.

    Args:
        database: Open SidecarDatabase.
        retention_days: Strictly-older-than window (default 90).
        today: Reference "today" (defaults to ``datetime.now(tz=UTC).date()``).
            The cutoff is ``today - retention_days``; rows whose
            ``snapshot_date < cutoff`` are deleted.

    Returns:
        The count of deleted rows.
    """
    if retention_days < 0:
        raise ValueError(
            f"retention_days must be non-negative; got {retention_days!r}"
        )
    reference_today = today if today is not None else datetime.now(tz=UTC).date()
    cutoff = (reference_today - timedelta(days=retention_days)).isoformat()

    lock = getattr(database, "_state_engine_writer_lock", None)
    if lock is None:
        import asyncio as _asyncio

        lock = _asyncio.Lock()
        database._state_engine_writer_lock = lock

    async with lock:
        conn = database._writer
        if conn is None:
            raise RuntimeError(
                "prune_old_scope_state_snapshots: SidecarDatabase is not open"
            )

        await conn.execute("BEGIN IMMEDIATE")
        try:
            async with conn.execute(
                "DELETE FROM scope_state_snapshots WHERE snapshot_date < ?",
                (cutoff,),
            ) as cur:
                deleted = cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0
            await conn.execute("COMMIT")
        except BaseException:
            with contextlib.suppress(Exception):
                await conn.execute("ROLLBACK")
            raise

        return deleted


__all__ = [
    "DEFAULT_EVENT_LOG_MAX_BYTES",
    "DEFAULT_SCOPE_STATE_SNAPSHOT_RETENTION_DAYS",
    "ROLE_RETENTION_ARCHIVE",
    "ROLE_STATE_ENGINE",
    "RetentionResult",
    "archive_dir",
    "event_log_max_bytes",
    "prune_old_scope_state_snapshots",
    "run_retention_pass",
    "set_sidecar_role",
    "write_daily_snapshot",
]
