"""VAL-ISO-009: crash between archive write and DELETE must not duplicate events.

Defect (bug-hunt finding ISO-009): ``run_retention_pass`` writes/concatenates
the compressed archive and digest to disk (retention.py:334-346) BEFORE
switching role and DELETE-ing the archived rows (368-380). These are two
separate durability events: the filesystem write, then a later DB COMMIT.
If the process crashes or is cancelled AFTER the archive+digest are written
but BEFORE the DELETE COMMIT, the rows remain live; on the next pass the
same rows are re-read, re-archived, and CONCATENATED to the existing archive
(line 336) -- duplicating events in ``<yyyy-mm>.jsonl.zst``.

Fix: make archive-then-delete crash-safe via a durable archived-ids
manifest. Event_ids written to the archive are recorded in the manifest
BEFORE the DELETE; on a re-run any id already in the manifest is NOT
re-archived (it is delete-only). After a successful DELETE COMMIT the ids
are pruned from the manifest. A crash before the DELETE therefore leaves
the rows live AND recorded, so the next pass deletes them without
re-archiving -- no duplicates.

This test is RED at base commit (duplicates appear) and GREEN after the fix.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
import zstandard as zstd
from relay_sidecar.db import SidecarDatabase, build_event_log_row
from relay_sidecar.primitives.transactional_db_write import (
    set_active_database,
    transactional_db_write,
)
from relay_sidecar.state_engine import retention
from relay_sidecar.state_engine.retention import run_retention_pass


async def _seed_rows(db: SidecarDatabase, n: int, payload_size: int = 4096) -> None:
    scope_id = str(uuid.uuid4())
    project_id = str(uuid.uuid4())
    for _i in range(n):
        payload = {
            "_blob_sha256": "0" * 64,
            "_padding": "p" * payload_size,
        }
        row = build_event_log_row(
            event_type="test.event",
            scope_id=scope_id,
            project_id=project_id,
            payload=payload,
            event_kind="retention_seed",
        )
        await transactional_db_write(
            table="event_log_entries",
            row=row,
            scope_id=scope_id,
        )


def _decompress_event_ids(archive_path: Path) -> list[str]:
    """Decompress the (possibly multi-frame) archive and return all event_ids."""
    raw = archive_path.read_bytes()
    decompressor = zstd.ZstdDecompressor()
    # The archive concatenates independent zstd frames; the streaming
    # reader transparently spans frame boundaries.
    text = decompressor.stream_reader(raw).read().decode("utf-8")
    ids: list[str] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        ids.append(json.loads(line)["event_id"])
    return ids


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-009")
@pytest.mark.asyncio
async def test_crash_between_archive_and_delete_does_not_duplicate(
    tmp_path: Path,
    relay_home_tmp: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Simulate a crash AFTER the archive write but BEFORE the DELETE
    COMMIT, then re-run retention; the archive MUST NOT contain duplicate
    event_ids."""
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    await db.open()
    set_active_database(db)
    now = datetime(2026, 5, 13, 12, 0, 0, tzinfo=UTC)
    try:
        await _seed_rows(db, n=300, payload_size=4096)

        # ---- Pass 1: crash AFTER archive write, BEFORE DELETE commit. ----
        # Patch set_sidecar_role to raise on entry. In run_retention_pass
        # the archive + digest are already written by the time the role
        # switch (and DELETE) run, so this reproduces the exact crash window.
        real_role = retention.set_sidecar_role

        def _exploding_role(conn: object, role: str) -> AsyncIterator[None]:
            raise RuntimeError("simulated crash before DELETE commit")

        monkeypatch.setattr(retention, "set_sidecar_role", _exploding_role)
        with pytest.raises(RuntimeError, match="simulated crash"):
            await run_retention_pass(
                db, home=relay_home_tmp, threshold_bytes=1024, now=now
            )
        monkeypatch.setattr(retention, "set_sidecar_role", real_role)

        archive_path = (
            relay_home_tmp
            / "evidence"
            / "event-log-archive"
            / "2026-05.jsonl.zst"
        )
        assert archive_path.is_file(), "pass 1 must have written the archive"
        ids_after_crash = _decompress_event_ids(archive_path)
        # The rows are still live (DELETE never committed).
        reader = db.acquire_reader()
        async with reader.execute(
            "SELECT COUNT(*) FROM event_log_entries"
        ) as cur:
            count_row = await cur.fetchone()
        assert count_row is not None
        assert count_row[0] == 300, count_row[0]

        # ---- Pass 2: normal re-run. Must DELETE without re-archiving. ----
        result2 = await run_retention_pass(
            db, home=relay_home_tmp, threshold_bytes=1024, now=now
        )
        assert result2.archive_path is not None

        ids_final = _decompress_event_ids(result2.archive_path)
        # No event_id may appear twice across the (possibly concatenated)
        # archive frames.
        dupes = sorted({i for i in ids_final if ids_final.count(i) > 1})
        assert not dupes, (
            f"VAL-ISO-009: {len(dupes)} duplicate event_id(s) in archive "
            f"after crash+rerun: {dupes[:5]}"
        )
        # Sanity: the archived id set is the same one written pre-crash
        # (nothing lost), just delivered exactly once.
        assert set(ids_final) == set(ids_after_crash), (
            "archived id set must be preserved exactly across the crash"
        )
    finally:
        await db.close()
        set_active_database(None)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-009")
@pytest.mark.asyncio
async def test_crash_after_archive_append_before_manifest_no_duplicate(
    tmp_path: Path,
    relay_home_tmp: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Narrow crash window: AFTER the archive bytes are appended to disk but
    BEFORE the archived-ids manifest is durably committed.

    Codex review P2: the pre-fix order was (1) append archive bytes + digest
    sidecar, (2) verify, (3) write the archived-ids manifest, (4) DELETE. A
    crash between (1) and (3) leaves the new zstd frame durably on disk while
    the manifest does NOT record those ids. On the next pass the ids are not
    in ``already_archived`` -> they are RE-ARCHIVED -> duplicate frames for
    the same events.

    We simulate the crash by making the in-archive-path archived-ids manifest
    write raise. In the pre-fix code that call sits right after the archive
    append, so the raise reproduces the exact window. RED at base commit
    (duplicates appear), GREEN after the crash-safe sequence lands.
    """
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    await db.open()
    set_active_database(db)
    now = datetime(2026, 5, 13, 12, 0, 0, tzinfo=UTC)
    try:
        await _seed_rows(db, n=300, payload_size=4096)

        # ---- Pass 1: crash AFTER archive append, BEFORE manifest commit. ----
        # Patch the archived-ids manifest writer to raise. The archive bytes
        # and digest sidecar are already on disk by the time the in-path
        # manifest write runs, so this reproduces the exact crash window.
        real_write_manifest = retention._write_archived_ids_manifest

        def _exploding_manifest_write(*_args: object, **_kwargs: object) -> None:
            raise RuntimeError("simulated crash before manifest commit")

        monkeypatch.setattr(
            retention,
            "_write_archived_ids_manifest",
            _exploding_manifest_write,
        )
        with pytest.raises(RuntimeError, match="simulated crash"):
            await run_retention_pass(
                db, home=relay_home_tmp, threshold_bytes=1024, now=now
            )
        monkeypatch.setattr(
            retention, "_write_archived_ids_manifest", real_write_manifest
        )

        archive_path = (
            relay_home_tmp
            / "evidence"
            / "event-log-archive"
            / "2026-05.jsonl.zst"
        )
        assert archive_path.is_file(), "pass 1 must have written the archive"
        ids_after_crash = _decompress_event_ids(archive_path)
        assert ids_after_crash, "pass 1 must have appended at least one frame"

        # The rows are still live (DELETE never committed).
        reader = db.acquire_reader()
        async with reader.execute(
            "SELECT COUNT(*) FROM event_log_entries"
        ) as cur:
            count_row = await cur.fetchone()
        assert count_row is not None
        assert count_row[0] == 300, count_row[0]

        # ---- Pass 2: normal re-run. MUST reconcile, NOT re-archive. ----
        result2 = await run_retention_pass(
            db, home=relay_home_tmp, threshold_bytes=1024, now=now
        )
        assert result2.archive_path is not None

        ids_final = _decompress_event_ids(result2.archive_path)
        dupes = sorted({i for i in ids_final if ids_final.count(i) > 1})
        assert not dupes, (
            f"VAL-ISO-009: {len(dupes)} duplicate event_id(s) in archive "
            f"after crash+rerun: {dupes[:5]}"
        )
        # The frame written pre-crash must be preserved exactly once; the
        # set must not grow (no re-archival of the already-committed frame).
        assert set(ids_final) == set(ids_after_crash), (
            "archived id set must be preserved exactly across the crash, "
            "neither lost nor re-archived"
        )
    finally:
        await db.close()
        set_active_database(None)
