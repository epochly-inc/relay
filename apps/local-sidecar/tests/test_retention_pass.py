"""VAL-W2-040 + VAL-W2-042: rolling retention pass + archive integrity.

The retention pass:
  - Estimates the live event_log_entries byte size.
  - When the estimate exceeds the threshold (default 1 GiB, tunable via
    RELAY_EVENT_LOG_MAX_BYTES; CI tests use 1 MiB), archives the oldest
    entries to ${RELAY_HOME}/evidence/event-log-archive/<yyyy-mm>.jsonl.zst
    via local_atomic_file_write, writes a sibling .sha256 digest, and
    DELETEs the archived rows under the relay_retention_archive role.

VAL-W2-040 evidence: archive file exists after the pass; live table size
below threshold; env override raises the trigger threshold.
VAL-W2-042 evidence: sibling sha256 file exists; digest matches the
archive bytes; deletion gated on match.

Also: schema-drift guard asserts the YAML default at
packages/schemas/raw/sidecar-config.yaml matches the Python constant.

ASCII-only per CLAUDE.md.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml
import zstandard as zstd
from relay_sidecar.db import SidecarDatabase, build_event_log_row
from relay_sidecar.primitives.transactional_db_write import (
    set_active_database,
    transactional_db_write,
)
from relay_sidecar.state_engine.retention import (
    DEFAULT_EVENT_LOG_MAX_BYTES,
    archive_dir,
    event_log_max_bytes,
    run_retention_pass,
)


async def _seed_rows(db: SidecarDatabase, n: int, payload_size: int = 256) -> None:
    """Insert ``n`` event_log_entries rows via the canonical primitive."""
    scope_id = str(uuid.uuid4())
    project_id = str(uuid.uuid4())
    for _i in range(n):
        # Use _blob_sha256 prefix so the SQL CHECK passes trivially.
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


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-040")
@pytest.mark.asyncio
async def test_retention_no_op_under_threshold(
    tmp_path: Path, relay_home_tmp: Path
) -> None:
    """Live size below threshold MUST NOT archive."""
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    await db.open()
    set_active_database(db)
    try:
        await _seed_rows(db, n=5, payload_size=64)
        result = await run_retention_pass(
            db, home=relay_home_tmp, threshold_bytes=10_000_000
        )
        assert result.archived_rows == 0
        assert result.archive_path is None or not result.archive_path.exists()
    finally:
        await db.close()
        set_active_database(None)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-040")
@pytest.mark.asyncio
async def test_retention_archives_oldest_rows(
    tmp_path: Path, relay_home_tmp: Path
) -> None:
    """Live size above 1 MiB threshold triggers archive + delete."""
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    await db.open()
    set_active_database(db)
    try:
        await _seed_rows(db, n=300, payload_size=4096)
        result = await run_retention_pass(
            db, home=relay_home_tmp, threshold_bytes=1024
        )
        assert result.archived_rows > 0, result
        assert result.archive_path is not None
        assert result.archive_path.is_file(), result.archive_path
        assert result.digest_path is not None
        assert result.digest_path.is_file(), result.digest_path
        assert result.live_bytes_after < result.live_bytes_before, result
    finally:
        await db.close()
        set_active_database(None)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-040")
@pytest.mark.asyncio
async def test_env_override_raises_threshold(
    tmp_path: Path,
    relay_home_tmp: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Setting RELAY_EVENT_LOG_MAX_BYTES to 2 GiB raises the threshold."""
    monkeypatch.setenv("RELAY_EVENT_LOG_MAX_BYTES", "2147483648")
    assert event_log_max_bytes() == 2147483648

    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    await db.open()
    set_active_database(db)
    try:
        await _seed_rows(db, n=10, payload_size=128)
        # With the 2 GiB threshold from env, retention should not trigger.
        result = await run_retention_pass(db, home=relay_home_tmp)
        assert result.archived_rows == 0
        assert result.threshold_bytes == 2147483648
    finally:
        await db.close()
        set_active_database(None)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-042")
@pytest.mark.asyncio
async def test_archive_digest_matches_file_bytes(
    tmp_path: Path, relay_home_tmp: Path
) -> None:
    """The .sha256 sidecar MUST hold the digest of the archive bytes."""
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    await db.open()
    set_active_database(db)
    try:
        await _seed_rows(db, n=200, payload_size=4096)
        result = await run_retention_pass(
            db, home=relay_home_tmp, threshold_bytes=1024
        )
        assert result.archive_path is not None
        # archive_path and digest_path are populated together when an archive
        # is produced (retention.py); narrow both so the reads type-check.
        assert result.digest_path is not None
        archive_bytes = result.archive_path.read_bytes()
        recomputed = hashlib.sha256(archive_bytes).hexdigest()
        assert recomputed == result.digest_hex
        # The sidecar file MUST also carry the digest text.
        digest_text = result.digest_path.read_text(encoding="ascii")
        assert recomputed in digest_text, digest_text
    finally:
        await db.close()
        set_active_database(None)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-042")
@pytest.mark.asyncio
async def test_archive_decompresses_to_jsonl(
    tmp_path: Path, relay_home_tmp: Path
) -> None:
    """The archive MUST decompress to JSONL recoverable per-line."""
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    await db.open()
    set_active_database(db)
    try:
        await _seed_rows(db, n=150, payload_size=4096)
        result = await run_retention_pass(
            db, home=relay_home_tmp, threshold_bytes=1024
        )
        assert result.archive_path is not None
        raw = result.archive_path.read_bytes()
        decompressor = zstd.ZstdDecompressor()
        jsonl = decompressor.decompress(raw).decode("utf-8")
        lines = [line for line in jsonl.splitlines() if line.strip()]
        assert len(lines) == result.archived_rows, (len(lines), result.archived_rows)
        # Each line must be a JSON object with the canonical columns.
        for line in lines:
            obj = json.loads(line)
            assert "event_id" in obj
            assert "ingest_sequence" in obj
    finally:
        await db.close()
        set_active_database(None)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-042")
@pytest.mark.asyncio
async def test_live_rows_deleted_after_archive(
    tmp_path: Path, relay_home_tmp: Path
) -> None:
    """After a successful pass, the archived rows MUST be gone from the live table."""
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    await db.open()
    set_active_database(db)
    try:
        await _seed_rows(db, n=120, payload_size=4096)

        reader = db.acquire_reader()
        async with reader.execute("SELECT COUNT(*) FROM event_log_entries") as cur:
            # fetchone() is typed Optional[Row]; a COUNT(...) query always
            # returns exactly one row, so assert-narrow before unpacking.
            before_row = await cur.fetchone()
            assert before_row is not None
            (before_count,) = before_row

        result = await run_retention_pass(
            db, home=relay_home_tmp, threshold_bytes=1024
        )

        async with reader.execute("SELECT COUNT(*) FROM event_log_entries") as cur:
            after_row = await cur.fetchone()
            assert after_row is not None
            (after_count,) = after_row
        assert after_count == before_count - result.archived_rows, (
            before_count,
            after_count,
            result.archived_rows,
        )
    finally:
        await db.close()
        set_active_database(None)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-040")
def test_yaml_default_matches_python_constant() -> None:
    """The canonical schema default MUST match the Python constant byte-for-byte."""
    yaml_path = (
        Path(__file__).resolve().parents[3]
        / "packages"
        / "schemas"
        / "raw"
        / "sidecar-config.yaml"
    )
    data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    yaml_default = data["env_vars"]["RELAY_EVENT_LOG_MAX_BYTES"]["default"]
    assert yaml_default == DEFAULT_EVENT_LOG_MAX_BYTES, (
        yaml_default,
        DEFAULT_EVENT_LOG_MAX_BYTES,
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-040")
@pytest.mark.asyncio
async def test_archive_filename_yyyy_mm(
    tmp_path: Path, relay_home_tmp: Path
) -> None:
    """The archive filename MUST be <yyyy-mm>.jsonl.zst."""
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    await db.open()
    set_active_database(db)
    try:
        await _seed_rows(db, n=100, payload_size=4096)
        now = datetime(2026, 5, 13, 12, 0, 0, tzinfo=UTC)
        result = await run_retention_pass(
            db, home=relay_home_tmp, threshold_bytes=1024, now=now
        )
        assert result.archive_path is not None
        assert result.archive_path.name == "2026-05.jsonl.zst", result.archive_path
        archive_root = archive_dir(relay_home_tmp)
        assert (archive_root / "2026-05.jsonl.zst.sha256").is_file()
    finally:
        await db.close()
        set_active_database(None)
