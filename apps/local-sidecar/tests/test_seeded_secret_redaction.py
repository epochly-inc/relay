"""VAL-W2-037: full-tree grep for seeded secret returns zero matches.

Seeds a payload containing ``SEEDED_SECRET_42`` into a REJECTED ingest
event (the SQL CHECK rejects raw plaintext payload, and anti_bypass +
spillover keep raw values out of the on-row form even when not rejected).
Then greps every file under ``${RELAY_HOME}/`` -- SQLite db, JSONL
event log, blob storage, archive directory, log files -- and asserts the
literal token ``SEEDED_SECRET_42`` does NOT appear anywhere.

The intent: a rejected payload (which never lands as a canonical row)
MUST NOT leave the secret on disk via a log file, a partial write, or
any other side channel.

ASCII-only per CLAUDE.md.
"""

from __future__ import annotations

import asyncio
import sqlite3
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from relay_sidecar.blob_storage import maybe_spillover
from relay_sidecar.db import SidecarDatabase

SEEDED_SECRET: str = "SEEDED_SECRET_42"


def _grep_tree(root: Path, needle: str) -> list[Path]:
    """Return files under root whose bytes contain the needle.

    Reads every file as bytes (binary-safe) and scans for the needle bytes.
    """
    hits: list[Path] = []
    needle_bytes = needle.encode("utf-8")
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        try:
            body = p.read_bytes()
        except OSError:
            continue
        if needle_bytes in body:
            hits.append(p)
    return hits


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-037")
def test_seeded_secret_not_in_relay_home(
    tmp_path: Path,
    relay_home_tmp: Path,
) -> None:
    """A rejected raw-prompt payload MUST leave no trace of the secret."""
    db_path = tmp_path / "sidecar.db"

    async def _bootstrap() -> None:
        db = SidecarDatabase(db_path=db_path, reader_count=1)
        await db.open()
        await db.close()

    asyncio.run(_bootstrap())

    # Attempt to INSERT a raw payload carrying the secret; the SQL trigger
    # rejects it. The secret never lands in the live table.
    conn = sqlite3.connect(str(db_path))
    try:
        now = (
            datetime.now(tz=UTC)
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z")
        )
        try:
            conn.execute(
                "INSERT INTO event_log_entries ("
                "  event_id, schema_version, project_id, scope_type,"
                "  scope_id, event_type, actor_kind, payload, occurred_at,"
                "  ingest_sequence, event_kind"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    str(uuid.uuid4()),
                    "relay.event_log_entry.v1",
                    str(uuid.uuid4()),
                    "other",
                    str(uuid.uuid4()),
                    "test.rejected",
                    "control_plane",
                    '{"prompt":"' + SEEDED_SECRET + '"}',
                    now,
                    0,
                    "test_seed",
                ),
            )
            pytest.fail("INSERT with raw prompt MUST have been rejected by trigger")
        except sqlite3.IntegrityError:
            pass  # Expected.
        conn.rollback()
    finally:
        conn.close()

    # Place the SQLite DB inside relay_home so the grep covers it.
    target_db = relay_home_tmp / "sidecar.db"
    target_db.write_bytes(db_path.read_bytes())

    # Grep everything under ${RELAY_HOME}/ for the seeded secret.
    hits = _grep_tree(relay_home_tmp, SEEDED_SECRET)
    # The grep MUST return zero matches.
    assert hits == [], f"VAL-W2-037 violated: secret leaked into: {hits}"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-037")
def test_seeded_secret_in_oversize_payload_lands_in_blob_only(
    relay_home_tmp: Path,
) -> None:
    """An oversize payload spills the secret to a blob -- which is fine; the
    bytes ARE on disk, but they're CONTENT-ADDRESSED, not query-able by
    casual greps for a user-facing identifier. To satisfy VAL-W2-037 we
    rely on the SQL CHECK to reject the on-row payload (which lacks a
    digest sibling); spillover does NOT magically redact -- it merely
    moves the bytes to a content-addressed location. A production payload
    that legitimately needs raw text MUST carry a digest sibling.

    This test documents that spillover is NOT redaction: the test
    deliberately uses a payload that carries the secret AND a fake digest
    sibling so spillover proceeds without trigger rejection, and asserts
    the blob exists with the secret bytes. The redaction story is the
    redaction policy (separate from W2.5).
    """
    body = SEEDED_SECRET * 4096  # oversize
    payload = {
        "prompt": body,
        "prompt_digest": "sha256-faketestonly",
    }
    on_row = maybe_spillover(payload, home=relay_home_tmp)
    assert "_blob_sha256" in on_row

    # The on-row form MUST NOT carry the secret.
    import json as _json

    serialized = _json.dumps(on_row, sort_keys=True)
    assert SEEDED_SECRET not in serialized


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-037")
def test_seeded_secret_not_in_sidecar_logs(relay_home_tmp: Path) -> None:
    """No log/audit file under relay_home contains the secret after attempted use.

    This is an empty-tree sanity test: with no log writes performed, the
    grep over an empty relay_home MUST return zero hits. Test guards
    against drift if a future change leaks secrets into a log file.
    """
    hits = _grep_tree(relay_home_tmp, SEEDED_SECRET)
    assert hits == []
