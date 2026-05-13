"""VAL-W2-060: event_log_entries.schema_version pinned to v1 via CHECK trigger.

Migration 0007 installs ``event_log_entries_schema_version_check`` that
aborts the insert when ``schema_version != 'relay.event_log_entry.v1'``.
This protects against a misconfigured worker bypassing the state engine
and writing a newer / unknown schema version (CLAUDE.md invariant #10:
engines refuse unknown versions on write).

ASCII-only per CLAUDE.md.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from _w25_helpers import direct_insert as _direct_insert
from _w25_helpers import seed_db as _seed_db


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-060")
def test_direct_insert_v2_schema_version_rejected(tmp_path: Path) -> None:
    """A direct insert with schema_version='v2' MUST raise IntegrityError."""
    db_path = _seed_db(tmp_path)
    with pytest.raises(sqlite3.IntegrityError) as excinfo:
        _direct_insert(
            db_path,
            payload={"_blob_sha256": "x" * 64},
            schema_version="relay.event_log_entry.v2",
        )
    assert (
        "event_log_entries_schema_version_check" in str(excinfo.value)
    ), excinfo.value


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-060")
def test_direct_insert_v1_schema_version_accepted(tmp_path: Path) -> None:
    """Schema_version='relay.event_log_entry.v1' MUST pass the CHECK."""
    db_path = _seed_db(tmp_path)
    _direct_insert(
        db_path,
        payload={"_blob_sha256": "x" * 64},
        schema_version="relay.event_log_entry.v1",
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-060")
def test_direct_insert_other_schema_version_rejected(tmp_path: Path) -> None:
    """Any non-canonical schema_version MUST be rejected."""
    db_path = _seed_db(tmp_path)
    for bogus in [
        "relay.event_log_entry.v0",
        "relay.event_log_entry.v999",
        "some.other.envelope.v1",
        "",
    ]:
        with pytest.raises(sqlite3.IntegrityError) as excinfo:
            _direct_insert(
                db_path,
                payload={"_blob_sha256": "x" * 64},
                schema_version=bogus,
            )
        assert (
            "event_log_entries_schema_version_check" in str(excinfo.value)
        ), (bogus, excinfo.value)
