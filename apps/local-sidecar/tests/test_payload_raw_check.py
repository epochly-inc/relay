"""VAL-W2-036: event_log_entries payload CHECK rejects raw plaintext patterns.

The W2.5 migration 0007 installs a BEFORE INSERT trigger
``event_log_entries_payload_raw_check`` that aborts the insert when the
payload JSON carries any of the canonical plaintext keys
(``"prompt":``, ``"completion":``, ``"messages":``) WITHOUT an accompanying
HMAC / sha256 / digest sibling.

These tests INSERT directly via sqlite3 (bypassing the state engine and
the Python-layer anti_bypass module) so the SQL CHECK is the only
defence. A production caller MUST go through the state engine, which
runs anti_bypass FIRST and additionally spills oversize payloads to
content-addressed storage so the on-row payload doesn't carry the raw
key in the first place.

ASCII-only per CLAUDE.md.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from _w25_helpers import direct_insert as _direct_insert
from _w25_helpers import seed_db as _seed_db


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-036")
def test_raw_prompt_payload_rejected(tmp_path: Path) -> None:
    """Inserting a payload with raw "prompt": key MUST raise IntegrityError."""
    db_path = _seed_db(tmp_path)
    with pytest.raises(sqlite3.IntegrityError) as excinfo:
        _direct_insert(db_path, payload={"prompt": "secret"})
    assert "event_log_entries_payload_raw_check" in str(excinfo.value), excinfo.value


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-036")
def test_raw_completion_payload_rejected(tmp_path: Path) -> None:
    """Inserting a payload with raw "completion": key MUST raise IntegrityError."""
    db_path = _seed_db(tmp_path)
    with pytest.raises(sqlite3.IntegrityError) as excinfo:
        _direct_insert(db_path, payload={"completion": "model output"})
    assert "event_log_entries_payload_raw_check" in str(excinfo.value), excinfo.value


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-036")
def test_raw_messages_payload_rejected(tmp_path: Path) -> None:
    """Inserting a payload with raw "messages": key MUST raise IntegrityError."""
    db_path = _seed_db(tmp_path)
    with pytest.raises(sqlite3.IntegrityError) as excinfo:
        _direct_insert(
            db_path,
            payload={"messages": [{"role": "user", "content": "hi"}]},
        )
    assert "event_log_entries_payload_raw_check" in str(excinfo.value), excinfo.value


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-036")
def test_prompt_with_digest_sibling_accepted(tmp_path: Path) -> None:
    """Payload with prompt + prompt_digest sibling MUST pass the CHECK."""
    db_path = _seed_db(tmp_path)
    # Even with the raw "prompt" key, presence of a "prompt_digest" sibling
    # tells the schema-level CHECK that the redaction has occurred AND the
    # digest is recorded. (Production callers MUST use anti_bypass for the
    # richer check; this proves the CHECK does not over-reject.)
    _direct_insert(
        db_path,
        payload={
            "prompt": "[REDACTED]",
            "prompt_digest": "sha256-abc",
        },
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-036")
def test_blob_reference_payload_accepted(tmp_path: Path) -> None:
    """A spilled payload ({_blob_sha256: ...}) MUST pass trivially."""
    db_path = _seed_db(tmp_path)
    _direct_insert(
        db_path,
        payload={"_blob_sha256": "deadbeef" * 8},
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-036")
def test_empty_payload_accepted(tmp_path: Path) -> None:
    """Empty payload MUST pass trivially."""
    db_path = _seed_db(tmp_path)
    _direct_insert(db_path, payload={})


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-036")
def test_constraint_name_appears_in_error(tmp_path: Path) -> None:
    """The error message MUST name the trigger so audit logs can correlate."""
    db_path = _seed_db(tmp_path)
    try:
        _direct_insert(db_path, payload={"prompt": "secret"})
    except sqlite3.IntegrityError as e:
        assert "event_log_entries_payload_raw_check" in str(e), str(e)
    else:
        pytest.fail("expected IntegrityError but the insert succeeded")
