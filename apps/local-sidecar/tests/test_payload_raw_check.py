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


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-036")
def test_raw_capture_gate_does_not_recurse_on_deeply_nested_body() -> None:
    """Round-7 re-hunt: the raw_capture default-deny gate runs BEFORE the
    nesting-depth cap, so a deeply-nested ingest body must NOT raise
    RecursionError (an unhandled-500 DoS). _iter_string_leaves is iterative.
    """
    import json

    from relay_sidecar.validation.raw_capture import (
        _iter_string_leaves,
        evaluate_raw_capture_on_request,
    )

    # 6000-deep nested list (~12 KB) exceeds CPython's 1000-frame recursion
    # limit; a recursive walk would raise RecursionError.
    nested = json.loads("[" * 6000 + '"deep-secret"' + "]" * 6000)

    # Leaf walk must complete without recursion error.
    leaves = list(_iter_string_leaves(nested))
    assert leaves[-1][1] == "deep-secret"

    # End-to-end default-deny gate (no applied policy -> raw_capture False)
    # must REJECT the raw-eligible field, not crash.
    rejection = evaluate_raw_capture_on_request(
        body={"model_call": {"input": nested}}
    )
    assert rejection is not None
    assert rejection.code == "RELAY-INGEST-RAWCAPTURE-DENIED"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-036")
def test_iter_string_leaves_preserves_depth_first_left_to_right_order() -> None:
    """The iterative walk yields leaves in the SAME order as the prior
    recursive version (the path the rejection envelope reports)."""
    from relay_sidecar.validation.raw_capture import _iter_string_leaves

    value = {"a": [{"b": "x"}, "y"], "c": "z"}
    assert list(_iter_string_leaves(value)) == [
        (("a", "0", "b"), "x"),
        (("a", "1"), "y"),
        (("c",), "z"),
    ]
