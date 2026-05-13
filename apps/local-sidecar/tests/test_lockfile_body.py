"""VAL-W2-002: Lockfile body has exactly the required keys.

Required key set: {pid, port, launched_at, launched_by, sidecar_version,
bearer_token_digest}. Missing any -> RELAY-SIDECAR-LOCKFILE-MALFORMED.
Extras also rejected by ``extra='forbid'``.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from relay_sidecar.errors import (
    RELAY_SIDECAR_LOCKFILE_MALFORMED,
    RELAY_SIDECAR_LOCKFILE_MALFORMED_CODE,
    SidecarError,
)
from relay_sidecar.lockfile import (
    LockfileBody,
    parse_lockfile_body,
    serialize_lockfile_body,
)
from relay_sidecar.spawn import acquire_or_attach

REQUIRED_KEYS = {
    "pid",
    "port",
    "launched_at",
    "launched_by",
    "sidecar_version",
    "bearer_token_digest",
}


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-002")
def test_spawn_lockfile_body_contains_exact_required_keys(
    relay_home_tmp: Path,
) -> None:
    decision = acquire_or_attach(
        home=relay_home_tmp,
        process_runner=lambda: (os.getpid(), 50001),
    )
    raw = (relay_home_tmp / "sidecar.lock").read_bytes()
    data = json.loads(raw)
    assert isinstance(data, dict)
    assert set(data.keys()) == REQUIRED_KEYS, (
        f"observed={set(data.keys())} expected={REQUIRED_KEYS}"
    )
    # Sanity: pid round-trips.
    assert data["pid"] == decision.lockfile_body.pid


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-002")
def test_parse_rejects_missing_key() -> None:
    body = {
        "pid": 1234,
        "port": 12345,
        "launched_at": "2026-05-13T12:00:00Z",
        "launched_by": "tester",
        "sidecar_version": "0.0.0",
        # bearer_token_digest deliberately omitted
    }
    with pytest.raises(SidecarError) as exc:
        parse_lockfile_body(json.dumps(body).encode("utf-8"))
    assert exc.value.code == RELAY_SIDECAR_LOCKFILE_MALFORMED_CODE
    assert exc.value.error_class == RELAY_SIDECAR_LOCKFILE_MALFORMED
    details = exc.value.details or {}
    assert "bearer_token_digest" in details.get("missing_keys", [])


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-002")
def test_parse_rejects_extra_key() -> None:
    body = {
        "pid": 1234,
        "port": 12345,
        "launched_at": "2026-05-13T12:00:00Z",
        "launched_by": "tester",
        "sidecar_version": "0.0.0",
        "bearer_token_digest": "sha256-" + "a" * 64,
        "extra_field_we_did_not_declare": "boom",
    }
    with pytest.raises(SidecarError) as exc:
        parse_lockfile_body(json.dumps(body).encode("utf-8"))
    assert exc.value.code == RELAY_SIDECAR_LOCKFILE_MALFORMED_CODE


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-002")
def test_parse_rejects_non_json_input() -> None:
    with pytest.raises(SidecarError) as exc:
        parse_lockfile_body(b"not-json")
    assert exc.value.code == RELAY_SIDECAR_LOCKFILE_MALFORMED_CODE


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-002")
def test_parse_rejects_empty_input() -> None:
    with pytest.raises(SidecarError) as exc:
        parse_lockfile_body(b"")
    assert exc.value.code == RELAY_SIDECAR_LOCKFILE_MALFORMED_CODE


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-002")
def test_round_trip_canonical_serializer() -> None:
    body = LockfileBody(
        pid=4321,
        port=49152,
        launched_at="2026-05-13T12:00:00Z",
        launched_by="round-trip-user",
        sidecar_version="0.0.0",
        bearer_token_digest="sha256-" + "b" * 64,
    )
    raw = serialize_lockfile_body(body)
    parsed = parse_lockfile_body(raw)
    assert parsed == body
