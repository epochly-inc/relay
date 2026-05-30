"""VAL-W2-057: sidecar refuses event_log payloads containing bypass markers.

The W2.5 anti_bypass module scans payloads for the canonical bypass-marker
token set::

    --no-verify, --no-gpg-sign, --skip-hooks,
    pytest.mark.skip,
    # TODO, # FIXME, # HACK

Detection rejects with error envelope code RELAY-SIDECAR-009 (descriptive
``RELAY-SIDECAR-BYPASS-MARKER-DETECTED``). Legitimate override path:
event_kind = 'operator_override' + operator_override_claim with actor
resolving via the W2.4 actors registry to kind='human' + org_admin=1.

ASCII-only per CLAUDE.md.
"""

from __future__ import annotations

import asyncio
import uuid
from pathlib import Path

import pytest
from relay_sidecar.anti_bypass import (
    BYPASS_MARKER_DETECTED_CLASS,
    BYPASS_MARKER_DETECTED_CODE,
    BYPASS_MARKERS,
    OPERATOR_OVERRIDE_EVENT_KIND,
    AntiBypassRejection,
    detect_bypass_markers,
    raise_on_reject,
    screen_payload,
)
from relay_sidecar.db import SidecarDatabase


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-057")
def test_marker_set_matches_contract() -> None:
    """Every contract-pinned marker MUST be in BYPASS_MARKERS."""
    expected = {
        "--no-verify",
        "--no-gpg-sign",
        "--skip-hooks",
        "pytest.mark.skip",
        "# TODO",
        "# FIXME",
        "# HACK",
    }
    assert set(BYPASS_MARKERS) == expected, (set(BYPASS_MARKERS), expected)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-057")
@pytest.mark.parametrize(
    "marker",
    [
        "--no-verify",
        "--no-gpg-sign",
        "--skip-hooks",
        "pytest.mark.skip",
        "# TODO",
        "# FIXME",
        "# HACK",
    ],
)
def test_marker_detected_in_string_value(marker: str) -> None:
    """Each marker MUST be detected when present as a JSON string value."""
    payload = {"comment": marker}
    found = detect_bypass_markers(
        # Render the same way anti_bypass does internally.
        '{"comment":"' + marker + '"}'
    )
    assert marker in found, (marker, found)
    _ = payload  # keep parametrize value visible to ide


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-057")
def test_no_false_positive_for_near_miss() -> None:
    """Substring near-misses (e.g. --no-verifyish) MUST NOT match."""
    found = detect_bypass_markers('{"x":"--no-verifyish"}')
    assert found == ()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-057")
def test_screen_clean_payload_accepts() -> None:
    """Clean payload MUST pass."""
    result = asyncio.run(
        screen_payload(payload={"foo": "bar"}, event_kind="state_transition")
    )
    assert result.ok is True


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-057")
def test_screen_flagged_payload_rejects() -> None:
    """Payload with a bypass marker MUST be rejected with structured tokens."""
    result = asyncio.run(
        screen_payload(
            payload={"args": ["git", "commit", "--no-verify"]},
            event_kind="state_transition",
        )
    )
    assert result.ok is False
    assert "--no-verify" in result.detected_tokens
    assert result.reason_kind == BYPASS_MARKER_DETECTED_CLASS


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-057")
def test_raise_on_reject_surfaces_envelope() -> None:
    """raise_on_reject MUST raise AntiBypassRejection with code + tokens."""
    result = asyncio.run(
        screen_payload(payload={"x": "# TODO"}, event_kind=None)
    )
    with pytest.raises(AntiBypassRejection) as excinfo:
        raise_on_reject(result)
    envelope = excinfo.value.to_envelope()
    assert envelope["code"] == BYPASS_MARKER_DETECTED_CODE
    assert envelope["error_class"] == BYPASS_MARKER_DETECTED_CLASS
    # to_envelope() is typed dict[str, object]; narrow the nested details map
    # so the membership check type-checks without changing the assertion.
    details = envelope["details"]
    assert isinstance(details, dict)
    assert "# TODO" in details["detected_tokens"]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-057")
def test_error_code_format_is_w1_compliant() -> None:
    """RELAY-SIDECAR-009 MUST match ^RELAY-[A-Z]+-[0-9]{3}$."""
    import re

    assert re.match(r"^RELAY-[A-Z]+-[0-9]{3}$", BYPASS_MARKER_DETECTED_CODE)


def _seed_actor(
    db_path: Path,
    *,
    identity_hash: str,
    kind: str,
    org_admin: int,
    revoked: bool = False,
) -> None:
    """Insert an actors row for the operator_override path test."""
    import sqlite3
    from datetime import UTC, datetime

    now = (
        datetime.now(tz=UTC)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute(
            "INSERT INTO actors "
            "(identity_hash, kind, display_name, org_admin, registered_at, revoked_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                identity_hash,
                kind,
                "test-actor",
                org_admin,
                now,
                now if revoked else None,
            ),
        )
        conn.commit()
    finally:
        conn.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-057")
def test_operator_override_path_permits_marker(tmp_path: Path) -> None:
    """Marker payload + valid human org_admin override claim MUST be accepted."""
    async def _run() -> None:
        db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
        await db.open()
        try:
            identity = "sha256-" + ("a" * 64)
            _seed_actor(
                tmp_path / "sidecar.db",
                identity_hash=identity,
                kind="human",
                org_admin=1,
            )
            result = await screen_payload(
                payload={"args": ["--no-verify"]},
                event_kind=OPERATOR_OVERRIDE_EVENT_KIND,
                operator_override_claim={"actor_identity_hash": identity},
                actors_connection=db._writer,
            )
            assert result.ok is True, result
        finally:
            await db.close()

    asyncio.run(_run())


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-057")
def test_operator_override_with_non_admin_rejected(tmp_path: Path) -> None:
    """Marker payload + non-admin override actor MUST be rejected."""
    async def _run() -> None:
        db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
        await db.open()
        try:
            identity = "sha256-" + ("b" * 64)
            _seed_actor(
                tmp_path / "sidecar.db",
                identity_hash=identity,
                kind="human",
                org_admin=0,
            )
            result = await screen_payload(
                payload={"args": ["--no-verify"]},
                event_kind=OPERATOR_OVERRIDE_EVENT_KIND,
                operator_override_claim={"actor_identity_hash": identity},
                actors_connection=db._writer,
            )
            assert result.ok is False, result
        finally:
            await db.close()

    asyncio.run(_run())


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-057")
def test_operator_override_revoked_actor_rejected(tmp_path: Path) -> None:
    """A revoked actor MUST NOT bypass the marker scan."""
    async def _run() -> None:
        db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
        await db.open()
        try:
            identity = "sha256-" + ("c" * 64)
            _seed_actor(
                tmp_path / "sidecar.db",
                identity_hash=identity,
                kind="human",
                org_admin=1,
                revoked=True,
            )
            result = await screen_payload(
                payload={"args": ["--no-verify"]},
                event_kind=OPERATOR_OVERRIDE_EVENT_KIND,
                operator_override_claim={"actor_identity_hash": identity},
                actors_connection=db._writer,
            )
            assert result.ok is False, result
        finally:
            await db.close()

    asyncio.run(_run())


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-057")
def test_operator_override_missing_claim_rejected(tmp_path: Path) -> None:
    """event_kind='operator_override' without a claim MUST be rejected."""
    async def _run() -> None:
        db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
        await db.open()
        try:
            result = await screen_payload(
                payload={"args": ["--no-verify"]},
                event_kind=OPERATOR_OVERRIDE_EVENT_KIND,
                operator_override_claim=None,
                actors_connection=db._writer,
            )
            assert result.ok is False, result
        finally:
            await db.close()

    asyncio.run(_run())


# Pyflakes pacifier.
_ = uuid
