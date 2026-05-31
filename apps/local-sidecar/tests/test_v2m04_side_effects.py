"""V2 M04 w4-side-effects sidecar tests.

Covers contract assertions for the server-side enforcement validators,
the marker/proof writer, the replay-namespace isolation, the
resurrection check, and the compensation invocation hook.

Targets:
  - VAL-V2M04-011..017 (span ingest enforcement)
  - VAL-V2M04-018..022 (resurrection + compensation)
  - VAL-V2M04-026..029 (replay class blocking codes)
  - VAL-V2M04-033..035 (control plane writer + atomic primitive + handoff)

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import aiosqlite
import pytest
from relay_sidecar.side_effect_markers import (
    CANONICAL_SIDE_EFFECT_CLASSES,
    ENFORCED_SIDE_EFFECT_CLASSES,
    MARKER_STATE_IN_FLIGHT,
    MARKER_STATE_PENDING,
    MARKER_STATES,
    RELAY_REPLAY_014,
    RELAY_REPLAY_APPROVAL_EXPIRED,
    RELAY_REPLAY_APPROVAL_REQUIRED,
    RELAY_REPLAY_APPROVAL_TOKEN_CONSUMED,
    RELAY_SIDEEFFECT_MARKER_MISSING,
    RELAY_SIDEEFFECT_PROOF_MISSING,
    RELAY_SIDEEFFECT_REPLAY_PREFIX_MISSING,
    RELAY_SIDEEFFECT_REPLAY_PREFIX_PROD,
    REPLAY_SUBCODE_APPROVAL_EXPIRED,
    REPLAY_SUBCODE_APPROVAL_REQUIRED,
    REPLAY_SUBCODE_APPROVAL_TOKEN_CONSUMED,
    SIDE_EFFECT_APPROVAL_REQUIRED,
    SIDE_EFFECT_EXTERNAL_IRREVERSIBLE,
    SIDE_EFFECT_MUTATING,
    SIDE_EFFECT_READ_ONLY,
    SIDEEFFECT_SUBCODE_MARKER_MISSING,
    SIDEEFFECT_SUBCODE_PROOF_MISSING,
    SIDEEFFECT_SUBCODE_REPLAY_PREFIX_MISSING,
    SIDEEFFECT_SUBCODE_REPLAY_PREFIX_PROD,
    build_compensation_event_payload,
    build_marker_row,
    build_proof_row,
    build_resurrection_event_payload,
    check_span_marker_pairing,
    expected_replay_prefix,
    is_canonical_side_effect_class,
    is_enforced_class,
    scan_orphan_markers,
    validate_replay_namespace_prefix,
    validate_span_batch,
)

_THIS = Path(__file__).resolve()
_REPO_ROOT = _THIS.parents[3]


def _new_uuid() -> str:
    return str(uuid.uuid4())


def _now_iso() -> str:
    return datetime.now(tz=UTC).isoformat()


# ---------------------------------------------------------------------------
# Constant validation (load-bearing)
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_canonical_side_effect_classes_is_exactly_four() -> None:
    """Spec E.3 lines 3931-3936 lock the four canonical classes."""
    assert frozenset(
        {
            "read_only",
            "mutating",
            "external_irreversible",
            "approval_required",
        }
    ) == CANONICAL_SIDE_EFFECT_CLASSES


@pytest.mark.plumbing
def test_enforced_classes_excludes_read_only() -> None:
    """read_only is exempt per spec line 5177 / VAL-V2M04-015."""
    assert SIDE_EFFECT_READ_ONLY not in ENFORCED_SIDE_EFFECT_CLASSES
    assert SIDE_EFFECT_MUTATING in ENFORCED_SIDE_EFFECT_CLASSES
    assert SIDE_EFFECT_EXTERNAL_IRREVERSIBLE in ENFORCED_SIDE_EFFECT_CLASSES
    assert SIDE_EFFECT_APPROVAL_REQUIRED in ENFORCED_SIDE_EFFECT_CLASSES


@pytest.mark.plumbing
def test_marker_states_is_exactly_six() -> None:
    """Spec line 5144 lists six legal states."""
    assert frozenset(
        {
            "pending",
            "in_flight",
            "succeeded",
            "failed",
            "compensated",
            "blocked_by_approval",
        }
    ) == MARKER_STATES


@pytest.mark.plumbing
def test_is_canonical_side_effect_class_truth_table() -> None:
    assert is_canonical_side_effect_class("read_only")
    assert is_canonical_side_effect_class("mutating")
    assert is_canonical_side_effect_class("external_irreversible")
    assert is_canonical_side_effect_class("approval_required")
    assert not is_canonical_side_effect_class("none")
    assert not is_canonical_side_effect_class("reversible")
    assert not is_canonical_side_effect_class("READ_ONLY")
    assert not is_canonical_side_effect_class("")
    assert not is_canonical_side_effect_class(None)
    assert not is_canonical_side_effect_class(42)


@pytest.mark.plumbing
def test_is_enforced_class_truth_table() -> None:
    assert not is_enforced_class("read_only")
    assert is_enforced_class("mutating")
    assert is_enforced_class("external_irreversible")
    assert is_enforced_class("approval_required")
    assert not is_enforced_class("none")
    assert not is_enforced_class(None)


# ---------------------------------------------------------------------------
# Wire code validation (numeric form per VAL-W1-029)
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_sideeffect_wire_codes_match_w1_029_regex() -> None:
    """Per VAL-W1-029 every wire code matches ^RELAY-[A-Z]+-[0-9]{3}$."""
    pattern = re.compile(r"^RELAY-[A-Z]+-[0-9]{3}$")
    for code in (
        RELAY_SIDEEFFECT_MARKER_MISSING,
        RELAY_SIDEEFFECT_PROOF_MISSING,
        RELAY_SIDEEFFECT_REPLAY_PREFIX_MISSING,
        RELAY_SIDEEFFECT_REPLAY_PREFIX_PROD,
        RELAY_REPLAY_014,
        RELAY_REPLAY_APPROVAL_REQUIRED,
        RELAY_REPLAY_APPROVAL_TOKEN_CONSUMED,
        RELAY_REPLAY_APPROVAL_EXPIRED,
    ):
        assert pattern.match(code), code


@pytest.mark.plumbing
def test_subcode_aliases_carry_descriptive_form() -> None:
    """Per CLAUDE.md, the descriptive alias is preserved in details.subcode."""
    assert SIDEEFFECT_SUBCODE_MARKER_MISSING == "MARKER_MISSING"
    assert SIDEEFFECT_SUBCODE_PROOF_MISSING == "PROOF_MISSING"
    assert SIDEEFFECT_SUBCODE_REPLAY_PREFIX_MISSING == "REPLAY_PREFIX_MISSING"
    assert SIDEEFFECT_SUBCODE_REPLAY_PREFIX_PROD == "REPLAY_PREFIX_PROD"
    assert REPLAY_SUBCODE_APPROVAL_REQUIRED == "APPROVAL_REQUIRED"
    assert REPLAY_SUBCODE_APPROVAL_TOKEN_CONSUMED == "APPROVAL_TOKEN_CONSUMED"
    assert REPLAY_SUBCODE_APPROVAL_EXPIRED == "APPROVAL_EXPIRED"


# ---------------------------------------------------------------------------
# VAL-V2M04-011: mutating without paired marker -> MARKER-MISSING
# ---------------------------------------------------------------------------


def _span(
    *,
    side_effect_class: str,
    idempotency_key: str | None = "key-1",
) -> dict[str, Any]:
    return {
        "span_id": _new_uuid(),
        "side_effect_class": side_effect_class,
        "tool_name": "create_case_note",
        "idempotency_key": idempotency_key,
    }


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-011")
def test_mutating_without_marker_rejected_with_marker_missing() -> None:
    rejection = check_span_marker_pairing(
        span=_span(side_effect_class="mutating"),
        has_marker=False,
        has_proof=False,
    )
    assert rejection is not None
    assert rejection.code == RELAY_SIDEEFFECT_MARKER_MISSING
    assert rejection.details["subcode"] == SIDEEFFECT_SUBCODE_MARKER_MISSING
    assert rejection.details["side_effect_class"] == "mutating"


# ---------------------------------------------------------------------------
# VAL-V2M04-012: mutating with marker but no proof -> PROOF-MISSING
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-012")
def test_mutating_with_marker_no_proof_rejected_with_proof_missing() -> None:
    rejection = check_span_marker_pairing(
        span=_span(side_effect_class="mutating"),
        has_marker=True,
        has_proof=False,
    )
    assert rejection is not None
    assert rejection.code == RELAY_SIDEEFFECT_PROOF_MISSING
    assert rejection.details["subcode"] == SIDEEFFECT_SUBCODE_PROOF_MISSING


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-012")
def test_mutating_with_marker_and_proof_accepted() -> None:
    rejection = check_span_marker_pairing(
        span=_span(side_effect_class="mutating"),
        has_marker=True,
        has_proof=True,
    )
    assert rejection is None


# ---------------------------------------------------------------------------
# VAL-V2M04-013: external_irreversible same rejection logic as mutating
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-013")
def test_external_irreversible_without_marker_rejected() -> None:
    rejection = check_span_marker_pairing(
        span=_span(side_effect_class="external_irreversible"),
        has_marker=False,
        has_proof=False,
    )
    assert rejection is not None
    assert rejection.code == RELAY_SIDEEFFECT_MARKER_MISSING


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-013")
def test_external_irreversible_with_marker_no_proof_rejected() -> None:
    rejection = check_span_marker_pairing(
        span=_span(side_effect_class="external_irreversible"),
        has_marker=True,
        has_proof=False,
    )
    assert rejection is not None
    assert rejection.code == RELAY_SIDEEFFECT_PROOF_MISSING


# ---------------------------------------------------------------------------
# VAL-V2M04-014: approval_required same rejection logic
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-014")
def test_approval_required_without_marker_rejected() -> None:
    rejection = check_span_marker_pairing(
        span=_span(side_effect_class="approval_required"),
        has_marker=False,
        has_proof=False,
    )
    assert rejection is not None
    assert rejection.code == RELAY_SIDEEFFECT_MARKER_MISSING


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-014")
def test_approval_required_blocked_by_approval_without_proof_rejected() -> None:
    """A marker in blocked_by_approval state without a user_acknowledgement
    proof is insufficient (VAL-V2M04-014)."""
    rejection = check_span_marker_pairing(
        span=_span(side_effect_class="approval_required"),
        has_marker=True,
        has_proof=False,
    )
    assert rejection is not None
    assert rejection.code == RELAY_SIDEEFFECT_PROOF_MISSING


# ---------------------------------------------------------------------------
# VAL-V2M04-015: read_only bypasses marker/proof check
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-015")
def test_read_only_bypasses_marker_proof_check() -> None:
    """span_ingest with side_effect_class='read_only' is accepted without
    any marker or proof (spec X line 5177, VAL-V2M04-015)."""
    rejection = check_span_marker_pairing(
        span=_span(side_effect_class="read_only"),
        has_marker=False,
        has_proof=False,
    )
    assert rejection is None


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-015")
def test_validate_span_batch_accepts_read_only_only_batch() -> None:
    spans = [
        _span(side_effect_class="read_only", idempotency_key=None),
        _span(side_effect_class="read_only", idempotency_key="key-x"),
    ]
    rejection = validate_span_batch(
        spans=spans,
        marker_existence_fn=lambda k: False,
        proof_existence_fn=lambda k: False,
    )
    assert rejection is None


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-011")
def test_validate_span_batch_rejects_first_failing_mutating_span() -> None:
    spans = [
        _span(side_effect_class="read_only", idempotency_key=None),
        _span(side_effect_class="mutating", idempotency_key="key-mut"),
    ]
    rejection = validate_span_batch(
        spans=spans,
        marker_existence_fn=lambda k: False,
        proof_existence_fn=lambda k: False,
    )
    assert rejection is not None
    assert rejection.code == RELAY_SIDEEFFECT_MARKER_MISSING


# ---------------------------------------------------------------------------
# VAL-V2M04-016 / VAL-V2M04-017: replay-namespace prefix isolation
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-016")
def test_expected_replay_prefix_format() -> None:
    case_id = "abc-123"
    assert expected_replay_prefix(case_id) == "replay:abc-123:"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-016")
def test_replay_prefix_accepts_matching_key() -> None:
    case_id = "case-7"
    key = f"replay:{case_id}:create_case_note:42"
    rejection = validate_replay_namespace_prefix(
        idempotency_key=key,
        active_replay_case_id=case_id,
    )
    assert rejection is None


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-016")
def test_production_marker_with_no_replay_context_is_accepted() -> None:
    rejection = validate_replay_namespace_prefix(
        idempotency_key="create_case_note:42",
        active_replay_case_id=None,
    )
    assert rejection is None


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-017")
def test_replay_context_rejects_key_without_prefix() -> None:
    rejection = validate_replay_namespace_prefix(
        idempotency_key="create_case_note:42",
        active_replay_case_id="case-7",
    )
    assert rejection is not None
    assert rejection.code == RELAY_SIDEEFFECT_REPLAY_PREFIX_MISSING
    assert rejection.details["subcode"] == SIDEEFFECT_SUBCODE_REPLAY_PREFIX_MISSING
    assert rejection.details["expected_prefix"] == "replay:case-7:"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-017")
def test_replay_context_rejects_key_with_wrong_case_id_prefix() -> None:
    """A key prefixed with 'replay:other-case:' in the context of 'case-7'
    is still rejected."""
    rejection = validate_replay_namespace_prefix(
        idempotency_key="replay:other-case:create_case_note:42",
        active_replay_case_id="case-7",
    )
    assert rejection is not None
    assert rejection.code == RELAY_SIDEEFFECT_REPLAY_PREFIX_MISSING


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-017")
def test_production_context_rejects_replay_prefixed_key() -> None:
    """Defensive opposite: a 'replay:' key in production rejected."""
    rejection = validate_replay_namespace_prefix(
        idempotency_key="replay:case-7:create_case_note:42",
        active_replay_case_id=None,
    )
    assert rejection is not None
    assert rejection.code == RELAY_SIDEEFFECT_REPLAY_PREFIX_PROD
    assert rejection.details["subcode"] == SIDEEFFECT_SUBCODE_REPLAY_PREFIX_PROD


# ---------------------------------------------------------------------------
# Row builder validation
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_build_marker_row_includes_all_required_columns() -> None:
    row = build_marker_row(
        run_id=_new_uuid(),
        span_id=_new_uuid(),
        tool_name="t",
        idempotency_key="k",
        policy_id=_new_uuid(),
    )
    required = {
        "marker_id",
        "run_id",
        "span_id",
        "tool_name",
        "idempotency_key",
        "policy_id",
        "state",
        "created_at",
        "expires_at",
    }
    missing = required - row.keys()
    assert not missing, missing
    assert row["state"] == MARKER_STATE_PENDING


@pytest.mark.plumbing
def test_build_marker_row_default_expires_at_is_not_immediately_orphaned() -> None:
    """When ``expires_at`` is omitted the row MUST NOT be immediately
    eligible for the orphan scan.

    Regression for the audit P1: prior to the fix, ``build_marker_row``
    defaulted ``expires_at`` to ``_now_iso()``, so the very next call
    to ``scan_orphan_markers`` (whose SQL is
    ``WHERE state = 'in_flight' AND expires_at < now()``) classified
    the marker as an orphan and silently fired the compensation hook.
    """
    row = build_marker_row(
        run_id=_new_uuid(),
        span_id=_new_uuid(),
        tool_name="t",
        idempotency_key="k",
        policy_id=_new_uuid(),
    )
    # Parse the ISO 8601 timestamp; accept the trailing 'Z' suffix used
    # by the V2M04 module.
    expires_str = row["expires_at"]
    assert isinstance(expires_str, str) and expires_str
    expires = datetime.fromisoformat(expires_str.replace("Z", "+00:00"))
    now = datetime.now(tz=UTC)
    # The default lifetime is one hour; allow generous slack for slow
    # CI machines (the assertion is "well in the future", not the exact
    # value).
    assert expires > now + timedelta(minutes=30), (
        f"default expires_at must be at least 30 minutes in the future; "
        f"got expires={expires_str!r}, now={now.isoformat()!r}"
    )
    assert expires < now + timedelta(hours=24), (
        f"default expires_at must not be more than 24h in the future; "
        f"got {expires_str!r}"
    )


@pytest.mark.plumbing
def test_build_marker_row_honors_explicit_expires_at() -> None:
    """Explicit ``expires_at`` overrides the default-future timestamp."""
    explicit = "2099-01-01T00:00:00+00:00"
    row = build_marker_row(
        run_id=_new_uuid(),
        span_id=_new_uuid(),
        tool_name="t",
        idempotency_key="k",
        policy_id=_new_uuid(),
        expires_at=explicit,
    )
    assert row["expires_at"] == explicit


@pytest.mark.plumbing
def test_build_marker_row_rejects_invalid_state() -> None:
    with pytest.raises(ValueError, match="state must be one of"):
        build_marker_row(
            run_id=_new_uuid(),
            span_id=_new_uuid(),
            tool_name="t",
            idempotency_key="k",
            policy_id=_new_uuid(),
            state="completed",
        )


@pytest.mark.plumbing
def test_build_proof_row_includes_all_required_columns() -> None:
    row = build_proof_row(
        marker_id=_new_uuid(),
        evidence_kind="exit_code",
        evidence_digest="sha256-abc",
    )
    required = {
        "proof_id",
        "marker_id",
        "evidence_kind",
        "evidence_digest",
        "external_id",
        "recorded_at",
    }
    missing = required - row.keys()
    assert not missing, missing


# ---------------------------------------------------------------------------
# VAL-V2M04-018..020: resurrection check
# ---------------------------------------------------------------------------


async def _make_db_with_side_effect_tables() -> aiosqlite.Connection:
    """Open a fresh in-memory aiosqlite connection and apply the 0018
    migration. Returns the connection; caller closes."""
    conn = await aiosqlite.connect(":memory:")
    await conn.execute("PRAGMA foreign_keys = ON")
    migration_path = (
        _REPO_ROOT
        / "apps"
        / "local-sidecar"
        / "migrations"
        / "0018_side_effects.sql"
    )
    sql = migration_path.read_text(encoding="utf-8")
    await conn.executescript(sql)
    await conn.commit()
    return conn


async def _seed_policy(
    conn: aiosqlite.Connection,
    *,
    policy_id: str | None = None,
    compensation_tool: str | None = None,
    max_retries: int = 1,
) -> str:
    pid = policy_id or _new_uuid()
    await conn.execute(
        "INSERT INTO tool_side_effect_policies "
        "(policy_id, project_id, tool_name, side_effect_class, "
        "compensation_tool, max_retries, effective_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            pid,
            _new_uuid(),
            "create_case_note",
            "mutating",
            compensation_tool,
            max_retries,
            _now_iso(),
        ),
    )
    await conn.commit()
    return pid


async def _seed_marker(
    conn: aiosqlite.Connection,
    *,
    policy_id: str,
    state: str,
    expires_at: str,
    idempotency_key: str | None = None,
) -> str:
    mid = _new_uuid()
    await conn.execute(
        "INSERT INTO side_effect_markers "
        "(marker_id, run_id, span_id, tool_name, idempotency_key, "
        "policy_id, state, created_at, expires_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            mid,
            _new_uuid(),
            _new_uuid(),
            "create_case_note",
            idempotency_key or f"key-{mid}",
            policy_id,
            state,
            _now_iso(),
            expires_at,
        ),
    )
    await conn.commit()
    return mid


@pytest.mark.plumbing
@pytest.mark.asyncio
@pytest.mark.fulfills("VAL-V2M04-018")
async def test_resurrection_scan_finds_orphan_in_flight_markers() -> None:
    """Seed 3 in_flight markers past expires_at; scan returns all three."""
    conn = await _make_db_with_side_effect_tables()
    try:
        pid = await _seed_policy(conn)
        past = (datetime.now(tz=UTC) - timedelta(hours=1)).isoformat()
        for _ in range(3):
            await _seed_marker(
                conn,
                policy_id=pid,
                state=MARKER_STATE_IN_FLIGHT,
                expires_at=past,
            )
        findings = await scan_orphan_markers(conn)
        assert len(findings) == 3
        for f in findings:
            assert f.state == MARKER_STATE_IN_FLIGHT
            assert f.expires_at == past
    finally:
        await conn.close()


@pytest.mark.plumbing
@pytest.mark.asyncio
@pytest.mark.fulfills("VAL-V2M04-019")
async def test_resurrection_skips_non_expired_in_flight_markers() -> None:
    """Markers with expires_at > now are NOT included in the scan."""
    conn = await _make_db_with_side_effect_tables()
    try:
        pid = await _seed_policy(conn)
        future = (datetime.now(tz=UTC) + timedelta(hours=1)).isoformat()
        await _seed_marker(
            conn,
            policy_id=pid,
            state=MARKER_STATE_IN_FLIGHT,
            expires_at=future,
        )
        # And one expired one for contrast:
        past = (datetime.now(tz=UTC) - timedelta(hours=1)).isoformat()
        await _seed_marker(
            conn,
            policy_id=pid,
            state=MARKER_STATE_IN_FLIGHT,
            expires_at=past,
        )
        findings = await scan_orphan_markers(conn)
        assert len(findings) == 1
        assert findings[0].expires_at == past
    finally:
        await conn.close()


@pytest.mark.plumbing
@pytest.mark.asyncio
@pytest.mark.fulfills("VAL-V2M04-019")
async def test_resurrection_skips_non_in_flight_states() -> None:
    """Markers in pending/succeeded/failed/etc. are NOT included."""
    conn = await _make_db_with_side_effect_tables()
    try:
        pid = await _seed_policy(conn)
        past = (datetime.now(tz=UTC) - timedelta(hours=1)).isoformat()
        for state in ("pending", "succeeded", "failed", "compensated"):
            await _seed_marker(
                conn,
                policy_id=pid,
                state=state,
                expires_at=past,
            )
        findings = await scan_orphan_markers(conn)
        assert findings == []
    finally:
        await conn.close()


@pytest.mark.plumbing
@pytest.mark.asyncio
@pytest.mark.fulfills("VAL-CANON-004")
async def test_resurrection_scan_z_suffixed_expires_at_vs_plus0000_cutoff() -> None:
    """VAL-CANON-004: a 'Z'-suffixed expires_at must compare correctly
    against a '+00:00'-suffixed cutoff.

    ``build_marker_row`` serializes ``expires_at`` via
    ``_now_plus_seconds_iso`` which ends in ``Z`` (and omits the
    fractional part on a whole second). The default cutoff is
    ``_now_iso`` which ends in ``+00:00``. The old SQL did a
    lexicographic SQLite TEXT compare (``expires_at < cutoff``):
    ``Z`` (0x5A) sorts AFTER ``.`` (0x2E) and ``+`` (0x2B), so a marker
    that expired CHRONOLOGICALLY BEFORE the cutoff is wrongly classified
    as still live and silently dropped from the orphan set, breaking
    side-effect orphan reclamation. Both sides must be normalized to a
    single comparable UTC form before comparison.
    """
    conn = await _make_db_with_side_effect_tables()
    try:
        pid = await _seed_policy(conn)
        # Whole-second 'Z' timestamp -- exactly what _now_plus_seconds_iso
        # emits when microseconds are zero. Chronologically EARLIER than
        # the cutoff below, so this marker IS expired and MUST be an orphan.
        expired_z = "2026-05-28T20:03:44Z"
        # A '+00:00'-suffixed cutoff one microsecond LATER (the form
        # _now_iso produces). Lexicographically 'Z' > '.', so the buggy
        # string compare reports expired_z is NOT < cutoff and drops it.
        cutoff = "2026-05-28T20:03:44.000001+00:00"
        await _seed_marker(
            conn,
            policy_id=pid,
            state=MARKER_STATE_IN_FLIGHT,
            expires_at=expired_z,
        )
        findings = await scan_orphan_markers(conn, now_iso=cutoff)
        assert len(findings) == 1, (
            "expired 'Z'-suffixed marker must be classified as an orphan "
            "relative to a '+00:00' cutoff; raw string compare misclassifies "
            "it as live"
        )
        assert findings[0].expires_at == expired_z
    finally:
        await conn.close()


@pytest.mark.plumbing
@pytest.mark.asyncio
@pytest.mark.fulfills("VAL-CANON-004")
async def test_resurrection_scan_z_suffixed_non_expired_not_orphaned() -> None:
    """VAL-CANON-004 (control): a non-expired 'Z'-suffixed marker must NOT
    be classified as an orphan against a '+00:00' cutoff.

    Guards against an over-correction that flips every 'Z' marker to
    expired. Here ``expires_at`` is chronologically LATER than the cutoff,
    so the marker is still live and must be excluded.
    """
    conn = await _make_db_with_side_effect_tables()
    try:
        pid = await _seed_policy(conn)
        # 'Z' timestamp one microsecond AFTER the cutoff => still live.
        future_z = "2026-05-28T20:03:44.000002Z"
        cutoff = "2026-05-28T20:03:44.000001+00:00"
        await _seed_marker(
            conn,
            policy_id=pid,
            state=MARKER_STATE_IN_FLIGHT,
            expires_at=future_z,
        )
        findings = await scan_orphan_markers(conn, now_iso=cutoff)
        assert findings == [], (
            "non-expired 'Z'-suffixed marker must NOT be classified as an "
            "orphan against a '+00:00' cutoff"
        )
    finally:
        await conn.close()


# ---------------------------------------------------------------------------
# CANON-004 follow-up: orphan-scan index efficiency (canonical expires_at)
#
# The canon-004 correctness fix dropped the index-backed ``expires_at <
# cutoff`` range bound (it filtered by ``state`` only and re-compared in
# Python). These tests pin the follow-up: a single canonical,
# lexicographically-sortable UTC string form for ``expires_at`` and the
# cutoff so the SQL ``expires_at < ?`` compare is BOTH correct AND
# index-backed, with a Python fallback keeping correctness no weaker than
# the Python-only compare.
# ---------------------------------------------------------------------------


async def _make_db_with_canonical_expires_migration() -> aiosqlite.Connection:
    """Open a fresh in-memory DB, apply 0018 then the canon-004 follow-up
    migration (0034) that normalizes ``expires_at`` and confirms the
    composite ``(state, expires_at)`` index. Returns the connection."""
    conn = await aiosqlite.connect(":memory:")
    await conn.execute("PRAGMA foreign_keys = ON")
    migrations_dir = (
        _REPO_ROOT / "apps" / "local-sidecar" / "migrations"
    )
    for name in ("0018_side_effects.sql", "0034_side_effect_markers_expires_at_canonical.sql"):
        sql = (migrations_dir / name).read_text(encoding="utf-8")
        await conn.executescript(sql)
    await conn.commit()
    return conn


def _canonical_form_re() -> re.Pattern[str]:
    # YYYY-MM-DDTHH:MM:SS.ffffff+00:00 -- fixed width, microsecond
    # precision, explicit +00:00 UTC suffix.
    return re.compile(
        r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}\+00:00$"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CANON-004")
def test_build_marker_row_expires_at_is_canonical_sortable_form() -> None:
    """The marker write path must emit ``expires_at`` in the single
    canonical, lexicographically-sortable UTC form so the SQL range
    compare is correct AND index-backed.

    RED at base: ``_now_plus_seconds_iso`` emits a ``Z`` suffix and omits
    the microsecond fraction on a whole second, so the value is neither
    ``+00:00``-suffixed nor fixed width.
    """
    row = build_marker_row(
        run_id=_new_uuid(),
        span_id=_new_uuid(),
        tool_name="create_case_note",
        idempotency_key=f"key-{_new_uuid()}",
        policy_id=_new_uuid(),
    )
    expires_at = row["expires_at"]
    assert _canonical_form_re().match(expires_at), (
        "expires_at must be canonical YYYY-MM-DDTHH:MM:SS.ffffff+00:00 so "
        f"lexicographic order == chronological order; got {expires_at!r}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CANON-004")
def test_canonical_form_lexicographic_order_matches_chronological() -> None:
    """The canonical form sorts lexicographically in chronological order
    across whole-second and microsecond boundaries -- the property the
    index range scan relies on."""
    from relay_sidecar.side_effect_markers import _canonical_expires_at

    earlier = _canonical_expires_at(datetime(2026, 5, 28, 20, 3, 44, 0, tzinfo=UTC))
    later_us = _canonical_expires_at(datetime(2026, 5, 28, 20, 3, 44, 1, tzinfo=UTC))
    next_sec = _canonical_expires_at(datetime(2026, 5, 28, 20, 3, 45, 0, tzinfo=UTC))
    assert earlier < later_us < next_sec
    # All same width => raw string sort is total and chronological.
    assert len({len(earlier), len(later_us), len(next_sec)}) == 1


@pytest.mark.plumbing
@pytest.mark.asyncio
@pytest.mark.fulfills("VAL-CANON-004")
async def test_orphan_scan_uses_index_search_not_full_scan() -> None:
    """EXPLAIN QUERY PLAN for the orphan scan must SEARCH the
    ``(state, expires_at)`` composite index, not full-SCAN the table.

    RED at base: the canon-004 query is ``WHERE m.state = ?`` only, so the
    plan shows ``SEARCH ... USING INDEX side_effect_markers_state (state=?)``
    with no range bound on ``expires_at`` -- the index is used for the
    equality prefix but the ``expires_at`` range is evaluated in Python,
    pulling every in_flight row. This test asserts the ``expires_at``
    range bound appears in the plan.
    """
    conn = await _make_db_with_canonical_expires_migration()
    try:
        sql, params = _orphan_scan_explain_sql()
        rows = []
        async with conn.execute("EXPLAIN QUERY PLAN " + sql, params) as cur:
            async for row in cur:
                rows.append(str(row[-1]))
        plan = "\n".join(rows)
        assert "side_effect_markers" in plan, plan
        # Must SEARCH via an index, never full SCAN the markers table.
        assert "SCAN side_effect_markers" not in plan, (
            "orphan scan must not full-SCAN side_effect_markers; "
            f"plan was:\n{plan}"
        )
        assert "USING INDEX side_effect_markers_state" in plan, (
            "orphan scan must SEARCH the (state, expires_at) composite "
            f"index; plan was:\n{plan}"
        )
        # The index range bound on expires_at (the perf-restoring part)
        # must appear: SQLite renders it as "(state=? AND expires_at<?)".
        assert "expires_at<?" in plan.replace(" ", ""), (
            "orphan scan must apply an index range bound on expires_at "
            f"(state=? AND expires_at<?); plan was:\n{plan}"
        )
    finally:
        await conn.close()


@pytest.mark.plumbing
@pytest.mark.asyncio
@pytest.mark.fulfills("VAL-CANON-004")
async def test_orphan_scan_correct_with_canonical_written_markers() -> None:
    """End-to-end: markers written through the canonical write path are
    correctly classified by the index-backed scan (expired => orphan,
    fresh => excluded)."""
    conn = await _make_db_with_canonical_expires_migration()
    try:
        pid = await _seed_policy(conn)
        from relay_sidecar.side_effect_markers import _canonical_expires_at

        expired = _canonical_expires_at(datetime.now(tz=UTC) - timedelta(hours=1))
        fresh = _canonical_expires_at(datetime.now(tz=UTC) + timedelta(hours=1))
        await _seed_marker(
            conn, policy_id=pid, state=MARKER_STATE_IN_FLIGHT, expires_at=expired
        )
        await _seed_marker(
            conn, policy_id=pid, state=MARKER_STATE_IN_FLIGHT, expires_at=fresh
        )
        findings = await scan_orphan_markers(conn)
        assert len(findings) == 1
        assert findings[0].expires_at == expired
    finally:
        await conn.close()


@pytest.mark.plumbing
@pytest.mark.asyncio
@pytest.mark.fulfills("VAL-CANON-004")
async def test_orphan_scan_python_fallback_classifies_legacy_noncanonical_row() -> None:
    """A legacy row whose ``expires_at`` is NOT in canonical form (e.g. a
    ``Z`` suffix or no fraction) must still be classified correctly by the
    Python re-check, even when the SQL index bound (lexicographic) would
    mis-order it. Correctness must never be weaker than the canon-004
    Python-only compare.

    The defensive case: a legacy expired ``Z``-suffixed value that the
    canonical-cutoff string compare would NOT catch (Z sorts after the
    cutoff) MUST still be returned as an orphan via the Python fallback.
    """
    conn = await _make_db_with_canonical_expires_migration()
    try:
        pid = await _seed_policy(conn)
        # Legacy whole-second Z form, chronologically BEFORE the cutoff =>
        # expired. Lexicographically "...44Z" > "...44.000001+00:00"
        # (Z=0x5A > .=0x2E), so a pure SQL range bound would drop it; the
        # Python fallback must still classify it as an orphan.
        legacy_expired_z = "2026-05-28T20:03:44Z"
        cutoff = "2026-05-28T20:03:44.000001+00:00"
        await _seed_marker(
            conn,
            policy_id=pid,
            state=MARKER_STATE_IN_FLIGHT,
            expires_at=legacy_expired_z,
        )
        findings = await scan_orphan_markers(conn, now_iso=cutoff)
        assert len(findings) == 1, (
            "legacy non-canonical expired Z marker must still be an orphan "
            "via the Python fallback; the SQL index bound must not be the "
            "sole filter when the row is non-canonical"
        )
        assert findings[0].expires_at == legacy_expired_z
    finally:
        await conn.close()


@pytest.mark.plumbing
@pytest.mark.asyncio
@pytest.mark.fulfills("VAL-CANON-004")
async def test_migration_0034_normalizes_existing_expires_at_to_canonical() -> None:
    """The 0034 migration must rewrite existing ``expires_at`` values to the
    canonical form so legacy rows benefit from the index range bound.

    Seed legacy ``Z`` / fraction-less rows under the bare 0018 schema, then
    apply 0034, and assert every ``expires_at`` is canonical and denotes
    the same instant."""
    conn = await aiosqlite.connect(":memory:")
    try:
        await conn.execute("PRAGMA foreign_keys = ON")
        migrations_dir = _REPO_ROOT / "apps" / "local-sidecar" / "migrations"
        await conn.executescript(
            (migrations_dir / "0018_side_effects.sql").read_text(encoding="utf-8")
        )
        await conn.commit()
        pid = await _seed_policy(conn)
        # Two legacy non-canonical forms denoting the same instants.
        z_form = "2026-05-28T20:03:44Z"
        whole_plus = "2026-05-28T20:03:45+00:00"
        await _seed_marker(
            conn, policy_id=pid, state=MARKER_STATE_IN_FLIGHT, expires_at=z_form
        )
        await _seed_marker(
            conn, policy_id=pid, state=MARKER_STATE_IN_FLIGHT, expires_at=whole_plus
        )
        # Apply the normalization migration.
        await conn.executescript(
            (
                migrations_dir
                / "0034_side_effect_markers_expires_at_canonical.sql"
            ).read_text(encoding="utf-8")
        )
        await conn.commit()

        canon_re = _canonical_form_re()
        async with conn.execute(
            "SELECT expires_at FROM side_effect_markers ORDER BY expires_at"
        ) as cur:
            values = [str(r[0]) async for r in cur]
        assert len(values) == 2
        for v in values:
            assert canon_re.match(v), f"expires_at not canonical after 0034: {v!r}"
        # Same instants preserved (Z 44 < +00:00 45).
        assert values[0] == "2026-05-28T20:03:44.000000+00:00"
        assert values[1] == "2026-05-28T20:03:45.000000+00:00"
    finally:
        await conn.close()


@pytest.mark.plumbing
@pytest.mark.asyncio
@pytest.mark.fulfills("VAL-CANON-004")
async def test_side_effect_markers_state_index_exists() -> None:
    """The composite ``(state, expires_at)`` index must exist after the
    follow-up migration (the index the range scan depends on)."""
    conn = await _make_db_with_canonical_expires_migration()
    try:
        async with conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' "
            "AND name='side_effect_markers_state'"
        ) as cur:
            row = await cur.fetchone()
        assert row is not None, "side_effect_markers_state index must exist"
        async with conn.execute(
            "PRAGMA index_info('side_effect_markers_state')"
        ) as cur:
            cols = [str(r[2]) async for r in cur]
        assert cols == ["state", "expires_at"], cols
    finally:
        await conn.close()


def _orphan_scan_explain_sql() -> tuple[str, tuple[Any, ...]]:
    """Return (sql, params) matching scan_orphan_markers's query so the
    EXPLAIN QUERY PLAN test exercises the production statement shape."""
    from relay_sidecar.side_effect_markers import _orphan_scan_sql

    return _orphan_scan_sql("2026-05-28T20:03:44.000001+00:00")


@pytest.mark.plumbing
@pytest.mark.asyncio
@pytest.mark.fulfills("VAL-V2M04-020")
async def test_resurrection_finding_carries_compensation_tool() -> None:
    """When the policy defines compensation_tool, the finding carries it."""
    conn = await _make_db_with_side_effect_tables()
    try:
        pid = await _seed_policy(conn, compensation_tool="undo_case_note")
        past = (datetime.now(tz=UTC) - timedelta(hours=1)).isoformat()
        await _seed_marker(
            conn,
            policy_id=pid,
            state=MARKER_STATE_IN_FLIGHT,
            expires_at=past,
        )
        findings = await scan_orphan_markers(conn)
        assert len(findings) == 1
        assert findings[0].compensation_tool == "undo_case_note"
    finally:
        await conn.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-018")
def test_resurrection_event_payload_carries_marker_metadata() -> None:
    """The worker.resurrection_check_failed event payload binds the marker
    metadata for the audit log."""
    from relay_sidecar.side_effect_markers import ResurrectionFinding

    finding = ResurrectionFinding(
        marker_id="mid-1",
        tool_name="create_case_note",
        policy_id="pid-1",
        expires_at="2026-01-01T00:00:00+00:00",
        state="in_flight",
        idempotency_key="ik-1",
        compensation_tool=None,
        max_retries=3,
    )
    payload = build_resurrection_event_payload(finding)
    assert payload["marker_id"] == "mid-1"
    assert payload["tool_name"] == "create_case_note"
    assert payload["policy_id"] == "pid-1"
    assert payload["idempotency_key"] == "ik-1"


# ---------------------------------------------------------------------------
# VAL-V2M04-021/022: compensation invocation
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-021")
def test_compensation_event_payload_includes_retry_count() -> None:
    from relay_sidecar.side_effect_markers import ResurrectionFinding

    finding = ResurrectionFinding(
        marker_id="mid-1",
        tool_name="create_case_note",
        policy_id="pid-1",
        expires_at="2026-01-01T00:00:00+00:00",
        state="in_flight",
        idempotency_key="ik-1",
        compensation_tool="undo_case_note",
        max_retries=3,
    )
    payload = build_compensation_event_payload(finding, retry_count=4)
    assert payload["compensation_tool"] == "undo_case_note"
    assert payload["retry_count"] == 4
    assert payload["marker_id"] == "mid-1"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-022")
def test_compensation_payload_distinguishes_compensation_from_original_tool() -> None:
    """VAL-V2M04-022: compensation never re-runs the original tool. The
    payload carries BOTH names but downstream worker subscribes only to
    compensation_tool."""
    from relay_sidecar.side_effect_markers import ResurrectionFinding

    finding = ResurrectionFinding(
        marker_id="mid-1",
        tool_name="create_case_note",
        policy_id="pid-1",
        expires_at="2026-01-01T00:00:00+00:00",
        state="in_flight",
        idempotency_key="ik-1",
        compensation_tool="undo_case_note",
        max_retries=3,
    )
    payload = build_compensation_event_payload(finding, retry_count=4)
    assert payload["tool_name"] == "create_case_note"
    assert payload["compensation_tool"] == "undo_case_note"
    assert payload["tool_name"] != payload["compensation_tool"]


# ---------------------------------------------------------------------------
# VAL-V2M04-033: control plane is sole writer
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-033")
def test_side_effect_tables_listed_in_allowed_tables_whitelist() -> None:
    """The transactional_db_write whitelist names side_effect_markers and
    side_effect_proofs, so future linters can reason about the sole-writer
    invariant from one source."""
    from relay_sidecar.db import _allowed_tables

    allowed = set(_allowed_tables())
    assert "side_effect_markers" in allowed
    assert "side_effect_proofs" in allowed


# ---------------------------------------------------------------------------
# VAL-V2M04-034: writes pass through transactional_db_write atomic primitive
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-034")
def test_no_direct_inserts_against_side_effect_tables_in_sidecar() -> None:
    """Grep guard: every INSERT against side_effect_markers /
    side_effect_proofs from apps/local-sidecar/relay_sidecar/ must go
    through transactional_db_write_raw. Direct
    db.execute("INSERT INTO side_effect_markers ...") is banned.

    Allowlist: side_effect_markers.py is the canonical writer module; its
    own code is permitted to reference the table names in INSERT-shaped
    string templates only via the build_*_row helpers that feed into the
    primitive.
    """
    sidecar_root = _REPO_ROOT / "apps" / "local-sidecar" / "relay_sidecar"
    pattern = re.compile(
        r"""(?ix)
        (?:\.execute|\.executemany|\.executescript)
        \s*\(\s*
        ["'][^"']*\bINSERT[^"']*\b(?:side_effect_markers|side_effect_proofs)\b
        """
    )
    offenders: list[tuple[Path, int, str]] = []
    for py in sidecar_root.rglob("*.py"):
        if "__pycache__" in py.parts:
            continue
        text = py.read_text(encoding="utf-8")
        for lineno, line in enumerate(text.splitlines(), start=1):
            if pattern.search(line):
                offenders.append((py, lineno, line.strip()))
    assert offenders == [], (
        "Direct INSERT statements against side-effect tables are banned; "
        "use transactional_db_write_raw. Offenders:\n"
        + "\n".join(f"  {p}:{ln}: {src}" for p, ln, src in offenders)
    )


# ---------------------------------------------------------------------------
# Replay-class blocking codes (VAL-V2M04-026..029 wire-format presence)
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-026")
def test_relay_replay_approval_required_wire_code_present() -> None:
    """The approval_required class blocking code is registered as a
    numeric wire token; the descriptive alias APPROVAL_REQUIRED is the
    log subcode (per the YAML mapping documented at relay-error-codes.yaml)."""
    assert RELAY_REPLAY_APPROVAL_REQUIRED == "RELAY-REPLAY-031"
    assert REPLAY_SUBCODE_APPROVAL_REQUIRED == "APPROVAL_REQUIRED"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-027")
def test_relay_replay_approval_token_consumed_wire_code_present() -> None:
    assert RELAY_REPLAY_APPROVAL_TOKEN_CONSUMED == "RELAY-REPLAY-032"
    assert REPLAY_SUBCODE_APPROVAL_TOKEN_CONSUMED == "APPROVAL_TOKEN_CONSUMED"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-027")
def test_relay_replay_approval_expired_wire_code_present() -> None:
    assert RELAY_REPLAY_APPROVAL_EXPIRED == "RELAY-REPLAY-033"
    assert REPLAY_SUBCODE_APPROVAL_EXPIRED == "APPROVAL_EXPIRED"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-028")
def test_relay_replay_014_preserved_for_mutating_block() -> None:
    """VAL-V2M04-028: mutating blocks under existing RELAY-REPLAY-014."""
    assert RELAY_REPLAY_014 == "RELAY-REPLAY-014"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-029")
def test_relay_replay_014_preserved_for_external_irreversible_block() -> None:
    """VAL-V2M04-029: external_irreversible blocks under existing
    RELAY-REPLAY-014 (same code as -028)."""
    assert RELAY_REPLAY_014 == "RELAY-REPLAY-014"
