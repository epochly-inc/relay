"""W8.1 plumbing tests: VAL-W8-006 draft TTL enforced.

Verifies a draft submitted before now - draft_ttl_seconds raises
DraftTtlExpiredError(RELAY-GATE-024); the boundary case (exactly
ttl_seconds elapsed) is treated as expired (closed-on-the-right).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from _w8_1_helpers import (
    GATE_ID_SCRUTINY,
    make_draft,
    make_gate,
    make_pipeline,
)
from relay_gate_engine import DraftTtlExpiredError, is_draft_expired
from relay_schemas.error_codes import RelayErrorCode

# Spec A.5 line 3056: default draft_ttl_seconds is 900.
_DEFAULT_TTL = 900


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-006")
def test_draft_just_under_ttl_is_not_expired() -> None:
    """ttl - 1 second -> not expired."""
    submitted_at = datetime(2026, 5, 14, 12, 0, 0, tzinfo=UTC)
    now = submitted_at + timedelta(seconds=_DEFAULT_TTL - 1)
    assert is_draft_expired(
        submitted_at=submitted_at, now=now, draft_ttl_seconds=_DEFAULT_TTL,
    ) is False


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-006")
def test_draft_exactly_at_ttl_is_expired() -> None:
    """elapsed == ttl_seconds -> expired (closed-on-the-right)."""
    submitted_at = datetime(2026, 5, 14, 12, 0, 0, tzinfo=UTC)
    now = submitted_at + timedelta(seconds=_DEFAULT_TTL)
    assert is_draft_expired(
        submitted_at=submitted_at, now=now, draft_ttl_seconds=_DEFAULT_TTL,
    ) is True


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-006")
def test_draft_over_ttl_raises_in_pipeline(evaluator) -> None:
    """submitted_at = now - 901s -> evaluator raises DraftTtlExpiredError."""
    pipeline = make_pipeline(evaluator)
    submitted_at = datetime(2026, 5, 14, 12, 0, 0, tzinfo=UTC)
    now = submitted_at + timedelta(seconds=_DEFAULT_TTL + 1)
    gate = make_gate(
        gate_id=GATE_ID_SCRUTINY,
        gate_name="scrutiny",
        draft_ttl_seconds=_DEFAULT_TTL,
    )
    draft = make_draft(gate_id=GATE_ID_SCRUTINY, submitted_at=submitted_at)
    with pytest.raises(DraftTtlExpiredError) as ei:
        pipeline.run_gate(
            gate_name="scrutiny", gate=gate, draft=draft, now=now,
        )
    assert ei.value.code == RelayErrorCode.RELAY_GATE_024
    assert ei.value.payload["draft_ttl_seconds"] == _DEFAULT_TTL
    assert ei.value.payload["submitted_at"] == submitted_at.isoformat()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-006")
def test_naive_datetime_rejected() -> None:
    """is_draft_expired refuses naive (timezone-less) datetimes."""
    naive = datetime(2026, 5, 14, 12, 0, 0)  # no tzinfo
    aware = datetime(2026, 5, 14, 12, 0, 0, tzinfo=UTC)
    with pytest.raises(ValueError):
        is_draft_expired(
            submitted_at=naive, now=aware, draft_ttl_seconds=_DEFAULT_TTL,
        )
    with pytest.raises(ValueError):
        is_draft_expired(
            submitted_at=aware, now=naive, draft_ttl_seconds=_DEFAULT_TTL,
        )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-006")
def test_invalid_ttl_rejected() -> None:
    """is_draft_expired refuses zero / negative / non-int draft_ttl_seconds."""
    aware = datetime(2026, 5, 14, 12, 0, 0, tzinfo=UTC)
    with pytest.raises(ValueError):
        is_draft_expired(
            submitted_at=aware, now=aware, draft_ttl_seconds=0,
        )
    with pytest.raises(ValueError):
        is_draft_expired(
            submitted_at=aware, now=aware, draft_ttl_seconds=-1,
        )
    with pytest.raises(ValueError):
        is_draft_expired(
            submitted_at=aware, now=aware, draft_ttl_seconds=900.5,  # type: ignore[arg-type]
        )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-006")
def test_ttl_expiry_writes_no_outcome_to_pipeline(evaluator) -> None:
    """A TTL-expired draft does NOT advance the pipeline.

    After the TTL exception, scrutiny is still un-accepted, so
    structural-review remains blocked.
    """
    pipeline = make_pipeline(evaluator)
    submitted_at = datetime(2026, 5, 14, 12, 0, 0, tzinfo=UTC)
    now = submitted_at + timedelta(seconds=_DEFAULT_TTL + 1)
    gate = make_gate(gate_id=GATE_ID_SCRUTINY, gate_name="scrutiny")
    draft = make_draft(gate_id=GATE_ID_SCRUTINY, submitted_at=submitted_at)

    with pytest.raises(DraftTtlExpiredError):
        pipeline.run_gate(
            gate_name="scrutiny", gate=gate, draft=draft, now=now,
        )

    result = pipeline.result()
    assert result.outcomes == ()
    assert result.finished is False
