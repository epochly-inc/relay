"""W8.1 plumbing tests: VAL-W8-004 assertions executed in priority order.

Verifies the evaluator sorts assertions by priority (P0 > P1 > P2 > P3),
short-circuits when a P0 fails AND cascade_on_block=True, and that the
P1 assertion id does NOT appear in failed_assertion_ids when it was
skipped (it appears in skipped_assertion_ids and the sequence log
records the skip).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from _w8_1_helpers import (
    GATE_ID_SCRUTINY,
    make_draft,
    make_gate,
    make_pipeline,
)
from relay_gate_engine import GateAssertion

_FAIL = "1 == 2"  # CEL false
_PASS = "1 == 1"  # CEL true


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-004")
def test_p0_failure_cascades_and_skips_p1(evaluator) -> None:
    """A failing P0 with cascade_on_block=True skips remaining P1/P2."""
    pipeline = make_pipeline(evaluator)
    now = datetime(2026, 5, 14, 12, 0, 30, tzinfo=UTC)
    gate = make_gate(
        gate_id=GATE_ID_SCRUTINY,
        gate_name="scrutiny",
        cascade_on_block=True,
        assertions=(
            GateAssertion(assertion_id="VAL-X-001", priority="p0", expression=_FAIL),
            GateAssertion(assertion_id="VAL-X-002", priority="p1", expression=_PASS),
            GateAssertion(assertion_id="VAL-X-003", priority="p2", expression=_PASS),
        ),
    )
    outcome = pipeline.run_gate(
        gate_name="scrutiny",
        gate=gate,
        draft=make_draft(gate_id=GATE_ID_SCRUTINY),
        now=now,
    )
    # The action MUST be "block" (failed P0).
    assert outcome.action == "block"
    # P0 failed.
    assert "VAL-X-001" in outcome.failed_assertion_ids
    # P1 and P2 were skipped, NOT failed (this is the load-bearing
    # invariant from the contract assertion text).
    assert "VAL-X-002" not in outcome.failed_assertion_ids
    assert "VAL-X-003" not in outcome.failed_assertion_ids
    assert "VAL-X-002" in outcome.skipped_assertion_ids
    assert "VAL-X-003" in outcome.skipped_assertion_ids
    # Sequence log records the skip with the cascade reason.
    skip_events = [
        e for e in outcome.sequence_log
        if e["event"] == "scrutiny.assertion.skipped"
    ]
    assert {e["body"]["assertion_id"] for e in skip_events} == {
        "VAL-X-002", "VAL-X-003",
    }
    for e in skip_events:
        assert e["body"]["reason"] == "cascade_on_block"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-004")
def test_p0_failure_without_cascade_still_evaluates_p1(evaluator) -> None:
    """cascade_on_block=False -> P1 runs even after P0 fails."""
    pipeline = make_pipeline(evaluator)
    now = datetime(2026, 5, 14, 12, 0, 30, tzinfo=UTC)
    gate = make_gate(
        gate_id=GATE_ID_SCRUTINY,
        gate_name="scrutiny",
        cascade_on_block=False,
        assertions=(
            GateAssertion(assertion_id="VAL-X-001", priority="p0", expression=_FAIL),
            GateAssertion(assertion_id="VAL-X-002", priority="p1", expression=_FAIL),
        ),
    )
    outcome = pipeline.run_gate(
        gate_name="scrutiny",
        gate=gate,
        draft=make_draft(gate_id=GATE_ID_SCRUTINY),
        now=now,
    )
    assert outcome.action == "block"
    # Both failed because cascade was disabled.
    assert "VAL-X-001" in outcome.failed_assertion_ids
    assert "VAL-X-002" in outcome.failed_assertion_ids
    assert outcome.skipped_assertion_ids == ()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-004")
def test_assertions_evaluated_in_priority_order(evaluator) -> None:
    """The evaluator runs P0 before P1 before P2 regardless of input order."""
    pipeline = make_pipeline(evaluator)
    now = datetime(2026, 5, 14, 12, 0, 30, tzinfo=UTC)
    # Submit in deliberately scrambled order; the engine MUST sort.
    gate = make_gate(
        gate_id=GATE_ID_SCRUTINY,
        gate_name="scrutiny",
        cascade_on_block=False,
        assertions=(
            GateAssertion(assertion_id="VAL-X-A", priority="p2", expression=_PASS),
            GateAssertion(assertion_id="VAL-X-B", priority="p0", expression=_PASS),
            GateAssertion(assertion_id="VAL-X-C", priority="p1", expression=_PASS),
            GateAssertion(assertion_id="VAL-X-D", priority="p3", expression=_PASS),
        ),
    )
    outcome = pipeline.run_gate(
        gate_name="scrutiny",
        gate=gate,
        draft=make_draft(gate_id=GATE_ID_SCRUTINY),
        now=now,
    )
    # The evaluated_assertion_ids list reflects evaluation order.
    assert outcome.evaluated_assertion_ids == (
        "VAL-X-B", "VAL-X-C", "VAL-X-A", "VAL-X-D",
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-004")
def test_p1_failure_alone_yields_remediate_not_block(evaluator) -> None:
    """A failing P1 with no failing P0 -> action='remediate'."""
    pipeline = make_pipeline(evaluator)
    now = datetime(2026, 5, 14, 12, 0, 30, tzinfo=UTC)
    gate = make_gate(
        gate_id=GATE_ID_SCRUTINY,
        gate_name="scrutiny",
        assertions=(
            GateAssertion(assertion_id="VAL-X-001", priority="p0", expression=_PASS),
            GateAssertion(assertion_id="VAL-X-002", priority="p1", expression=_FAIL),
        ),
    )
    outcome = pipeline.run_gate(
        gate_name="scrutiny",
        gate=gate,
        draft=make_draft(gate_id=GATE_ID_SCRUTINY),
        now=now,
    )
    assert outcome.action == "remediate"
    assert outcome.failed_assertion_ids == ("VAL-X-002",)
