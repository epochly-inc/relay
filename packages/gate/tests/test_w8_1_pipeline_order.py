"""W8.1 plumbing tests: VAL-W8-001 three-gate pipeline ordering.

Verifies the pipeline runs scrutiny -> structural-review -> testing in
that order; out-of-order calls raise GateOrderingError(RELAY-GATE-001);
re-running an already-accepted gate raises the same error; the
sequence-log binds gate names in start order.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from _w8_1_helpers import (
    GATE_ID_SCRUTINY,
    GATE_ID_STRUCTURAL,
    GATE_ID_TESTING,
    make_draft,
    make_gate,
    make_pipeline,
)
from relay_gate_engine import (
    GATE_ORDER,
    GateOrderingError,
)
from relay_schemas.error_codes import RelayErrorCode


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-001")
def test_canonical_gate_order_is_fixed() -> None:
    """The pipeline gate order constant is exactly the spec-pinned tuple."""
    assert GATE_ORDER == ("scrutiny", "structural-review", "testing")


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-001")
def test_pipeline_runs_three_gates_in_fixed_order(evaluator) -> None:
    pipeline = make_pipeline(evaluator)
    now = datetime(2026, 5, 14, 12, 0, 30, tzinfo=UTC)

    scrutiny_gate = make_gate(gate_id=GATE_ID_SCRUTINY, gate_name="scrutiny")
    structural_gate = make_gate(gate_id=GATE_ID_STRUCTURAL, gate_name="structural-review")
    testing_gate = make_gate(gate_id=GATE_ID_TESTING, gate_name="testing")

    s = pipeline.run_gate(
        gate_name="scrutiny",
        gate=scrutiny_gate,
        draft=make_draft(gate_id=GATE_ID_SCRUTINY),
        now=now,
    )
    sr = pipeline.run_gate(
        gate_name="structural-review",
        gate=structural_gate,
        draft=make_draft(gate_id=GATE_ID_STRUCTURAL),
        now=now,
    )
    t = pipeline.run_gate(
        gate_name="testing",
        gate=testing_gate,
        draft=make_draft(gate_id=GATE_ID_TESTING),
        now=now,
    )

    assert s.action == sr.action == t.action == "accept"
    result = pipeline.result()
    assert result.gate_order == ("scrutiny", "structural-review", "testing")
    assert result.finished is True

    # Each outcome's sequence log MUST start with its own gate.start
    # event, in the canonical name. Tests bind on this directly per the
    # contract assertion's "instrumented sequence log" evidence clause.
    assert s.sequence_log[0]["event"] == "scrutiny.start"
    assert sr.sequence_log[0]["event"] == "structural-review.start"
    assert t.sequence_log[0]["event"] == "testing.start"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-001")
def test_structural_before_scrutiny_is_rejected(evaluator) -> None:
    pipeline = make_pipeline(evaluator)
    now = datetime(2026, 5, 14, 12, 0, 30, tzinfo=UTC)
    structural_gate = make_gate(
        gate_id=GATE_ID_STRUCTURAL, gate_name="structural-review"
    )

    with pytest.raises(GateOrderingError) as ei:
        pipeline.run_gate(
            gate_name="structural-review",
            gate=structural_gate,
            draft=make_draft(gate_id=GATE_ID_STRUCTURAL),
            now=now,
        )
    assert ei.value.code == RelayErrorCode.RELAY_GATE_001
    assert ei.value.payload["expected_prior_gate"] == "scrutiny"
    assert ei.value.payload["attempted_gate"] == "structural-review"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-001")
def test_testing_before_structural_is_rejected(evaluator) -> None:
    pipeline = make_pipeline(evaluator)
    now = datetime(2026, 5, 14, 12, 0, 30, tzinfo=UTC)
    scrutiny_gate = make_gate(gate_id=GATE_ID_SCRUTINY, gate_name="scrutiny")
    testing_gate = make_gate(gate_id=GATE_ID_TESTING, gate_name="testing")

    pipeline.run_gate(
        gate_name="scrutiny",
        gate=scrutiny_gate,
        draft=make_draft(gate_id=GATE_ID_SCRUTINY),
        now=now,
    )
    with pytest.raises(GateOrderingError) as ei:
        pipeline.run_gate(
            gate_name="testing",
            gate=testing_gate,
            draft=make_draft(gate_id=GATE_ID_TESTING),
            now=now,
        )
    assert ei.value.code == RelayErrorCode.RELAY_GATE_001
    assert ei.value.payload["expected_prior_gate"] == "structural-review"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-001")
def test_rerun_accepted_gate_is_rejected(evaluator) -> None:
    pipeline = make_pipeline(evaluator)
    now = datetime(2026, 5, 14, 12, 0, 30, tzinfo=UTC)
    scrutiny_gate = make_gate(gate_id=GATE_ID_SCRUTINY, gate_name="scrutiny")
    pipeline.run_gate(
        gate_name="scrutiny",
        gate=scrutiny_gate,
        draft=make_draft(gate_id=GATE_ID_SCRUTINY),
        now=now,
    )
    with pytest.raises(GateOrderingError) as ei:
        pipeline.run_gate(
            gate_name="scrutiny",
            gate=scrutiny_gate,
            draft=make_draft(gate_id=GATE_ID_SCRUTINY),
            now=now,
        )
    assert ei.value.code == RelayErrorCode.RELAY_GATE_001
    assert "already produced an accept decision" in ei.value.message
