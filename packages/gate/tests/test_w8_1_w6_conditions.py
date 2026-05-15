"""W8.1 plumbing tests: VAL-W8-002 conditions evaluated by W6 contract engine.

Verifies that gate_policies.conditions are evaluated through the
relay_contracts.RelayCelEvaluator (the W6 single source of truth) and
NOT via an inlined CEL implementation. A known-false condition produces
an unmet_conditions[] entry whose expression matches the policy text
exactly.

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
from relay_contracts import RelayCelEvaluator


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-002")
def test_unmet_condition_surfaces_expression_text(evaluator) -> None:
    """A known-false CEL condition appears in unmet_conditions verbatim."""
    pipeline = make_pipeline(evaluator)
    now = datetime(2026, 5, 14, 12, 0, 30, tzinfo=UTC)
    gate = make_gate(
        gate_id=GATE_ID_SCRUTINY,
        gate_name="scrutiny",
        # Pure-CEL false expression: 1 == 2.
        conditions=("1 == 2",),
    )

    outcome = pipeline.run_gate(
        gate_name="scrutiny",
        gate=gate,
        draft=make_draft(gate_id=GATE_ID_SCRUTINY),
        now=now,
    )
    assert outcome.action == "remediate"
    assert any(
        u.get("expression") == "1 == 2" and u.get("kind") == "unmet_condition"
        for u in outcome.unmet_conditions
    ), outcome.unmet_conditions


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-002")
def test_passing_condition_does_not_appear_in_unmet(evaluator) -> None:
    """A known-true CEL condition is silent in the outcome envelope."""
    pipeline = make_pipeline(evaluator)
    now = datetime(2026, 5, 14, 12, 0, 30, tzinfo=UTC)
    gate = make_gate(
        gate_id=GATE_ID_SCRUTINY,
        gate_name="scrutiny",
        conditions=("2 + 2 == 4",),
    )
    outcome = pipeline.run_gate(
        gate_name="scrutiny",
        gate=gate,
        draft=make_draft(gate_id=GATE_ID_SCRUTINY),
        now=now,
    )
    assert outcome.action == "accept"
    assert outcome.unmet_conditions == ()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-002")
def test_evaluator_uses_w6_relaycel_evaluator_instance(evaluator) -> None:
    """The evaluator's CEL backend is a RelayCelEvaluator instance.

    Empirical guard against accidental "in-house" CEL forks. CLAUDE.md
    banned pattern 16 + eng plan CQ1 line 145 require single-source CEL
    evaluation per language.
    """
    # Reach into the private attribute used by the implementation. Test
    # is allowed to know this internal because the constraint is
    # structural -- if a future refactor introduces a parallel CEL
    # impl, this test breaks loudly.
    assert isinstance(evaluator._cel, RelayCelEvaluator)  # noqa: SLF001


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-002")
def test_condition_with_relay_profile_violation_surfaces_error(evaluator) -> None:
    """A CEL profile violation in a condition becomes a condition error.

    The Relay CEL profile bans dyn(...). A condition referencing it
    should NOT crash the gate engine -- it should surface as a
    condition_evaluation_error in unmet_conditions and the action
    should be "remediate".
    """
    pipeline = make_pipeline(evaluator)
    now = datetime(2026, 5, 14, 12, 0, 30, tzinfo=UTC)
    gate = make_gate(
        gate_id=GATE_ID_SCRUTINY,
        gate_name="scrutiny",
        conditions=("dyn(1) == 1",),
    )
    outcome = pipeline.run_gate(
        gate_name="scrutiny",
        gate=gate,
        draft=make_draft(gate_id=GATE_ID_SCRUTINY),
        now=now,
    )
    assert outcome.action == "remediate"
    error_entries = [
        u for u in outcome.unmet_conditions
        if u.get("kind") == "condition_evaluation_error"
    ]
    assert len(error_entries) == 1
    assert error_entries[0]["expression"] == "dyn(1) == 1"
    # Surfaced code is RELAY-CEL-NNN per relay_contracts.errors.
    assert error_entries[0]["error_code"].startswith("RELAY-CEL-")
