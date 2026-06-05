"""W8.1 / WS-D plumbing tests: VAL-CWC-P2TSGATE-011 -- a wasm CEL engine PANIC
is caught by the gate's existing ``except RelayCelError`` blocks.

A wasm ``RELAY-CEL-PANIC`` engine failure is raised as a
:class:`relay_contracts.RelayCelEngineError`, which is a ``RelayCelError``
subclass carrying code ``RELAY-CEL-009`` (subtype ``RELAY-CEL-ENGINE-PANIC``).
The gate's condition loop (evaluator.py condition ``except RelayCelError``)
and the priority-ordered assertion loop (evaluator.py assertion
``except RelayCelError``) MUST catch it and record a structured
``error_code`` rather than letting the exception escape uncaught.

Crucially, the recorded engine error stays distinguishable from a legitimate
p0 fail-and-cascade: it surfaces as a condition/assertion ERROR entry tagged
with ``error_code == 'RELAY-CEL-009'`` (the ``.condition.error`` /
``.assertion.error`` events + the ``condition_evaluation_error`` unmet entry),
never as a plain ``.assertion.fail`` / ``unmet_condition`` boolean-false.

These tests inject a fake CEL evaluator (satisfying ``CelEvaluatorProtocol``)
whose ``evaluate`` raises ``RelayCelEngineError`` from the PANIC envelope, so
they exercise the gate's catch path without needing the built wasm artifact
and without flipping the default engine.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from _w8_1_helpers import (
    COMMAND_HASH_CLEAN,
    GATE_ID_SCRUTINY,
    InMemoryEvidenceProvider,
    InMemoryManifestResolver,
    make_draft,
    make_gate,
    make_pipeline,
)
from relay_contracts import CelEvaluatorProtocol, RelayCelError
from relay_contracts.errors import RelayCelEngineError
from relay_gate_engine import GateAssertion, GateEvaluator


class _PanicCelEvaluator:
    """A fake CEL evaluator that always raises a wasm RELAY-CEL-PANIC.

    Satisfies ``CelEvaluatorProtocol`` structurally (``timeout_ms``, ``_env``,
    ``compile``, ``evaluate``) so the gate engine can hold it through the
    widened ``CelEvaluatorProtocol`` hint. ``evaluate`` raises the exact error
    the wasm-backed evaluator produces for a reactor trap: a
    ``RelayCelEngineError`` mapped from the ``RELAY-CEL-PANIC`` envelope
    (code RELAY-CEL-009, subtype RELAY-CEL-ENGINE-PANIC).
    """

    timeout_ms: int = 5000
    _env: Any = None

    def compile(self, expression: str) -> Any:  # pragma: no cover - not reached
        # Compilation is fine; the panic happens at evaluation time, the
        # realistic wasm reactor-trap failure mode.
        return expression

    def evaluate(self, expression: str, bindings: Any = None) -> Any:
        raise RelayCelEngineError.from_wasm_envelope(
            "RELAY-CEL-PANIC", f"wasm reactor trap evaluating {expression!r}"
        )


def _panic_evaluator() -> GateEvaluator:
    return GateEvaluator(
        evidence_provider=InMemoryEvidenceProvider(),
        # Seed the benign command so the anti-bypass guard (which resolves the
        # draft command_hash before any condition runs) does not reject the
        # draft before we reach the CEL-evaluation path under test.
        manifest_resolver=InMemoryManifestResolver(
            {COMMAND_HASH_CLEAN: "uv run pytest -m plumbing"}
        ),
        cel_evaluator=_PanicCelEvaluator(),
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P2TSGATE-011")
def test_panic_error_is_a_relaycelerror_subclass() -> None:
    """A wasm RELAY-CEL-PANIC maps to a RelayCelError-family error (009).

    This is the keystone of VAL-CWC-P2TSGATE-011: the gate engine catches
    ``RelayCelError``; a PANIC must be an instance of it (via
    ``RelayCelEngineError``) or it would escape the gate uncaught.
    """
    err = RelayCelEngineError.from_wasm_envelope("RELAY-CEL-PANIC", "trap")
    assert isinstance(err, RelayCelError)
    assert err.code == "RELAY-CEL-009"
    assert err.subtype == "RELAY-CEL-ENGINE-PANIC"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P2TSGATE-011")
def test_panic_during_condition_is_caught_and_recorded() -> None:
    """A PANIC in a gate condition is caught, not propagated, and recorded.

    The gate's condition ``except RelayCelError`` block records the failure as
    a ``condition_evaluation_error`` with ``error_code == 'RELAY-CEL-009'`` in
    both ``unmet_conditions`` and the ``sequence_log`` (a ``.condition.error``
    event), and the gate does NOT raise.
    """
    pipeline = make_pipeline(_panic_evaluator())
    now = datetime(2026, 5, 14, 12, 0, 30, tzinfo=UTC)
    gate = make_gate(
        gate_id=GATE_ID_SCRUTINY,
        gate_name="scrutiny",
        conditions=("1 == 1",),
    )

    # Does NOT raise -- the PANIC is caught by except RelayCelError.
    outcome = pipeline.run_gate(
        gate_name="scrutiny",
        gate=gate,
        draft=make_draft(gate_id=GATE_ID_SCRUTINY),
        now=now,
    )

    # Recorded as a structured condition_evaluation_error, error_code 009.
    error_entries = [
        u
        for u in outcome.unmet_conditions
        if u.get("kind") == "condition_evaluation_error"
    ]
    assert len(error_entries) == 1, outcome.unmet_conditions
    assert error_entries[0]["expression"] == "1 == 1"
    assert error_entries[0]["error_code"] == "RELAY-CEL-009"

    # The engine error is distinct from a plain unmet boolean-false condition.
    assert not any(
        u.get("kind") == "unmet_condition" for u in outcome.unmet_conditions
    ), outcome.unmet_conditions

    # The sequence_log carries the .condition.error event with the 009 code.
    cond_error_events = [
        e
        for e in outcome.sequence_log
        if e["event"] == "scrutiny.condition.error"
    ]
    assert len(cond_error_events) == 1, outcome.sequence_log
    assert cond_error_events[0]["body"]["error_code"] == "RELAY-CEL-009"
    assert cond_error_events[0]["body"]["outcome"] == "error"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P2TSGATE-011")
def test_panic_during_assertion_is_caught_and_recorded() -> None:
    """A PANIC in a gate assertion is caught, recorded, and distinct from a fail.

    The gate's assertion ``except RelayCelError`` block records the failure as
    an ``.assertion.error`` event carrying ``error_code == 'RELAY-CEL-009'``
    (NOT a plain ``.assertion.fail``), marks the assertion failed, and the gate
    does NOT raise. A p0 PANIC still cascades like any p0 block, but the
    evidence entry is an engine ERROR, not a boolean assertion fail.
    """
    pipeline = make_pipeline(_panic_evaluator())
    now = datetime(2026, 5, 14, 12, 0, 30, tzinfo=UTC)
    assertion = GateAssertion(
        assertion_id="VAL-EXAMPLE-001",
        priority="p0",
        expression="evidence_bundles.size() >= 0",
    )
    gate = make_gate(
        gate_id=GATE_ID_SCRUTINY,
        gate_name="scrutiny",
        assertions=(assertion,),
        conditions=(),
    )

    # Does NOT raise -- the PANIC is caught by except RelayCelError.
    outcome = pipeline.run_gate(
        gate_name="scrutiny",
        gate=gate,
        draft=make_draft(gate_id=GATE_ID_SCRUTINY),
        now=now,
    )

    # The assertion is recorded as failed via the engine-error path.
    assert "VAL-EXAMPLE-001" in outcome.failed_assertion_ids

    # The sequence_log carries the .assertion.error event (engine error),
    # tagged with error_code 009 -- NOT a plain .assertion.fail.
    assertion_error_events = [
        e
        for e in outcome.sequence_log
        if e["event"] == "scrutiny.assertion.error"
    ]
    assert len(assertion_error_events) == 1, outcome.sequence_log
    body = assertion_error_events[0]["body"]
    assert body["assertion_id"] == "VAL-EXAMPLE-001"
    assert body["error_code"] == "RELAY-CEL-009"

    # Distinguishable from a plain assertion fail: no .assertion.fail event for
    # this assertion (the engine PANIC took the error branch, not the fail one).
    plain_fail_events = [
        e
        for e in outcome.sequence_log
        if e["event"] == "scrutiny.assertion.fail"
    ]
    assert plain_fail_events == [], outcome.sequence_log


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P2TSGATE-011")
def test_panic_evaluator_satisfies_cel_evaluator_protocol() -> None:
    """The injected fake satisfies CelEvaluatorProtocol (the widened gate hint).

    Guards that the test's fake is a faithful stand-in for a real evaluator
    behind the ``CelEvaluatorProtocol`` facade the gate now holds.
    """
    fake = _PanicCelEvaluator()
    assert isinstance(fake, CelEvaluatorProtocol)
