"""W8.1 plumbing tests: VAL-W8-002 conditions evaluated by W6 contract engine.

Verifies that gate_policies.conditions are evaluated through the
the relay_contracts W6 evaluator (the single source of truth) and
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
from relay_contracts import CelEvaluatorProtocol, make_cel_evaluator
from relay_contracts.wasm_backed_evaluator import WasmCelEvaluator


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
def test_evaluator_uses_w6_contracts_cel_backend(evaluator) -> None:
    """The evaluator's CEL backend is a W6 contracts evaluator, not an in-gate fork.

    Empirical guard against accidental "in-house" CEL forks. CLAUDE.md
    banned pattern 16 + eng plan CQ1 line 145 require single-source CEL
    evaluation per language.

    The gate builds its backend via ``relay_contracts.make_cel_evaluator``
    (the single engine-selection read site), which returns the single
    ``WasmCelEvaluator`` backend (M6 WS-I). The structural guard stays the
    backend must (a) satisfy the W6 ``CelEvaluatorProtocol`` capability facade
    (``compile`` + ``evaluate``), AND (b) be one of the concrete classes the
    ``relay_contracts`` factory produces -- it must live in the
    ``relay_contracts`` package, NOT in a gate-local module. A future refactor
    that inlines a parallel CEL impl inside ``relay_gate_engine`` (a fork) would
    fail clause (b) loudly even though it might quack like the protocol.
    """
    # Reach into the private attribute used by the implementation. Test
    # is allowed to know this internal because the constraint is
    # structural -- if a future refactor introduces a parallel CEL
    # impl, this test breaks loudly.
    cel = evaluator._cel  # noqa: SLF001

    # (a) Capability check: the backend honors the W6 protocol facade. The
    # protocol is @runtime_checkable, so isinstance verifies the structural
    # surface (compile + evaluate) is present.
    assert isinstance(cel, CelEvaluatorProtocol)
    assert hasattr(cel, "evaluate") and callable(cel.evaluate)
    assert hasattr(cel, "compile") and callable(cel.compile)

    # (b) Provenance check: the backend is a class the relay_contracts factory
    # produces, i.e. it lives in the relay_contracts package -- never a
    # gate-local CEL fork. This is what makes the guard non-vacuous: a parallel
    # in-gate evaluator (module under relay_gate_engine) would fail here.
    backend_module = type(cel).__module__
    assert backend_module.startswith("relay_contracts"), (
        "gate CEL backend must come from the relay_contracts W6 engine, not an "
        f"in-gate fork; got {type(cel).__name__} from module {backend_module!r}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-002")
def test_evaluator_default_backend_is_wasm_when_env_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With ``RELAY_CEL_ENGINE`` unset, the gate's default CEL backend is wasm.

    Pins the post-M5-flip default from the gate's vantage point: the gate stays
    engine-agnostic (it never reads ``RELAY_CEL_ENGINE`` -- that would trip the
    VAL-W8-005 determinism grep) and follows the contracts factory default. M1-M4
    that default was the legacy engine; the M5 (WS-H) flip made it wasm, and M6
    (WS-I) removed the legacy engine, so a gate built on the unset-env default
    holds a ``WasmCelEvaluator`` backend -- the only backend.
    """
    from _w8_1_helpers import (
        InMemoryEvidenceProvider,
        InMemoryManifestResolver,
    )
    from relay_gate_engine import GateEvaluator

    monkeypatch.delenv("RELAY_CEL_ENGINE", raising=False)
    default_evaluator = GateEvaluator(
        evidence_provider=InMemoryEvidenceProvider(),
        manifest_resolver=InMemoryManifestResolver(),
    )
    assert isinstance(default_evaluator._cel, WasmCelEvaluator)  # noqa: SLF001
    # The default backend round-trips a trivial expression (it is wired, not a
    # bare stub). Value assertion decoupled from the 50 ms wall-clock to avoid
    # host-thread jitter under concurrent load; the factory forwards timeout_ms
    # to the default wasm evaluator. Production 50 ms default (CQ1) unchanged;
    # root cause resolved by M7 P7EDGE fuel metering.
    from relay_contracts.evaluator import MAX_TIMEOUT_MS

    assert (
        int(make_cel_evaluator(udfs=(), timeout_ms=MAX_TIMEOUT_MS).evaluate("1 + 2"))
        == 3
    )


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
