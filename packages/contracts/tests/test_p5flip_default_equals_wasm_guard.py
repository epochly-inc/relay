"""VAL-CWC-P5FLIP-012 cross-host guard (Python half): default == wasm.

This is the ADR-acceptance-gate-named guard ('a test asserts default == wasm'):
it encodes the M5 FLIP ITSELF as a guarded invariant, so a future accidental
revert of the factory default back to celpy is caught by name. The TS half of
the cross-host pair lives in
``packages/contracts-typescript/test/default-equals-wasm-guard.test.ts``
(vitest ``-t "default equals wasm"``); this file is the pytest
``-k default_equals_wasm_guard`` half. Both selectors are the contract.md
Evidence commands for VAL-CWC-P5FLIP-012.

Relationship to the existing post-flip default tests (this guard is ADDITIVE,
not a duplicate import): ``test_p5flip_default_engine_wasm.py``
(VAL-CWC-P5FLIP-009) and ``test_engine_factory.py`` (VAL-CWC-P1HOST-010)
already pin the wasm default behaviorally. THIS file is the explicitly-named
acceptance-gate guard with its own REAL assertions (resolver token AND
constructed instance) plus a NON-VACUITY companion that simulates a revert
(``_DEFAULT_ENGINE`` monkeypatched back to celpy) and proves the guard's
discriminators actually flip -- so the guard can never rot into a tautology.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import pytest


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P5FLIP-012")
def test_default_equals_wasm_guard_python_default_resolves_to_wasm(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """THE GUARD (ADR acceptance gate 'a test asserts default == wasm').

    With ``RELAY_CEL_ENGINE`` UNSET (deleted from the environment), the
    Python factory's default-engine selection MUST be wasm:

      1. resolver level: ``_select_engine_name() == "wasm"`` -- the unset env
         resolves to the wasm token, never celpy;
      2. instance level: ``make_cel_evaluator()`` (bare, no args) constructs a
         :class:`WasmCelEvaluator`, and NOT the legacy celpy
         :class:`RelayCelEvaluator`.

    If a future change reverts the default to celpy (engine.py
    ``_DEFAULT_ENGINE``), BOTH assertions fail loudly by name
    (``-k default_equals_wasm_guard``). The companion test below proves this
    guard is non-vacuous (its discriminators flip under a simulated revert).
    """
    monkeypatch.delenv("RELAY_CEL_ENGINE", raising=False)

    from relay_contracts.engine import _select_engine_name, make_cel_evaluator
    from relay_contracts.evaluator import RelayCelEvaluator
    from relay_contracts.wasm_backed_evaluator import WasmCelEvaluator

    resolved = _select_engine_name()
    assert resolved == "wasm", (
        "M5 flip invariant violated: with RELAY_CEL_ENGINE unset the factory "
        f"default MUST resolve to 'wasm'; got {resolved!r}. A revert of "
        "engine.py _DEFAULT_ENGINE back to celpy is a P5FLIP contract breach "
        "(VAL-CWC-P5FLIP-012)."
    )

    ev = make_cel_evaluator()
    assert isinstance(ev, WasmCelEvaluator), (
        "M5 flip invariant violated: bare make_cel_evaluator() with "
        "RELAY_CEL_ENGINE unset MUST construct the wasm-backed "
        f"WasmCelEvaluator; got {type(ev).__name__}."
    )
    assert not isinstance(ev, RelayCelEvaluator), (
        "M5 flip invariant violated: the unset-env default constructed the "
        "legacy celpy RelayCelEvaluator -- the default was reverted."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P5FLIP-012")
def test_default_equals_wasm_guard_non_vacuous_under_simulated_revert(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """NON-VACUITY: a simulated revert flips BOTH of the guard's discriminators.

    Monkeypatches ``engine._DEFAULT_ENGINE`` back to the celpy token (the
    exact one-line accidental revert the guard exists to catch) with the env
    still UNSET, and asserts the observable behavior the guard checks really
    does change: the resolver returns ``"celpy"`` (not ``"wasm"``) and the
    bare factory constructs the legacy :class:`RelayCelEvaluator` (not a
    :class:`WasmCelEvaluator`). Therefore the guard above CANNOT pass
    vacuously -- under a real revert its ``== "wasm"`` and
    ``isinstance(..., WasmCelEvaluator)`` assertions both fail.

    The monkeypatch is test-scoped (pytest restores the module attribute on
    teardown); production engine source is never modified.
    """
    monkeypatch.delenv("RELAY_CEL_ENGINE", raising=False)

    from relay_contracts import engine as engine_module
    from relay_contracts.evaluator import RelayCelEvaluator
    from relay_contracts.wasm_backed_evaluator import WasmCelEvaluator

    # Sanity before the simulation: the real module default is the wasm token.
    assert engine_module._DEFAULT_ENGINE == engine_module._ENGINE_WASM

    # Simulate the accidental revert: default back to celpy, env still unset.
    monkeypatch.setattr(
        engine_module, "_DEFAULT_ENGINE", engine_module._ENGINE_CELPY
    )

    reverted = engine_module._select_engine_name()
    assert reverted == "celpy", (
        "non-vacuity broken: simulating the revert did not change the "
        f"resolver output (got {reverted!r}) -- the guard's resolver "
        "assertion would not catch a real revert."
    )
    assert reverted != "wasm"

    ev = engine_module.make_cel_evaluator()
    assert isinstance(ev, RelayCelEvaluator), (
        "non-vacuity broken: under the simulated revert the bare factory did "
        f"not construct the celpy RelayCelEvaluator (got {type(ev).__name__})"
        " -- the guard's isinstance assertion would not catch a real revert."
    )
    assert not isinstance(ev, WasmCelEvaluator), (
        "non-vacuity broken: the simulated revert still constructed a "
        "WasmCelEvaluator, so the guard's isinstance check does not "
        "discriminate between the engines."
    )
