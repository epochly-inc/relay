"""VAL-CWC-P5FLIP-012 cross-host guard (Python half): default == wasm.

This is the ADR-acceptance-gate-named guard ('a test asserts default == wasm'):
it encodes the M5 FLIP ITSELF as a guarded invariant, so a future accidental
revert of the factory default is caught by name. The TS half of
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
(``_DEFAULT_ENGINE`` monkeypatched to a non-wasm token) and proves the
guard's discriminators actually flip -- so the guard can never rot into a
tautology. M6 WS-I transition: the legacy engine no longer exists, so under
a simulated revert the factory FAILS CLOSED (the unhandled-token guard)
instead of constructing a legacy class -- still a loud, named failure.

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
         resolves to the wasm token;
      2. instance level: ``make_cel_evaluator()`` (bare, no args) constructs a
         :class:`WasmCelEvaluator`.

    If a future change reverts the default (engine.py ``_DEFAULT_ENGINE``),
    BOTH assertions fail loudly by name (``-k default_equals_wasm_guard``).
    The companion test below proves this guard is non-vacuous (its
    discriminators flip under a simulated revert).
    """
    monkeypatch.delenv("RELAY_CEL_ENGINE", raising=False)

    from relay_contracts.engine import _select_engine_name, make_cel_evaluator
    from relay_contracts.wasm_backed_evaluator import WasmCelEvaluator

    resolved = _select_engine_name()
    assert resolved == "wasm", (
        "M5 flip invariant violated: with RELAY_CEL_ENGINE unset the factory "
        f"default MUST resolve to 'wasm'; got {resolved!r}. A revert of "
        "engine.py _DEFAULT_ENGINE is a P5FLIP contract breach "
        "(VAL-CWC-P5FLIP-012)."
    )

    ev = make_cel_evaluator()
    assert isinstance(ev, WasmCelEvaluator), (
        "M5 flip invariant violated: bare make_cel_evaluator() with "
        "RELAY_CEL_ENGINE unset MUST construct the wasm-backed "
        f"WasmCelEvaluator; got {type(ev).__name__}."
    )
    assert type(ev).__name__ == "WasmCelEvaluator"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P5FLIP-012")
def test_default_equals_wasm_guard_non_vacuous_under_simulated_revert(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """NON-VACUITY: a simulated revert flips BOTH of the guard's discriminators.

    Monkeypatches ``engine._DEFAULT_ENGINE`` to the removed legacy token (the
    exact one-line accidental revert the guard exists to catch) with the env
    still UNSET, and asserts the observable behavior the guard checks really
    does change: the resolver returns the non-wasm token (the unset-env path
    returns ``_DEFAULT_ENGINE`` verbatim), and the bare factory FAILS CLOSED
    with the unhandled-token ``ValueError`` (M6 WS-I: there is no legacy
    class left to construct -- the defensive factory guard catches the
    unreachable token loudly). Therefore the guard above CANNOT pass
    vacuously -- under a real revert its ``== "wasm"`` and
    ``isinstance(..., WasmCelEvaluator)`` assertions both fail.

    The monkeypatch is test-scoped (pytest restores the module attribute on
    teardown); production engine source is never modified.
    """
    monkeypatch.delenv("RELAY_CEL_ENGINE", raising=False)

    from relay_contracts import engine as engine_module

    # Sanity before the simulation: the real module default is the wasm token.
    assert engine_module._DEFAULT_ENGINE == engine_module._ENGINE_WASM

    # Simulate the accidental revert: default to the removed legacy token,
    # env still unset.
    monkeypatch.setattr(engine_module, "_DEFAULT_ENGINE", "celpy")

    reverted = engine_module._select_engine_name()
    assert reverted == "celpy", (
        "non-vacuity broken: simulating the revert did not change the "
        f"resolver output (got {reverted!r}) -- the guard's resolver "
        "assertion would not catch a real revert."
    )
    assert reverted != "wasm"

    with pytest.raises(ValueError) as ctx:
        engine_module.make_cel_evaluator()
    assert "wasm" in str(ctx.value), (
        "non-vacuity broken: under the simulated revert the bare factory "
        "did not fail closed with the structured unhandled-token ValueError "
        f"naming the allowed set; got {ctx.value!r}."
    )
