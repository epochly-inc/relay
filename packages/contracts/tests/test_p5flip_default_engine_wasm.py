"""M5 P5FLIP guard tests: the Python factory default is now WASM.

This is the most consequential change in the cel-wasm cutover: at milestone M5
the ``packages/contracts`` factory ``make_cel_evaluator()`` flips its DEFAULT
engine from celpy to wasm. Every consumer that constructs an evaluator through
the factory WITHOUT setting ``RELAY_CEL_ENGINE`` now gets the single wasm CEL
engine. The M1-M4 dual-run byte-parity work PROVED celpy and wasm agree, so the
flip is behavior-preserving for in-corpus expressions; these tests LOCK the new
default and the rollback escape hatch so a future accidental revert to celpy is
caught.

Covers (contract.md Evidence ``-k`` selectors are matched EXACTLY by the test
function names):

  - VAL-CWC-P5FLIP-009 (``default_engine_is_wasm``): with ``RELAY_CEL_ENGINE``
    UNSET (``monkeypatch.delenv``) -- and also set-but-BLANK -- the factory
    returns a wasm-backed :class:`WasmCelEvaluator`, NOT the celpy
    ``RelayCelEvaluator``. The default flipped.
  - VAL-CWC-P5FLIP-010 (``explicit_celpy_rollback``): with the default now wasm,
    an explicit ``RELAY_CEL_ENGINE=celpy`` (``monkeypatch.setenv``) still returns
    the legacy cel-python ``RelayCelEvaluator`` (the rollback escape hatch is
    intact during the one-release bake); ``RELAY_CEL_ENGINE=wasm`` returns the
    wasm class.
  - VAL-CWC-P5FLIP-014 (``unsupported_udf_rejected_on_default``): on the
    now-default wasm path (env unset), a caller passing a non-allowlist (extra)
    UDF is rejected fail-closed with the structured
    :class:`RelayCelUnsupportedUdfError` (RELAY-CEL-004 / RELAY-CEL-UDF-
    UNREGISTERED) -- the wasm exposes only the 3 hardcoded relay.* UDFs -- not a
    silent acceptance or a generic crash.

VAL-CWC-P5FLIP-013 (the wasm engine envelope -> RELAY-CEL-009 mapping, never the
host 004/006) is covered by ``test_engine_errors.py`` (the
``RelayCelEngineError.from_wasm_envelope`` taxonomy is engine-agnostic and holds
on the default path after the flip).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import pytest


# ---------------------------------------------------------------------------
# VAL-CWC-P5FLIP-009: default engine is WASM when env unset / blank (flip)
# ---------------------------------------------------------------------------
@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P5FLIP-009")
def test_default_engine_is_wasm_when_env_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Contract Evidence: with ``RELAY_CEL_ENGINE`` DELETED from the env, the
    contracts factory resolves to the wasm-backed evaluator (NOT celpy).

    Asserts BOTH the engine-name resolution (``_select_engine_name`` -> 'wasm')
    AND the concrete returned type (``WasmCelEvaluator`` / NOT
    ``RelayCelEvaluator``), so the M5 flip is pinned at the resolver level and at
    the constructed-instance level.
    """
    monkeypatch.delenv("RELAY_CEL_ENGINE", raising=False)

    from relay_contracts import RELAY_UDFS
    from relay_contracts.engine import _select_engine_name, make_cel_evaluator
    from relay_contracts.evaluator import RelayCelEvaluator
    from relay_contracts.wasm_backed_evaluator import WasmCelEvaluator

    # Engine-name resolution: unset -> "wasm" (the M5 flip), never "celpy".
    assert _select_engine_name() == "wasm", (
        "M5 default-flip broken: with RELAY_CEL_ENGINE unset the factory "
        "resolver must return 'wasm' (the M5 flip); got "
        f"{_select_engine_name()!r}"
    )

    ev = make_cel_evaluator(udfs=RELAY_UDFS)
    assert type(ev).__name__ == "WasmCelEvaluator", (
        "unset RELAY_CEL_ENGINE must construct the wasm WasmCelEvaluator after "
        f"the M5 flip; got {type(ev).__name__}"
    )
    assert isinstance(ev, WasmCelEvaluator)
    assert not isinstance(ev, RelayCelEvaluator), (
        "unset RELAY_CEL_ENGINE must NOT construct the celpy RelayCelEvaluator "
        f"after the M5 flip; got {type(ev).__name__}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P5FLIP-009")
def test_default_engine_is_wasm_when_env_blank(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A set-but-BLANK ``RELAY_CEL_ENGINE=""`` is the standard 'no selection'
    signal and MUST resolve to the new default (wasm), same as unset -- so the
    flip cannot be bypassed (back to celpy) with an empty export."""
    monkeypatch.setenv("RELAY_CEL_ENGINE", "")

    from relay_contracts import RELAY_UDFS
    from relay_contracts.engine import _select_engine_name, make_cel_evaluator
    from relay_contracts.wasm_backed_evaluator import WasmCelEvaluator

    assert _select_engine_name() == "wasm", (
        "blank RELAY_CEL_ENGINE='' must resolve to the wasm default after the "
        f"M5 flip; got {_select_engine_name()!r}"
    )
    ev = make_cel_evaluator(udfs=RELAY_UDFS)
    assert isinstance(ev, WasmCelEvaluator)


# ---------------------------------------------------------------------------
# VAL-CWC-P5FLIP-010: explicit RELAY_CEL_ENGINE=celpy rollback escape hatch
# ---------------------------------------------------------------------------
@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P5FLIP-010")
def test_explicit_celpy_rollback_returns_celpy_evaluator(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Contract Evidence: with the default now wasm, an explicit
    ``RELAY_CEL_ENGINE=celpy`` still returns the legacy cel-python
    ``RelayCelEvaluator`` (the rollback escape hatch is intact during the
    one-release bake), and ``RELAY_CEL_ENGINE=wasm`` returns the wasm class."""
    from relay_contracts import RELAY_UDFS
    from relay_contracts.engine import make_cel_evaluator
    from relay_contracts.evaluator import RelayCelEvaluator
    from relay_contracts.wasm_backed_evaluator import WasmCelEvaluator

    # Rollback escape hatch: explicit celpy still yields the legacy evaluator.
    monkeypatch.setenv("RELAY_CEL_ENGINE", "celpy")
    ev_celpy = make_cel_evaluator(udfs=RELAY_UDFS)
    assert type(ev_celpy).__name__ == "RelayCelEvaluator", (
        "explicit RELAY_CEL_ENGINE=celpy must still return the legacy "
        f"RelayCelEvaluator (rollback hatch); got {type(ev_celpy).__name__}"
    )
    assert isinstance(ev_celpy, RelayCelEvaluator)
    assert not isinstance(ev_celpy, WasmCelEvaluator)

    # And explicit wasm still selects the wasm class.
    monkeypatch.setenv("RELAY_CEL_ENGINE", "wasm")
    ev_wasm = make_cel_evaluator(udfs=RELAY_UDFS)
    assert type(ev_wasm).__name__ == "WasmCelEvaluator", (
        "explicit RELAY_CEL_ENGINE=wasm must return the WasmCelEvaluator; got "
        f"{type(ev_wasm).__name__}"
    )
    assert isinstance(ev_wasm, WasmCelEvaluator)


# ---------------------------------------------------------------------------
# VAL-CWC-P5FLIP-014: non-allowlist UDF rejected on the now-default wasm path
# ---------------------------------------------------------------------------
@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P5FLIP-014")
def test_unsupported_udf_rejected_on_default_wasm_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Contract Evidence: on the now-default (wasm) path -- env UNSET -- a caller
    passing a non-allowlist (extra) UDF is rejected with the structured
    :class:`RelayCelUnsupportedUdfError` (RELAY-CEL-004 / RELAY-CEL-UDF-
    UNREGISTERED). The wasm exposes only the 3 hardcoded relay.* UDFs and has no
    registration slot for a custom callable, so this is a fail-closed structured
    rejection -- not a silent acceptance and not a generic crash."""
    monkeypatch.delenv("RELAY_CEL_ENGINE", raising=False)

    from relay_contracts.engine import _select_engine_name, make_cel_evaluator
    from relay_contracts.errors import (
        SUBTYPE_UDF_UNREGISTERED,
        RelayCelError,
        RelayCelUnsupportedUdfError,
    )
    from relay_contracts.udf import register_udf

    # Sanity: the default really IS the wasm path here (env unset, post-flip).
    assert _select_engine_name() == "wasm", (
        "this test asserts the DEFAULT (env-unset) path rejects an extra UDF; "
        "the default must be wasm post-flip for the assertion to be meaningful"
    )

    extra = register_udf("my_check", lambda *a: True, pure=True, arity=1)
    with pytest.raises(RelayCelUnsupportedUdfError) as ctx:
        make_cel_evaluator(udfs=(extra,))

    err = ctx.value
    assert isinstance(err, RelayCelError)
    assert err.code == "RELAY-CEL-004", err.code
    assert err.subtype == SUBTYPE_UDF_UNREGISTERED, err.subtype
    # The rejection names the offending UDF so the operator can fix it.
    assert "my_check" in err.message
