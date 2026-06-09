"""One-shot ``evaluate_with_wasm_path`` fail-closed parity with the shared path.

Fail-closed-consistency gap (P5FLIP fix): the SHARED-engine path
``WasmCelEvaluator._ensure_shared`` wraps ANY wasm load / module-instantiation
failure (including a bare ``wasmtime.WasmtimeError`` from a corrupt-but-present
artifact) into the structured ``RelayCelEngineError`` (RELAY-CEL-009 /
RELAY-CEL-ENGINE-REQUEST) via a try/except around the handle construction. The
ONE-SHOT explicit-path API ``evaluate_with_wasm_path`` constructed its handle
WITHOUT that wrap, so a corrupt (valid path, garbage bytes) wasm surfaced a BARE
``wasmtime.WasmtimeError`` to the caller instead of the wrapped
``RelayCelEngineError`` -- inconsistent fail-closed behavior between the two
paths, and a bare engine exception escaping the host facade.

This module pins the fixed behavior:

  - a CORRUPT-but-present wasm via the one-shot API fails closed with
    ``RelayCelEngineError`` (RELAY-CEL-009), NEVER a bare ``wasmtime.WasmtimeError``
    (RED before the fix: a bare loader error escapes; GREEN after);
  - an ABSENT wasm_path via the one-shot API still raises the already-structured
    ``RelayCelEngineError`` (the presence gate -- unchanged);
  - the HAPPY path (the real pinned package-data wasm) still evaluates correctly
    (no behavior change to genuine evaluation results);
  - the SHARED path's existing corrupt-load wrap is unchanged (parity anchor).

These are tier-1 plumbing tests (offline, deterministic, no network, no build).
The ``-k`` selectors used by the contract evidence commands match
``wasm and (evaluator or path or unloadable or corrupt or engine)``.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""
from __future__ import annotations

import celpy.celtypes as celtypes
import pytest
import wasmtime
from relay_contracts.errors import (
    SUBTYPE_ENGINE_REQUEST,
    RelayCelEngineError,
    RelayCelError,
)
from relay_contracts.wasm_backed_evaluator import WasmCelEvaluator

pytestmark = pytest.mark.plumbing


def _write_corrupt_wasm(tmp_path) -> str:
    """Write a present-but-garbage-bytes file with a .wasm name.

    The bytes are NOT a valid wasm module, so the loader's ``Module.from_file``
    raises a bare ``wasmtime.WasmtimeError`` at handle construction. The path
    EXISTS (so the presence gate ``_resolve_wasm_path`` passes), isolating the
    failure to the load / module-instantiation step the fix must wrap.
    """
    corrupt = tmp_path / "relay_cel_wasm__corrupt__.wasm"
    corrupt.write_bytes(b"not a wasm module -- garbage bytes \x00\x01\x02\x03")
    return str(corrupt)


def test_one_shot_wasm_path_corrupt_artifact_wraps_engine_error(tmp_path) -> None:
    """A corrupt-but-present wasm via the one-shot API fails closed structurally.

    The path exists (presence gate passes), but the bytes are not a valid wasm
    module. Pre-fix the bare ``wasmtime.WasmtimeError`` from ``Module.from_file``
    escapes the host facade; post-fix it is wrapped into the SAME structured
    ``RelayCelEngineError`` (RELAY-CEL-009 / RELAY-CEL-ENGINE-REQUEST) the shared
    path produces -- never a bare loader error.
    """
    corrupt_path = _write_corrupt_wasm(tmp_path)
    ev = WasmCelEvaluator(timeout_ms=250)

    with pytest.raises(RelayCelEngineError) as excinfo:
        ev.evaluate_with_wasm_path("1 + 2", wasm_path=corrupt_path)

    err = excinfo.value
    # Structured fail-closed: RELAY-CEL-009 with the engine-request subtype,
    # identical to the shared path's load-failure wrap.
    assert err.code == "RELAY-CEL-009", err.code
    assert err.subtype == SUBTYPE_ENGINE_REQUEST, err.subtype
    # NEVER a bare wasmtime error escaping the host facade.
    assert not isinstance(err, wasmtime.WasmtimeError)


def test_one_shot_wasm_path_corrupt_never_raises_bare_wasmtime_error(
    tmp_path,
) -> None:
    """The corrupt one-shot load NEVER surfaces a bare ``wasmtime.WasmtimeError``.

    Directly asserts the negative: catching ``wasmtime.WasmtimeError`` does NOT
    intercept the raised error (it is the structured RelayCelError instead). This
    is the precise gap -- a bare loader/wasmtime error leaking through the
    explicit-path API.
    """
    corrupt_path = _write_corrupt_wasm(tmp_path)
    ev = WasmCelEvaluator(timeout_ms=250)

    with pytest.raises(RelayCelError):
        ev.evaluate_with_wasm_path("1 + 2", wasm_path=corrupt_path)

    # And it is specifically NOT a bare wasmtime error.
    with pytest.raises(RelayCelEngineError):
        try:
            ev.evaluate_with_wasm_path("1 + 2", wasm_path=corrupt_path)
        except wasmtime.WasmtimeError as bare:  # pragma: no cover - must not hit
            pytest.fail(
                "one-shot evaluate_with_wasm_path leaked a bare "
                f"wasmtime.WasmtimeError instead of a structured RelayCelEngineError: {bare!r}"
            )


def test_one_shot_wasm_path_absent_artifact_still_structured(tmp_path) -> None:
    """An ABSENT wasm_path via the one-shot API stays structured (unchanged).

    The presence gate ``_resolve_wasm_path`` already raises the structured
    ``RelayCelEngineError`` for an absent path BEFORE any load. This pins that
    behavior is untouched by the corrupt-load wrap fix.
    """
    missing = str(tmp_path / "relay_cel_wasm__absent__.wasm")
    ev = WasmCelEvaluator(timeout_ms=250)

    with pytest.raises(RelayCelEngineError) as excinfo:
        ev.evaluate_with_wasm_path("1 + 2", wasm_path=missing)

    err = excinfo.value
    assert err.code == "RELAY-CEL-009", err.code
    assert err.subtype == SUBTYPE_ENGINE_REQUEST, err.subtype
    assert not isinstance(err, FileNotFoundError)


def test_one_shot_wasm_path_happy_path_real_artifact_unchanged() -> None:
    """The HAPPY path over the real pinned package-data wasm still evaluates.

    No behavior change to genuine evaluation results: a valid expression over the
    real packaged wasm via the one-shot API returns the correct typed value.
    """
    from relay_contracts.wasm_artifact import resolve_packaged_wasm_path

    packaged = resolve_packaged_wasm_path()
    assert packaged is not None, "packaged wasm must resolve for the happy path"

    ev = WasmCelEvaluator(timeout_ms=250)
    result = ev.evaluate_with_wasm_path("1 + 2", wasm_path=str(packaged))
    assert isinstance(result, celtypes.IntType)
    assert int(result) == 3

    # A binding-carrying expression also flows through unchanged.
    out = ev.evaluate_with_wasm_path(
        "x + y",
        wasm_path=str(packaged),
        bindings={"x": celtypes.IntType(5), "y": celtypes.IntType(7)},
    )
    assert int(out) == 12


def test_shared_path_corrupt_load_wrap_is_unchanged(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The SHARED-engine path still wraps a corrupt load identically (parity anchor).

    Forces ``_resolve_wasm_path_or_none`` (used by ``_ensure_shared``) to return
    the corrupt artifact so the shared bootstrap handle construction hits the
    same ``Module.from_file`` failure. The shared path must continue to wrap it
    into the structured ``RelayCelEngineError`` (RELAY-CEL-009 / ENGINE-REQUEST)
    -- this is the behavior the one-shot fix mirrors, and it must NOT regress.
    """
    import relay_contracts.wasm_backed_evaluator as wbe

    corrupt_path = _write_corrupt_wasm(tmp_path)
    monkeypatch.setattr(
        wbe, "_resolve_wasm_path_or_none", lambda override=None: corrupt_path
    )

    ev = WasmCelEvaluator(timeout_ms=250)
    with pytest.raises(RelayCelEngineError) as excinfo:
        # _ensure_shared is reached on first evaluate() through the shared path.
        ev.evaluate("1 + 2")

    err = excinfo.value
    assert err.code == "RELAY-CEL-009", err.code
    assert err.subtype == SUBTYPE_ENGINE_REQUEST, err.subtype
    assert not isinstance(err, wasmtime.WasmtimeError)
