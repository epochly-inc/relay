"""CEL engine-selection factory -- the SINGLE RELAY_CEL_ENGINE read site.

``make_cel_evaluator()`` is the one place in the whole codebase that reads the
``RELAY_CEL_ENGINE`` environment variable. As of milestone M6 (WS-I) the
single wasm CEL engine is the ONLY Python CEL backend:

  - ``wasm`` (the default, and the value when ``RELAY_CEL_ENGINE`` is unset
    or blank): :class:`relay_contracts.wasm_backed_evaluator.WasmCelEvaluator`.
  - ANY other value -- including the legacy engine token that served as the
    M5 one-release rollback escape hatch -- FAILS CLOSED with a clear
    :class:`ValueError` naming the bad value AND the (wasm-only) allowed set.
    The rollback hatch is closed: the legacy Python CEL engine and its
    dependency were removed at M6, so an explicit legacy selection must be a
    loud structured failure, never a silent fallback to a default.

Why selection lives ONLY here (a load-bearing invariant):

  - The gate engine (``packages/gate``) constructs its evaluator through this
    factory (WS-D / VAL-CWC-P2TSGATE-010) and NEVER reads ``RELAY_CEL_ENGINE``
    itself. A gate-src env read would trip the VAL-W8-005 gate-determinism
    grep (the gate decision must not depend on ambient process environment).
  - Keeping the read in exactly one file means the engine surface (wasm-only
    as of M6) is governed at a single auditable point.

History: M1-M4 defaulted to the legacy engine with wasm behind the flag; M5
(WS-H) flipped the default to wasm with the legacy engine selectable as the
bake-window rollback; M6 (WS-I) removed the legacy engine entirely. The env
var itself is retained as the single selection point so a future engine
addition (if ever) lands here and only here.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from typing import Any, Protocol, runtime_checkable

from .udf import PureUdf
from .wasm_backed_evaluator import WasmCelEvaluator

# The environment variable that selects the CEL engine. Read in THIS module
# only (asserted by test_engine_factory.test_relay_cel_engine_read_only_in_
# engine_module and the VAL-W8-005 / VAL-CWC-P4DUALRUN-008 determinism greps).
_ENGINE_ENV_VAR: str = "RELAY_CEL_ENGINE"

# Canonical engine tokens. ``wasm`` is the only engine as of M6 (WS-I removed
# the legacy backend). Matching is exact (case-sensitive) after
# surrounding-whitespace trim -- no locale-dependent case-folding, so
# selection is deterministic.
_ENGINE_WASM: str = "wasm"

# The default engine when RELAY_CEL_ENGINE is unset or blank. Flipped to wasm
# at M5 (WS-H); the only engine since M6 (WS-I).
_DEFAULT_ENGINE: str = _ENGINE_WASM

_ALLOWED_ENGINES: tuple[str, ...] = (_ENGINE_WASM,)


@runtime_checkable
class CelEvaluatorProtocol(Protocol):
    """The host-side CEL evaluator facade.

    :class:`WasmCelEvaluator` satisfies this protocol structurally, so the
    factory's declared return type is the protocol rather than the concrete
    class. Downstream consumers (the gate engine in WS-D, ``pipeline.py``)
    type the evaluator they hold as ``CelEvaluatorProtocol`` and stay
    engine-agnostic.

    ``probe_compile`` and ``evaluate_with_trace`` are part of the facade:
    ``pipeline.publish_contract`` uses the former for publish-time
    malformed-syntax rejection through the engine's authoritative compiler,
    and ``pipeline.evaluate_assertion`` uses the latter to reconstruct
    ``udf_outputs_jcs`` / ``udfs_invoked`` from the engine's ``udf_trace``
    forensic field.
    """

    timeout_ms: int

    def compile(self, expression: str) -> Any: ...

    def probe_compile(self, expression: str) -> None: ...

    def evaluate(self, expression: str, bindings: Any = ...) -> Any: ...

    def evaluate_with_trace(
        self, expression: str, bindings: Any = ...
    ) -> tuple[Any, dict[str, list[Any]]]: ...


def _select_engine_name() -> str:
    """Resolve the engine name from ``RELAY_CEL_ENGINE`` (the ONLY env read).

    An absent or blank value resolves to the default (wasm). A non-blank
    value is trimmed of surrounding whitespace (a common shell-export
    accident) and matched case-sensitively against the allowed tokens. An
    unknown value -- including the removed legacy engine token -- raises a
    clear :class:`ValueError` naming the allowed set (fail closed, never a
    silent fallback).
    """
    raw = os.environ.get(_ENGINE_ENV_VAR)
    if raw is None:
        return _DEFAULT_ENGINE
    value = raw.strip()
    if value == "":
        # A set-but-blank env var (e.g. ``RELAY_CEL_ENGINE=``) is the standard
        # "no selection" signal; fall back to the default.
        return _DEFAULT_ENGINE
    if value not in _ALLOWED_ENGINES:
        allowed = ", ".join(repr(name) for name in _ALLOWED_ENGINES)
        raise ValueError(
            f"{_ENGINE_ENV_VAR}={value!r} is not a recognized CEL engine; "
            f"allowed values are {allowed} (unset or blank -> "
            f"{_DEFAULT_ENGINE!r}). Engine names are case-sensitive. The "
            f"legacy engine was removed at M6; the wasm engine is the only "
            f"Python CEL backend."
        )
    return value


def make_cel_evaluator(
    *,
    timeout_ms: int | None = None,
    udfs: Iterable[PureUdf] = (),
) -> CelEvaluatorProtocol:
    """Construct the CEL evaluator for the selected engine.

    Reads ``RELAY_CEL_ENGINE`` (the SINGLE read site). ``wasm`` (the default;
    unset / blank) constructs :class:`WasmCelEvaluator`; any other value
    fails closed in :func:`_select_engine_name`. ``timeout_ms`` and ``udfs``
    are forwarded to the evaluator's constructor with IDENTICAL semantics, so
    the factory is a transparent substitute for constructing the class
    directly: the same bound checks (positive int, <= ``MAX_TIMEOUT_MS``) and
    the same UDF handling (the wasm accepts the 3 native ``relay.*`` UDFs and
    rejects any other fail-closed) apply.

    Args:
        timeout_ms: per-evaluation wall-clock budget in milliseconds. ``None``
            (the default) defers to the evaluator's own default
            (``DEFAULT_TIMEOUT_MS``), so callers that do not care get identical
            behavior to constructing the evaluator with no ``timeout_ms``.
        udfs: pure UDFs to register. Forwarded verbatim. The wasm engine
            rejects any non-allowlist UDF at construction
            (``RelayCelUnsupportedUdfError`` / RELAY-CEL-004).

    Returns:
        A :class:`CelEvaluatorProtocol` (a :class:`WasmCelEvaluator`).

    Raises:
        ValueError: ``RELAY_CEL_ENGINE`` holds an unrecognized value (the
            removed legacy engine token included), OR the forwarded
            ``timeout_ms`` is out of bounds (re-raised from the evaluator
            constructor).
        RelayCelUnsupportedUdfError: a non-allowlist UDF was forwarded to the
            wasm engine.
    """
    engine = _select_engine_name()
    # Only pass timeout_ms when the caller supplied one, so the evaluator's own
    # DEFAULT_TIMEOUT_MS governs the unspecified case (identical to direct
    # construction with no timeout_ms argument).
    kwargs: dict[str, Any] = {"udfs": udfs}
    if timeout_ms is not None:
        kwargs["timeout_ms"] = timeout_ms

    if engine == _ENGINE_WASM:
        return WasmCelEvaluator(**kwargs)
    # Defensive: _select_engine_name only returns an allowed token or raises;
    # this is unreachable. Kept as a fail-closed guard rather than a silent
    # default so a future allowed-set edit that forgets a branch is caught.
    raise ValueError(  # pragma: no cover -- unreachable given _select_engine_name
        f"{_ENGINE_ENV_VAR} resolved to an unhandled engine {engine!r}; "
        f"allowed values are {_ALLOWED_ENGINES}."
    )


__all__ = ["CelEvaluatorProtocol", "make_cel_evaluator"]
