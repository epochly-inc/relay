"""CEL engine-selection factory -- the SINGLE RELAY_CEL_ENGINE read site.

``make_cel_evaluator()`` is the one place in the whole codebase that reads the
``RELAY_CEL_ENGINE`` environment variable. It selects between the two
host-side CEL evaluators that share the identical
:class:`CelEvaluatorProtocol` facade (``__init__(*, timeout_ms, udfs)``,
``compile``, ``evaluate``, ``_env``):

  - ``wasm`` (the DEFAULT as of milestone M5, and the value when
    ``RELAY_CEL_ENGINE`` is unset or blank):
    :class:`relay_contracts.wasm_backed_evaluator.WasmCelEvaluator`, the single
    wasm CEL engine behind the host facade. This is now the engine EVERY
    consumer that does not explicitly opt out runs on.
  - ``celpy`` (``RELAY_CEL_ENGINE=celpy``):
    :class:`relay_contracts.evaluator.RelayCelEvaluator`, the legacy
    cel-python-backed evaluator. It is retained ONLY as the rollback escape
    hatch during the one-release bake window (cel-python is removed at M6); a
    deployment that hits a wasm regression can set ``RELAY_CEL_ENGINE=celpy`` to
    fall back to the legacy path while the regression is diagnosed.

An unknown engine name is rejected with a clear :class:`ValueError` naming the
bad value AND the allowed set -- never a silent fallback to a default.

Why selection lives ONLY here (a load-bearing invariant):

  - The gate engine (``packages/gate``) constructs its evaluator through this
    factory (WS-D / VAL-CWC-P2TSGATE-010) and NEVER reads ``RELAY_CEL_ENGINE``
    itself. A gate-src env read would trip the VAL-W8-005 gate-determinism
    grep (the gate decision must not depend on ambient process environment).
  - Keeping the read in exactly one file means the default engine (now wasm, M5)
    and the rollback escape hatch (explicit ``celpy``) are governed at a single
    auditable point.

The M5 flip (this factory's default): an unset / blank ``RELAY_CEL_ENGINE`` now
selects ``wasm``. Through M1-M4 the default was ``celpy`` and the wasm path lived
behind the flag (boundaries.md: "Do NOT flip the RELAY_CEL_ENGINE default to
wasm before milestone M5"); M5 (WS-H) is exactly the milestone that flips it. The
M1-M4 dual-run byte-parity work PROVED celpy and wasm agree on every in-corpus
expression, so the flip is behavior-preserving for the contract/gate workload;
``RELAY_CEL_ENGINE=celpy`` remains the deliberate rollback override until M6.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from typing import Any, Protocol, runtime_checkable

from .evaluator import RelayCelEvaluator
from .udf import PureUdf
from .wasm_backed_evaluator import WasmCelEvaluator

# The environment variable that selects the CEL engine. Read in THIS module
# only (asserted by test_engine_factory.test_relay_cel_engine_read_only_in_
# engine_module and the VAL-W8-005 / VAL-CWC-P4DUALRUN-008 determinism greps).
_ENGINE_ENV_VAR: str = "RELAY_CEL_ENGINE"

# Canonical engine tokens. ``wasm`` is the default as of M5 (the flip landed in
# WS-H / M5); ``celpy`` is the explicit rollback override (removed at M6).
# Matching is exact (case-sensitive) after surrounding-whitespace trim -- no
# locale-dependent case-folding, so selection is deterministic.
_ENGINE_CELPY: str = "celpy"
_ENGINE_WASM: str = "wasm"

# The default engine when RELAY_CEL_ENGINE is unset or blank. FLIPPED to wasm at
# M5 (WS-H) -- this is the cutover's most consequential change: every consumer
# that constructs an evaluator through this factory without setting
# RELAY_CEL_ENGINE now runs on the single wasm CEL engine. M1-M4 kept this at
# celpy behind the flag; the M1-M4 dual-run byte-parity work proved celpy and
# wasm agree, so the flip is behavior-preserving. ``RELAY_CEL_ENGINE=celpy`` is
# the deliberate rollback escape hatch through the one-release bake (until M6).
_DEFAULT_ENGINE: str = _ENGINE_WASM

_ALLOWED_ENGINES: tuple[str, ...] = (_ENGINE_CELPY, _ENGINE_WASM)


@runtime_checkable
class CelEvaluatorProtocol(Protocol):
    """The shared host-side CEL evaluator facade.

    Both :class:`RelayCelEvaluator` and :class:`WasmCelEvaluator` satisfy this
    protocol structurally, so the factory's declared return type is the
    protocol rather than a concrete class. Downstream consumers (the gate
    engine in WS-D, ``pipeline.py``) type the evaluator they hold as
    ``CelEvaluatorProtocol`` and stay engine-agnostic.

    ``_env`` is part of the facade because ``pipeline.py``'s ``udfs_invoked``
    path reads it; the wasm evaluator exposes a typed celpy ``Environment``
    stand-in to keep the facade total.
    """

    timeout_ms: int
    _env: Any

    def compile(self, expression: str) -> Any: ...

    def evaluate(self, expression: str, bindings: Any = ...) -> Any: ...


def _select_engine_name() -> str:
    """Resolve the engine name from ``RELAY_CEL_ENGINE`` (the ONLY env read).

    An absent or blank value resolves to the default (wasm as of M5). A
    non-blank value is trimmed of surrounding whitespace (a common
    shell-export accident) and matched case-sensitively against the allowed
    tokens. An unknown value raises a clear :class:`ValueError`.
    """
    raw = os.environ.get(_ENGINE_ENV_VAR)
    if raw is None:
        return _DEFAULT_ENGINE
    value = raw.strip()
    if value == "":
        # A set-but-blank env var (e.g. ``RELAY_CEL_ENGINE=``) is the standard
        # "no selection" signal; fall back to the default. As of M5 that default
        # is wasm (the flip); an empty export cannot pin the legacy celpy engine
        # -- only an explicit ``RELAY_CEL_ENGINE=celpy`` selects the rollback.
        return _DEFAULT_ENGINE
    if value not in _ALLOWED_ENGINES:
        allowed = ", ".join(repr(name) for name in _ALLOWED_ENGINES)
        raise ValueError(
            f"{_ENGINE_ENV_VAR}={value!r} is not a recognized CEL engine; "
            f"allowed values are {allowed} (unset or blank -> "
            f"{_DEFAULT_ENGINE!r}). Engine names are case-sensitive."
        )
    return value


def make_cel_evaluator(
    *,
    timeout_ms: int | None = None,
    udfs: Iterable[PureUdf] = (),
) -> CelEvaluatorProtocol:
    """Construct the CEL evaluator for the selected engine.

    Reads ``RELAY_CEL_ENGINE`` (the SINGLE read site) to choose the backend:
    ``wasm`` (the M5 default; unset / blank) -> :class:`WasmCelEvaluator`;
    ``celpy`` (the explicit rollback override) -> :class:`RelayCelEvaluator`.
    ``timeout_ms`` and ``udfs`` are forwarded to the selected evaluator's
    constructor with IDENTICAL semantics, so the factory is a transparent
    substitute for constructing either class directly: the same bound checks
    (positive int, <= ``MAX_TIMEOUT_MS``) and the same UDF handling (the wasm
    accepts the 3 native ``relay.*`` UDFs and rejects any other fail-closed; the
    legacy celpy path registers them) apply.

    Args:
        timeout_ms: per-evaluation wall-clock budget in milliseconds. ``None``
            (the default) defers to the evaluator's own default
            (``DEFAULT_TIMEOUT_MS``), so callers that do not care get identical
            behavior to constructing the evaluator with no ``timeout_ms``.
        udfs: pure UDFs to register. Forwarded verbatim. The wasm engine
            rejects any non-allowlist UDF at construction
            (``RelayCelUnsupportedUdfError`` / RELAY-CEL-004).

    Returns:
        A :class:`CelEvaluatorProtocol` -- a ``RelayCelEvaluator`` or a
        ``WasmCelEvaluator`` depending on the selected engine.

    Raises:
        ValueError: ``RELAY_CEL_ENGINE`` holds an unrecognized value, OR the
            forwarded ``timeout_ms`` is out of bounds (re-raised from the
            evaluator constructor).
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

    if engine == _ENGINE_CELPY:
        return RelayCelEvaluator(**kwargs)
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
