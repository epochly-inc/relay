"""Relay-profile cel-python evaluator wrapper.

The single Python CEL evaluator (VAL-W6-001). Constructed with the Relay
CEL profile (VAL-W6-002): ``dyn`` disabled, native CEL ``timestamp(...)``
and ``duration(...)`` disabled, regex pinned to the RE2 subset that
cel-python's ``re2`` binding accepts (VAL-W6-007). Every evaluation
runs under a wall-clock timeout (VAL-W6-003) and rejects NaN / +Inf /
-Inf at the result boundary (VAL-W6-006). UDFs are registered through
the pure-only :func:`register_udf` (VAL-W6-004).

The evaluator is a thin wrapper around :class:`celpy.Environment`; we do
not vendor or re-implement CEL parsing -- CQ1 line 145 mandates
cel-python is the *single* Python implementation.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import math
import re
import threading
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

import celpy
import celpy.celtypes as celtypes

from .errors import (
    SUBTYPE_PROFILE_DUR_DISABLED,
    SUBTYPE_PROFILE_DYN_DISABLED,
    SUBTYPE_PROFILE_TS_DISABLED,
    RelayCelError,
    RelayCelNumericOutOfBoundsError,
    RelayCelProfileError,
    RelayCelRegexBackreferenceError,
    RelayCelTimeoutError,
)
from .udf import PureUdf

# CQ1 line 153 ("timeout-bounded"): default per-evaluation wall-clock
# budget is 50 ms; the per-tenant override caps at 250 ms (also CQ1).
DEFAULT_TIMEOUT_MS: int = 50
MAX_TIMEOUT_MS: int = 250

# Disabled native CEL identifiers when used as function calls
# (`dyn(x)`, `timestamp("...")`, `duration("...")`). Detection runs at
# parse/check time so the violation is surfaced before any evaluation.
_DISABLED_BUILTINS = {
    "dyn": (
        "Relay CEL profile disables 'dyn(...)': dynamic typing breaks "
        "cross-runtime determinism.",
        SUBTYPE_PROFILE_DYN_DISABLED,
    ),
    "timestamp": (
        "Relay CEL profile disables native 'timestamp(...)': use "
        "schema-typed timestamp inputs instead.",
        SUBTYPE_PROFILE_TS_DISABLED,
    ),
    "duration": (
        "Relay CEL profile disables native 'duration(...)': use "
        "schema-typed duration inputs instead.",
        SUBTYPE_PROFILE_DUR_DISABLED,
    ),
}

# Regex feature detection. RE2 (and cel-python's `google-re2` binding)
# rejects backreferences, lookaround, and possessive quantifiers; we
# pre-screen and emit the structured error code so callers see
# RELAY-CEL-007 / RELAY-CEL-PROFILE-REGEX-BACKREF rather than a leaked
# cel-python parse error.
_BACKREF_PATTERN = re.compile(r"\\\d")  # \1, \2, ... in a regex literal

# CEL string-method names whose regex argument we screen.
_REGEX_METHODS = {"matches"}


@dataclass(frozen=True)
class _CompiledExpression:
    """Held internally by the evaluator after parse + check.

    ``runner`` is the cel-python program. ``udf_functions`` is the
    function map passed at evaluation time (pure UDFs only).
    """

    expression: str
    runner: Any
    udf_functions: dict[str, Any]


def _walk_tree(node: Any) -> Iterable[Any]:
    """Yield every node in a lark Tree (incl. Token leaves)."""

    yield node
    children = getattr(node, "children", None)
    if children is None:
        return
    for child in children:
        yield from _walk_tree(child)


def _check_profile(ast: Any) -> None:
    """Reject expressions that violate the Relay CEL profile.

    Walks the lark tree returned by :meth:`celpy.Environment.compile`
    and rejects:

      - ``dyn(...)`` calls (RELAY-CEL-002 / DYN-DISABLED)
      - native ``timestamp(...)`` calls (RELAY-CEL-002 / TS-DISABLED)
      - native ``duration(...)`` calls (RELAY-CEL-002 / DUR-DISABLED)
      - ``"...".matches("...\\1...")`` regex backreferences
        (RELAY-CEL-007 / REGEX-BACKREF)
    """

    for node in _walk_tree(ast):
        data = getattr(node, "data", None)
        if data is None:
            continue
        # Function-call shapes: `ident_arg` is the bare-call form
        # (`dyn(x)`); `member_dot_arg` is the method form
        # (`"abc".matches("...")`). Both expose IDENT + exprlist.
        if data == "ident_arg":
            ident_token = next(
                (
                    c for c in node.children
                    if hasattr(c, "type") and getattr(c, "type", None) == "IDENT"
                ),
                None,
            )
            if ident_token is None:
                continue
            name = str(ident_token)
            entry = _DISABLED_BUILTINS.get(name)
            if entry is not None:
                msg, subtype = entry
                raise RelayCelProfileError(msg, subtype=subtype)
        elif data == "member_dot_arg":
            # Find the trailing IDENT (method name) and the exprlist.
            ident_token = None
            exprlist = None
            for c in node.children:
                if hasattr(c, "type") and getattr(c, "type", None) == "IDENT":
                    ident_token = c
                elif getattr(c, "data", None) == "exprlist":
                    exprlist = c
            if ident_token is None or exprlist is None:
                continue
            method_name = str(ident_token)
            if method_name not in _REGEX_METHODS:
                continue
            # Walk the exprlist looking for a string literal first arg.
            for sub in _walk_tree(exprlist):
                if hasattr(sub, "type") and getattr(sub, "type", None) == "STRING_LIT":
                    raw = str(sub)
                    # Strip the surrounding quotes; cel-python emits the
                    # literal with its delimiters intact.
                    if len(raw) >= 2 and raw[0] in ("'", '"') and raw[-1] == raw[0]:
                        body = raw[1:-1]
                    else:
                        body = raw
                    if _BACKREF_PATTERN.search(body):
                        raise RelayCelRegexBackreferenceError(
                            "Relay CEL profile pins regex to the RE2 subset; "
                            "backreferences (e.g., \\1) are not supported."
                        )
                    break  # only check the first string literal


def _check_finite(value: Any) -> Any:
    """Reject NaN / +Inf / -Inf at the evaluation-result boundary.

    Recurses into lists and maps so a partial result containing a
    non-finite cell is still rejected. Returns the value unchanged when
    no violation is found (caller may keep it for canonicalisation).
    """

    if isinstance(value, bool):
        return value
    if isinstance(value, int | float):
        # celtypes.DoubleType / IntType inherit from float / int.
        if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
            raise RelayCelNumericOutOfBoundsError(
                f"Relay CEL evaluator rejects non-finite number: {value!r}"
            )
        return value
    if isinstance(value, list | tuple):
        for item in value:
            _check_finite(item)
        return value
    if isinstance(value, Mapping):
        for k, v in value.items():
            _check_finite(k)
            _check_finite(v)
        return value
    return value


class RelayCelEvaluator:
    """Cel-python wrapper bound to the Relay profile.

    Construction is cheap: a fresh :class:`celpy.Environment` plus a
    UDF registry. Per-expression compilation is cached by expression
    text on the instance so repeated evaluations of the same contract
    do not re-parse.
    """

    def __init__(
        self,
        *,
        timeout_ms: int = DEFAULT_TIMEOUT_MS,
        udfs: Iterable[PureUdf] = (),
    ) -> None:
        if not isinstance(timeout_ms, int) or timeout_ms <= 0:
            raise ValueError(
                f"timeout_ms MUST be a positive int; got {timeout_ms!r}"
            )
        if timeout_ms > MAX_TIMEOUT_MS:
            raise ValueError(
                f"timeout_ms exceeds Relay cap ({MAX_TIMEOUT_MS} ms); "
                f"got {timeout_ms}"
            )
        self.timeout_ms = timeout_ms
        # Annotations name the UDF callables for cel-python's type
        # checker. Each UDF MUST already be a PureUdf (pure=True).
        self._udfs: dict[str, PureUdf] = {}
        annotations: dict[str, Any] = {}
        for udf in udfs:
            if not isinstance(udf, PureUdf):
                raise TypeError(
                    "RelayCelEvaluator: udfs must be PureUdf instances "
                    "(use register_udf to construct)."
                )
            self._udfs[udf.name] = udf
            annotations[udf.name] = celtypes.FunctionType
        self._env = celpy.Environment(annotations=annotations)
        self._compile_cache: dict[str, _CompiledExpression] = {}

    # --- Compilation -------------------------------------------------

    def compile(self, expression: str) -> _CompiledExpression:
        """Parse + check ``expression`` against the Relay CEL profile.

        Cached by expression text. Profile violations raise at this
        point (not at evaluate-time) so the gate runner sees the
        structured error before any value is bound.
        """

        cached = self._compile_cache.get(expression)
        if cached is not None:
            return cached
        try:
            ast = self._env.compile(expression)
        except RelayCelError:
            raise
        except Exception as exc:  # pragma: no cover -- cel-python parse errors
            raise RelayCelProfileError(
                f"cel-python parse failed: {exc}",
                subtype=SUBTYPE_PROFILE_DYN_DISABLED,
            ) from exc
        _check_profile(ast)
        functions = {name: udf.fn for name, udf in self._udfs.items()}
        runner = self._env.program(ast, functions=functions or None)
        compiled = _CompiledExpression(
            expression=expression, runner=runner, udf_functions=functions
        )
        self._compile_cache[expression] = compiled
        return compiled

    # --- Evaluation --------------------------------------------------

    def evaluate(
        self,
        expression: str,
        bindings: Mapping[str, Any] | None = None,
    ) -> Any:
        """Evaluate ``expression`` with ``bindings``.

        Runs under the configured wall-clock timeout. NaN / +Inf / -Inf
        in the result raise :class:`RelayCelNumericOutOfBoundsError`.
        Profile violations raise :class:`RelayCelProfileError` at
        :meth:`compile` time, before evaluation begins.
        """

        compiled = self.compile(expression)
        bindings = dict(bindings or {})
        result_box: dict[str, Any] = {}
        error_box: dict[str, BaseException] = {}

        def _run() -> None:
            try:
                result_box["value"] = compiled.runner.evaluate(bindings)
            except BaseException as exc:  # noqa: BLE001 -- forward to main thread
                error_box["error"] = exc

        thread = threading.Thread(target=_run, daemon=True)
        thread.start()
        thread.join(timeout=self.timeout_ms / 1000.0)
        if thread.is_alive():
            # cel-python evaluation is not interruptible mid-step from
            # another thread; the daemon thread will be reaped at
            # interpreter exit. We surface the timeout immediately and
            # do NOT bind a partial result -- VAL-W6-003 explicitly
            # forbids partial-state leakage.
            raise RelayCelTimeoutError(
                f"Relay CEL evaluation exceeded {self.timeout_ms} ms wall-clock "
                f"budget for expression: {expression!r}"
            )
        if "error" in error_box:
            err = error_box["error"]
            if isinstance(err, RelayCelError):
                raise err
            # cel-python raises celpy.CELEvalError and friends; surface
            # them as profile errors with the original message preserved.
            raise RelayCelProfileError(
                f"cel-python evaluation failed: {err}",
                subtype=SUBTYPE_PROFILE_DYN_DISABLED,
            ) from err
        value = result_box.get("value")
        return _check_finite(value)


__all__ = ["DEFAULT_TIMEOUT_MS", "MAX_TIMEOUT_MS", "RelayCelEvaluator"]
