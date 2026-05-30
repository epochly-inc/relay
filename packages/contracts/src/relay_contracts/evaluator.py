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
    RelayCelResourceExhaustedError,
    RelayCelTimeoutError,
)
from .udf import PureUdf

# CQ1 line 153 ("timeout-bounded"): default per-evaluation wall-clock
# budget is 50 ms; the per-tenant override caps at 250 ms (also CQ1).
DEFAULT_TIMEOUT_MS: int = 50
MAX_TIMEOUT_MS: int = 250

# Round-3 P1 fix #4: cap on concurrently-live orphan worker threads.
# cel-python evaluation is not cancellable from another thread, so a
# wall-clock timeout leaves the worker alive until cel-python finishes.
# Under adversarial inputs orphans accumulate without bound -- a DoS
# vector. The cap is process-wide (a class-level set on
# RelayCelEvaluator) so concurrent evaluator instances share the same
# budget. 64 is generous for normal traffic (timeouts are exceptional)
# and tight enough to cap DoS damage at a small fixed number of native
# threads.
MAX_ORPHAN_THREADS: int = 64

# VAL-PARITY-001: integral evaluation results whose absolute value exceeds
# 2**53 are rejected at the result boundary. cel-python uses
# arbitrary-precision Python ints, so such a value canonicalises EXACTLY
# (str(n)); a cel-js double silently rounds it (9007199254740993 ->
# 9007199254740992), producing DIVERGENT JCS bytes for the same logical
# result and a cross-runtime digest break (CLAUDE.md keystone invariant #11:
# cross-runtime byte equality). The cel-js mirror applies the SAME numeric
# threshold (abs > 2**53; see contracts-typescript evaluator.ts checkFinite)
# so BOTH runtimes fail-closed identically. The boundary value 2**53 itself
# is a power of two -- exactly representable as an IEEE-754 double,
# byte-identical in both runtimes -- so it is accepted; only abs > 2**53 is
# rejected. (The threshold is abs > 2**53, NOT Number.isSafeInteger, which
# would also reject the byte-safe boundary value 2**53.) This complements
# the NaN/Inf check below (RFC 8785 cannot canonicalise either class).
SAFE_INTEGER_BOUND: int = 2**53  # 9007199254740992

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
#
# VAL-PARITY-007: the digit class is pinned to ASCII `[0-9]` (NOT the bare
# `\d`). A real regex backreference is ASCII `\1`..`\9` only. Python's `\d`
# without `re.ASCII` matches the FULL Unicode Nd category, so `\` followed by
# a NON-ASCII digit (e.g. fullwidth zero U+FF10, Arabic-Indic zero U+0660)
# would be treated as a backref and REJECTED -- while the cel-js mirror
# `/\\\d/` (no `u` flag; JS `\d` is ASCII-only) ACCEPTS it. That asymmetry is
# a cross-runtime divergence (the exact thing VAL-PARITY-007 eliminates), and
# was enlarged by parity-007's first-arg->all-literals widening. Pinning to
# `[0-9]` makes cel-python accept/reject the IDENTICAL set as cel-js: only
# `\`+ASCII-digit is a backref; `\`+non-ASCII-digit is accepted on both.
_BACKREF_PATTERN = re.compile(r"\\[0-9]")  # \1, \2, ... (ASCII only) in a regex literal

# Whole-expression raw-text screen for regex backreferences. We scan the
# ENTIRE source text for any single- or double-quoted CEL string literal
# whose body contains `\<digit>`, regardless of position or receiver. This
# matches the cel-js mirror `checkRegexBackref` in
# packages/contracts-typescript/src/evaluator.ts byte-for-byte in scope, so
# both runtimes accept/reject the IDENTICAL set of expressions (VAL-PARITY-007).
# A narrower screen (only the first string literal of a `.matches()` call)
# failed open for backreferences in sibling sub-expressions, non-first
# `.matches()` arguments, and concatenated string operands.
#
# Both CEL string-quote styles parse the backslash literally, so an inner
# `\1` in the source becomes the RE2-illegal backref `\1` after CEL string
# parsing. The pattern below captures each literal's body (group 1 =
# double-quoted, group 2 = single-quoted) so the backref check runs only
# against literal contents, never against surrounding operators.
_STRING_LITERAL_PATTERN = re.compile(
    r'"((?:[^"\\]|\\.)*)"|\'((?:[^\'\\]|\\.)*)\''
)

# CEL string-method names whose regex argument we screen. Retained for the
# regex-method allow-list; the backreference screen itself is now
# whole-expression (see `_check_regex_backref`).
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

    The regex-backreference screen (RELAY-CEL-007 / REGEX-BACKREF) is a
    separate whole-expression raw-text pass, :func:`_check_regex_backref`,
    run before this AST walk in :meth:`RelayCelEvaluator.compile`. It scans
    every string literal in the source -- not just the first argument of a
    ``.matches()`` call -- so it stays byte-for-byte in scope with the
    cel-js mirror ``checkRegexBackref`` (VAL-PARITY-007).
    """

    for node in _walk_tree(ast):
        data = getattr(node, "data", None)
        if data is None:
            continue
        # Function-call shape: `ident_arg` is the bare-call form
        # (`dyn(x)`) exposing IDENT + exprlist.
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


def _check_regex_backref(expression: str) -> None:
    """Reject any regex backreference (``\\1``..``\\9``) in the raw
    expression text.

    Scans the ENTIRE source for single- and double-quoted CEL string
    literals and rejects with ``RELAY-CEL-007`` /
    ``RELAY-CEL-PROFILE-REGEX-BACKREF`` if ANY literal body contains
    ``\\<digit>``, regardless of position or receiver. This is the
    fail-closed whole-expression scope; it mirrors the cel-js
    ``checkRegexBackref`` (packages/contracts-typescript/src/evaluator.ts)
    so the two runtimes accept/reject the IDENTICAL set of expressions
    (VAL-PARITY-007).

    Run as a pre-screen before AST parse so the structured error surfaces
    even for expressions whose ``.matches()`` argument is a non-first or
    concatenated literal (which a scoped AST screen missed), and so the
    error is RELAY-CEL-007 rather than a leaked RE2 compile error.

    RE2-legal shorthand classes (``\\d``, ``\\w``, ``\\s`` -- backslash
    followed by a LETTER) are NOT matched by ``_BACKREF_PATTERN`` and stay
    accepted. A backreference is ASCII ``\\1``..``\\9`` only:
    ``_BACKREF_PATTERN`` is pinned to ``\\[0-9]`` (VAL-PARITY-007), so a
    backslash followed by a NON-ASCII digit (fullwidth/Arabic-Indic, etc.)
    is NOT flagged -- matching the cel-js mirror whose ``/\\\\d/`` has
    ASCII-only ``\\d`` semantics, so both runtimes accept/reject the same set.
    """

    for match in _STRING_LITERAL_PATTERN.finditer(expression):
        # group(1) = double-quoted body, group(2) = single-quoted body.
        body = match.group(1)
        if body is None:
            body = match.group(2)
        if body is not None and _BACKREF_PATTERN.search(body):
            raise RelayCelRegexBackreferenceError(
                "Relay CEL profile pins regex to the RE2 subset; "
                "backreferences (e.g., \\1) are not supported."
            )


def _check_finite(value: Any) -> Any:
    """Reject NaN / +Inf / -Inf and out-of-safe-range ints at the
    evaluation-result boundary.

    Recurses into lists and maps so a partial result containing a
    non-finite or out-of-range cell is still rejected. Returns the value
    unchanged when no violation is found (caller may keep it for
    canonicalisation).

    Two classes are rejected here so the result can be canonicalised
    cross-runtime byte-identically (CLAUDE.md keystone invariant #11):

      - NaN / +Inf / -Inf: RFC 8785 JCS cannot canonicalise them
        (VAL-W6-006).
      - Integers with abs value > 2**53: cel-python keeps them exact but
        a cel-js double rounds them, so the same logical result would
        canonicalise to DIFFERENT bytes in each runtime (VAL-PARITY-001).
        The boundary value 2**53 is exactly representable as a double and
        is accepted.
    """

    if isinstance(value, bool):
        return value
    if isinstance(value, int | float):
        # celtypes.DoubleType / IntType inherit from float / int.
        if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
            raise RelayCelNumericOutOfBoundsError(
                f"Relay CEL evaluator rejects non-finite number: {value!r}"
            )
        # VAL-PARITY-001: an integral result outside [-2**53, 2**53] is an
        # out-of-band signal -- cel-python preserves it exactly while cel-js
        # loses precision, diverging the cross-runtime digest. Fail-closed
        # in both runtimes. ``int`` covers cel-python's IntType (a subclass);
        # bool was already routed out above. Whole-valued floats are not
        # treated as ints here (they live on the float code path and are
        # already finite-checked); the JS mirror screens them via
        # Number.isSafeInteger on the numeric leaf, but a Python float that
        # large is itself imprecise and is out of scope for this signal.
        if isinstance(value, int) and abs(value) > SAFE_INTEGER_BOUND:
            raise RelayCelNumericOutOfBoundsError(
                "Relay CEL evaluator rejects integer outside the IEEE-754 "
                "safe range [-2**53, 2**53]: a cel-js double would lose "
                f"precision and diverge the cross-runtime digest: {value!r}"
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

    # Round-3 P1 fix #4: class-level tracker for orphan worker threads.
    # cel-python evaluation is not cancellable; on wall-clock timeout
    # we cannot kill the worker thread, so it persists as a daemon
    # orphan until cel-python returns. We cap the live orphan count at
    # MAX_ORPHAN_THREADS to prevent unbounded native-thread accumulation
    # under adversarial input loops. The tracker is class-level (shared
    # across evaluator instances in the process) because thread budget
    # is a process resource. Access is guarded by a class-level lock
    # because evaluate() may be called concurrently from different
    # threads.
    _orphaned_thread_tracker: set[threading.Thread] = set()  # noqa: RUF012
    _orphan_tracker_lock: threading.Lock = threading.Lock()  # noqa: RUF012

    @classmethod
    def _prune_orphans(cls) -> int:
        """Drop terminated threads from the tracker; return live count.

        Holds the tracker lock for the duration. Safe to call from any
        thread.
        """
        with cls._orphan_tracker_lock:
            terminated = {t for t in cls._orphaned_thread_tracker if not t.is_alive()}
            cls._orphaned_thread_tracker.difference_update(terminated)
            return len(cls._orphaned_thread_tracker)

    @classmethod
    def _register_orphan(cls, thread: threading.Thread) -> None:
        """Add ``thread`` to the orphan tracker.

        Caller MUST have verified the live count is under the cap via
        :meth:`_prune_orphans` immediately prior.
        """
        with cls._orphan_tracker_lock:
            cls._orphaned_thread_tracker.add(thread)

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
        # Pre-screen regex backreferences in the raw expression text before
        # parse, so a backref in ANY string literal (not just the first
        # `.matches()` argument) surfaces RELAY-CEL-007. Mirrors the cel-js
        # `checkRegexBackref` pre-parse screen (VAL-PARITY-007).
        _check_regex_backref(expression)
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

        # Round-3 P1 fix #4: prune dead orphans, then refuse to spawn if
        # the live count is at the cap. cel-python evaluation is not
        # cancellable from another thread; a timeout leaves the worker
        # alive until cel-python finishes. Without the cap, adversarial
        # input loops accumulate unbounded native threads -- a DoS
        # vector. The check + spawn must happen atomically under the
        # tracker lock to avoid the TOCTOU race where two callers both
        # observe ``live < cap`` and both spawn.
        with type(self)._orphan_tracker_lock:
            # Inline prune to keep the live-count check and the
            # subsequent thread.start() under the same lock acquisition.
            terminated = {
                t for t in type(self)._orphaned_thread_tracker
                if not t.is_alive()
            }
            type(self)._orphaned_thread_tracker.difference_update(terminated)
            live_count = len(type(self)._orphaned_thread_tracker)
            if live_count >= MAX_ORPHAN_THREADS:
                raise RelayCelResourceExhaustedError(
                    f"Relay CEL evaluator orphan-thread cap reached "
                    f"({live_count}/{MAX_ORPHAN_THREADS}); refusing to "
                    f"spawn another worker. Wait for live orphans to "
                    f"finish or restart the process. Expression: "
                    f"{expression!r}"
                )

            def _run() -> None:
                try:
                    result_box["value"] = compiled.runner.evaluate(bindings)
                except BaseException as exc:  # noqa: BLE001 -- forward to main thread
                    error_box["error"] = exc

            thread = threading.Thread(target=_run, daemon=True)
            # Register BEFORE start so a concurrent prune sees the
            # not-yet-alive thread as live (is_alive() is True after
            # start; False before, but Thread() instances are not in
            # the running state until start() is called -- we keep the
            # registration here to preserve the atomic check+spawn
            # invariant).
            type(self)._orphaned_thread_tracker.add(thread)
            thread.start()
        # Lock released; the worker runs concurrently. join() outside
        # the lock so concurrent evaluate() calls are not serialised on
        # the worker's run time.
        thread.join(timeout=self.timeout_ms / 1000.0)
        if thread.is_alive():
            # cel-python evaluation is not interruptible mid-step from
            # another thread; the daemon thread will be reaped at
            # interpreter exit OR pruned from the orphan tracker once
            # cel-python finishes (whichever comes first). We surface
            # the timeout immediately and do NOT bind a partial result
            # -- VAL-W6-003 explicitly forbids partial-state leakage.
            # The thread REMAINS in the orphan tracker; the next
            # evaluate() call will prune it once is_alive() returns
            # False.
            raise RelayCelTimeoutError(
                f"Relay CEL evaluation exceeded {self.timeout_ms} ms wall-clock "
                f"budget for expression: {expression!r}"
            )
        # Thread completed -- remove from the orphan tracker so the
        # budget is freed for future calls. Held briefly under the
        # tracker lock.
        with type(self)._orphan_tracker_lock:
            type(self)._orphaned_thread_tracker.discard(thread)
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
