"""Engine-agnostic host-side CEL guards (locked decision #4).

M6 WS-I removed the legacy Python CEL engine; the single wasm CEL engine
(``wasm_backed_evaluator.WasmCelEvaluator``) is the only Python CEL backend.
This module is the surviving HOST-SIDE home for the guards that were always
host-owned and engine-agnostic (ADR cel-wasm-cutover-workstreams, locked
decision #4: "host-side guards stay in the host"):

  - the whole-expression regex-backreference pre-screen
    (RELAY-CEL-007 / RELAY-CEL-PROFILE-REGEX-BACKREF), VAL-W6-007 /
    VAL-PARITY-007;
  - the compile-time Relay-profile screen over statically-referenced bare
    callees (RELAY-CEL-002 / DYN- / TS- / DUR-DISABLED), VAL-W6-002;
  - the result-boundary finiteness / IEEE-754-safe-integer guard
    (RELAY-CEL-006 / RELAY-CEL-NUMERIC-OOB), VAL-W6-006 / VAL-PARITY-001;
  - the wall-clock timeout + process-wide orphan-thread cap
    (RELAY-CEL-003 / RELAY-CEL-008), VAL-W6-003;
  - the canonical timeout constants (CQ1: default 50 ms, cap 250 ms).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import math
import re
import threading
from collections.abc import Iterable, Mapping
from typing import Any

from .errors import (
    SUBTYPE_PROFILE_DUR_DISABLED,
    SUBTYPE_PROFILE_DYN_DISABLED,
    SUBTYPE_PROFILE_TS_DISABLED,
    RelayCelNumericOutOfBoundsError,
    RelayCelProfileError,
    RelayCelRegexBackreferenceError,
    RelayCelResourceExhaustedError,
    RelayCelTimeoutError,
)
from .wasm_codec import CelMap

# CQ1 line 153 ("timeout-bounded"): default per-evaluation wall-clock
# budget is 50 ms; the per-tenant override caps at 250 ms (also CQ1).
DEFAULT_TIMEOUT_MS: int = 50
MAX_TIMEOUT_MS: int = 250

# Round-3 P1 fix #4: cap on concurrently-live orphan worker threads.
# The engine's eval primitive is not cancellable from another thread, so a
# wall-clock timeout leaves the worker alive until the engine finishes.
# Under adversarial inputs orphans accumulate without bound -- a DoS
# vector. The cap is PROCESS-WIDE (a module-level tracker shared by every
# evaluator instance) because thread budget is a process resource. 64 is
# generous for normal traffic (timeouts are exceptional) and tight enough
# to cap DoS damage at a small fixed number of native threads.
MAX_ORPHAN_THREADS: int = 64

# VAL-PARITY-001: integral evaluation results whose absolute value EXCEEDS
# Number.MAX_SAFE_INTEGER (2**53 - 1) are rejected at the result boundary.
# The Python host preserves large ints exactly (arbitrary precision), so such
# a value canonicalises EXACTLY (str(n)); an IEEE-754 double host silently
# rounds it (9007199254740993 -> 9007199254740992), producing DIVERGENT JCS
# bytes for the same logical result and a cross-runtime digest break
# (CLAUDE.md keystone invariant: cross-runtime byte equality). The TS mirror
# applies the SAME numeric threshold (abs > MAX_SAFE_INTEGER; see
# contracts-typescript evaluator checkFinite) so BOTH runtimes fail-closed
# identically.
#
# The threshold is MAX_SAFE_INTEGER (2**53 - 1), NOT 2**53: 2**53 is itself
# NOT a safe integer -- it cannot be distinguished from 2**53 + 1 after
# IEEE-754 double rounding. A double host rounds an integer overflow that
# lands on 2**53 + 1 down to 2**53; accepting exactly 2**53 (the prior,
# EXCLUSIVE bound) let the double host silently pass that rounded integer
# overflow (fail-open relative to the exact-int host, which keeps the value
# exact and rejects it). Rejecting magnitude >= 2**53 closes that gap. Key
# identity: for any integer V, float64(V) > MAX_SAFE_INTEGER <=> V >= 2**53,
# so the exact-int host and a float64 host give the SAME verdict for every
# integer, including arithmetic overflow. (Found by `codex review`: CEL
# +-2^53 Py<->TS parity P1; CONFIRMED empirically.) This complements the
# NaN/Inf check below (RFC 8785 cannot canonicalise either class).
SAFE_INTEGER_BOUND: int = 2**53 - 1  # 9007199254740991 == Number.MAX_SAFE_INTEGER

# Disabled native CEL identifiers when used as bare function calls
# (`dyn(x)`, `timestamp("...")`, `duration("...")`). Detection runs at
# compile time over the statically-referenced callee set so the violation
# is surfaced before any evaluation -- including a short-circuited branch
# the engine would never execute.
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

# Regex feature detection. RE2 (the regex subset the Relay profile pins)
# rejects backreferences, lookaround, and possessive quantifiers; we
# pre-screen and emit the structured error code so callers see
# RELAY-CEL-007 / RELAY-CEL-PROFILE-REGEX-BACKREF rather than a leaked
# engine regex error.
#
# VAL-PARITY-007: the digit class is pinned to ASCII `[0-9]` (NOT the bare
# `\d`). A real regex backreference is ASCII `\1`..`\9` only. Python's `\d`
# without `re.ASCII` matches the FULL Unicode Nd category, so `\` followed by
# a NON-ASCII digit (e.g. fullwidth zero U+FF10, Arabic-Indic zero U+0660)
# would be treated as a backref and REJECTED -- while the TS mirror
# `/\\\d/` (no `u` flag; JS `\d` is ASCII-only) ACCEPTS it. That asymmetry is
# a cross-runtime divergence (the exact thing VAL-PARITY-007 eliminates).
# Pinning to `[0-9]` makes the Python host accept/reject the IDENTICAL set as
# the TS host: only `\`+ASCII-digit is a backref; `\`+non-ASCII-digit is
# accepted on both.
_BACKREF_PATTERN = re.compile(r"\\[0-9]")  # \1, \2, ... (ASCII only) in a regex literal

# Whole-expression raw-text screen for regex backreferences. We scan the
# ENTIRE source text for any single- or double-quoted CEL string literal
# whose body contains `\<digit>`, regardless of position or receiver. This
# matches the TS mirror `checkRegexBackref` in
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


def check_profile_callees(callees: Iterable[str]) -> None:
    """Reject statically-referenced disabled-builtin calls (RELAY-CEL-002).

    ``callees`` is the bare-call identifier set in SOURCE ORDER (see
    :func:`relay_contracts.callee_parser.extract_bare_callees`); the first
    disabled builtin encountered raises, so rejection is deterministic for a
    given expression. Member calls (``x.timestamp(...)``) are not in the
    bare-callee set and are not flagged -- matching the legacy compile-time
    screen this replaces, which only inspected bare-call nodes.
    """
    for name in callees:
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
    fail-closed whole-expression scope; it mirrors the TS
    ``checkRegexBackref`` (packages/contracts-typescript/src/evaluator.ts)
    so the two runtimes accept/reject the IDENTICAL set of expressions
    (VAL-PARITY-007).

    Run as a pre-screen before the engine call so the structured error
    surfaces even for expressions whose ``.matches()`` argument is a
    non-first or concatenated literal (which a scoped AST screen missed),
    and so the error is RELAY-CEL-007 rather than a leaked engine regex
    error.

    RE2-legal shorthand classes (``\\d``, ``\\w``, ``\\s`` -- backslash
    followed by a LETTER) are NOT matched by ``_BACKREF_PATTERN`` and stay
    accepted. A backreference is ASCII ``\\1``..``\\9`` only:
    ``_BACKREF_PATTERN`` is pinned to ``\\[0-9]`` (VAL-PARITY-007), so a
    backslash followed by a NON-ASCII digit (fullwidth/Arabic-Indic, etc.)
    is NOT flagged -- matching the TS mirror whose ``/\\\\d/`` has
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

    Three classes are rejected here so the result can be canonicalised
    cross-runtime byte-identically (CLAUDE.md keystone invariant):

      - NaN / +Inf / -Inf: RFC 8785 JCS cannot canonicalise them
        (VAL-W6-006).
      - Integers with abs value > MAX_SAFE_INTEGER (2**53 - 1): the Python
        host keeps them exact but an IEEE-754 double host rounds them, so the
        same logical result would canonicalise to DIFFERENT bytes in each
        runtime (VAL-PARITY-001). 2**53 itself is NOT a safe integer (a
        rounded overflow may land on it) so it is rejected; only magnitude
        <= MAX_SAFE_INTEGER is accepted.
      - Whole-valued DOUBLES (``.is_integer()``) with abs value
        > MAX_SAFE_INTEGER: the TS host erases the CEL int/double distinction
        at the result boundary (it classifies any whole-valued number as int
        and rejects it via the same bound), so the Python host MUST reject
        the whole-valued double too or the two runtimes diverge -- Python
        ACCEPT, TS REJECT (VAL-PARITY-001 whole-double branch). Note that
        no representable float64 of magnitude > MAX_SAFE_INTEGER is
        non-integral (the ULP at 2**53 is 2.0), so a genuinely non-integral
        double (e.g. 1.5) is always within the safe range and stays accepted.
    """

    if isinstance(value, bool):
        return value
    if isinstance(value, int | float):
        if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
            raise RelayCelNumericOutOfBoundsError(
                f"Relay CEL evaluator rejects non-finite number: {value!r}"
            )
        # VAL-PARITY-001: an integral result outside
        # [-(2**53 - 1), 2**53 - 1] is an out-of-band signal -- the Python
        # host preserves it exactly while a float64 host loses precision,
        # diverging the cross-runtime digest. Fail-closed in both runtimes.
        # bool was already routed out above; a float does NOT match this
        # ``int`` branch -- whole-valued doubles beyond the bound are caught
        # by the dedicated float branch just below.
        if isinstance(value, int) and abs(value) > SAFE_INTEGER_BOUND:
            raise RelayCelNumericOutOfBoundsError(
                "Relay CEL evaluator rejects integer outside the IEEE-754 "
                "safe range [-(2**53 - 1), 2**53 - 1]: a float64 host would "
                f"lose precision and diverge the cross-runtime digest: {value!r}"
            )
        # VAL-PARITY-001 (whole-valued double branch): a CEL DOUBLE whose value
        # is whole (``.is_integer()``) and whose magnitude exceeds
        # MAX_SAFE_INTEGER is rejected too, so the Python and TS hosts give
        # the SAME verdict. The TS host collapses CEL int and CEL double to a
        # bare JS ``number`` and re-derives the type from the value
        # (classifying ANY whole-valued number as int), so the DOUBLE literal
        # ``9007199254740994.0`` is INDISTINGUISHABLE there from the int
        # ``9007199254740994`` and is rejected by the int bound in the TS
        # checkFinite. The Python host preserves the type (a float routed
        # onto THIS branch -- bool was excluded at the top, NaN/Inf raised
        # just above so ``.is_integer()`` only runs on a finite float), so an
        # int-only bound would let Python ACCEPT this double while TS
        # REJECTED it -- a cross-runtime divergence. Rejecting the
        # whole-valued double here closes it, fail-closed in BOTH runtimes.
        #
        # No representable float64 of magnitude > MAX_SAFE_INTEGER is
        # non-integral (the ULP at 2**53 is 2.0), so this branch NEVER fires
        # on a fractional double; a genuinely non-integral double (e.g. 1.5)
        # is always within the safe range and stays accepted.
        if (
            isinstance(value, float)
            and value.is_integer()
            and abs(value) > SAFE_INTEGER_BOUND
        ):
            raise RelayCelNumericOutOfBoundsError(
                "Relay CEL evaluator rejects integer outside the IEEE-754 "
                "safe range [-(2**53 - 1), 2**53 - 1]: a float64 host would "
                f"lose precision and diverge the cross-runtime digest: {value!r}"
            )
        return value
    if isinstance(value, list | tuple):
        for item in value:
            _check_finite(item)
        return value
    if isinstance(value, CelMap):
        # A wasm map with non-string keys (bool/int/uint) decodes to the
        # lossless CelMap pair-list (ROBOREV M6 finding A); it is not a
        # Mapping, so walk its VALUES explicitly. Keys are the VERBATIM
        # typed-canonical key objects (scalar CEL keys, never collections),
        # mirroring the TS checkFinite Map branch, which iterates
        # map.values() only.
        for _typed_key, v in value.pairs:
            _check_finite(v)
        return value
    if isinstance(value, Mapping):
        for k, v in value.items():
            _check_finite(k)
            _check_finite(v)
        return value
    return value


# ---------------------------------------------------------------------------
# Host-side wall-clock timeout + process-wide orphan-thread cap
# ---------------------------------------------------------------------------

# Round-3 P1 fix #4: module-level tracker for orphan worker threads.
# Engine evaluation is not cancellable; on wall-clock timeout we cannot
# kill the worker thread, so it persists as a daemon orphan until the
# engine returns. We cap the live orphan count at MAX_ORPHAN_THREADS to
# prevent unbounded native-thread accumulation under adversarial input
# loops. The tracker is module-level (shared across evaluator instances in
# the process) because thread budget is a process resource. Access is
# guarded by the module-level lock because run_with_timeout may be called
# concurrently from different threads. (Formerly class-level state on the
# legacy evaluator; WS-I moved it to this engine-agnostic module home.)
_orphaned_thread_tracker: set[threading.Thread] = set()
_orphan_tracker_lock: threading.Lock = threading.Lock()


def _prune_orphans() -> int:
    """Drop terminated threads from the tracker; return live count.

    Holds the tracker lock for the duration. Safe to call from any thread.
    """
    with _orphan_tracker_lock:
        terminated = {t for t in _orphaned_thread_tracker if not t.is_alive()}
        _orphaned_thread_tracker.difference_update(terminated)
        return len(_orphaned_thread_tracker)


def run_with_timeout(run: Any, timeout_seconds: float) -> Any:
    """Run a 0-arg callable under the host wall-clock budget + orphan cap.

    Engine-agnostic host-side guard (VAL-CWC-P1HOST-002) used by the
    wasm-backed evaluator. The engine's eval primitive is not cancellable
    from another thread, so a wall-clock timeout leaves the worker thread
    alive until the engine finishes; the process-wide orphan cap
    (``MAX_ORPHAN_THREADS``) bounds unbounded native-thread accumulation
    under adversarial input loops (a DoS vector).

    ``run`` is invoked on a fresh daemon worker thread; its return value
    is returned faithfully (falsy / None values included -- the result is
    carried through a box, not inferred from truthiness). A non-Relay
    exception raised by ``run`` is re-raised on the calling thread and the
    worker is deregistered from the orphan tracker (no slot leak on the
    error path). Numeric / finiteness checks and ``RelayCelError`` mapping
    stay with the caller (engine-specific) -- this helper only owns the
    timeout + orphan-cap mechanism.

    Raises:
        RelayCelResourceExhaustedError: at the orphan-thread cap (the
            callable is NOT spawned).
        RelayCelTimeoutError: the worker did not return within
            ``timeout_seconds`` (the worker stays a tracked daemon orphan,
            pruned by a later call once it terminates).
    """

    result_box: dict[str, Any] = {}
    error_box: dict[str, BaseException] = {}

    # Round-3 P1 fix #4: prune dead orphans, then refuse to spawn if
    # the live count is at the cap. The engine eval primitive is not
    # cancellable from another thread; a timeout leaves the worker
    # alive until it finishes. Without the cap, adversarial input
    # loops accumulate unbounded native threads -- a DoS vector. The
    # check + spawn must happen atomically under the tracker lock to
    # avoid the TOCTOU race where two callers both observe
    # ``live < cap`` and both spawn.
    with _orphan_tracker_lock:
        # Inline prune to keep the live-count check and the
        # subsequent thread.start() under the same lock acquisition.
        terminated = {
            t for t in _orphaned_thread_tracker
            if not t.is_alive()
        }
        _orphaned_thread_tracker.difference_update(terminated)
        live_count = len(_orphaned_thread_tracker)
        if live_count >= MAX_ORPHAN_THREADS:
            raise RelayCelResourceExhaustedError(
                f"Relay CEL evaluator orphan-thread cap reached "
                f"({live_count}/{MAX_ORPHAN_THREADS}); refusing to "
                f"spawn another worker. Wait for live orphans to "
                f"finish or restart the process."
            )

        def _worker() -> None:
            try:
                result_box["value"] = run()
            except BaseException as exc:  # noqa: BLE001 -- forward to main thread
                error_box["error"] = exc

        thread = threading.Thread(target=_worker, daemon=True)
        # Register BEFORE start so a concurrent prune sees the
        # not-yet-alive thread as live (is_alive() is True after
        # start; False before, but Thread() instances are not in
        # the running state until start() is called -- we keep the
        # registration here to preserve the atomic check+spawn
        # invariant).
        _orphaned_thread_tracker.add(thread)
        thread.start()
    # Lock released; the worker runs concurrently. join() outside
    # the lock so concurrent calls are not serialised on the
    # worker's run time.
    thread.join(timeout=timeout_seconds)
    if thread.is_alive():
        # The engine eval primitive is not interruptible mid-step
        # from another thread; the daemon thread will be reaped at
        # interpreter exit OR pruned from the orphan tracker once it
        # finishes (whichever comes first). We surface the timeout
        # immediately and do NOT bind a partial result -- VAL-W6-003
        # explicitly forbids partial-state leakage. The thread
        # REMAINS in the orphan tracker; the next call will prune it
        # once is_alive() returns False.
        raise RelayCelTimeoutError(
            f"Relay CEL evaluation exceeded {timeout_seconds * 1000.0:g} ms "
            f"wall-clock budget."
        )
    # Thread completed -- remove from the orphan tracker so the
    # budget is freed for future calls. Held briefly under the
    # tracker lock.
    with _orphan_tracker_lock:
        _orphaned_thread_tracker.discard(thread)
    if "error" in error_box:
        # A callable exception (Relay or not) is re-raised on the
        # caller thread. The worker has already been deregistered
        # above, so there is no orphan-slot leak on this path.
        raise error_box["error"]
    return result_box.get("value")


def validate_timeout_ms(timeout_ms: Any) -> int:
    """Validate an evaluator ``timeout_ms`` against the canonical bounds.

    A positive ``int`` (bool excluded -- True/False are not valid budgets)
    no greater than ``MAX_TIMEOUT_MS``. Returns the value unchanged on
    success; raises ``ValueError`` otherwise. Shared so every evaluator
    construction path enforces IDENTICAL bounds.
    """
    if (
        not isinstance(timeout_ms, int)
        or isinstance(timeout_ms, bool)
        or timeout_ms <= 0
    ):
        raise ValueError(
            f"timeout_ms MUST be a positive int; got {timeout_ms!r}"
        )
    if timeout_ms > MAX_TIMEOUT_MS:
        raise ValueError(
            f"timeout_ms exceeds Relay cap ({MAX_TIMEOUT_MS} ms); "
            f"got {timeout_ms}"
        )
    return timeout_ms


__all__ = [
    "DEFAULT_TIMEOUT_MS",
    "MAX_ORPHAN_THREADS",
    "MAX_TIMEOUT_MS",
    "SAFE_INTEGER_BOUND",
    "check_profile_callees",
    "run_with_timeout",
    "validate_timeout_ms",
]
