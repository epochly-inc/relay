"""ReDoS regex budget for redaction-policy publish (VAL-V2M08-005).

Spec anchor: AI line 5665.

Per spec G + AI line 5665 and contract VAL-V2M08-005, every regex
matcher in a candidate ``redaction_policies.body`` is executed against
a published catastrophic-backtracking corpus under a per-input
wall-clock budget (:data:`REDACTION_REGEX_BUDGET_MS` = 50 ms). A matcher
that exceeds the budget on any single input fails the policy publish
with code ``RELAY-REDACT-014``; the rejection envelope carries the
offending ``matcher_id`` and the ``measured_ms`` so the policy author
can revise the pattern.

The wall-clock measurement runs the regex on a background thread so
the budget enforcer never deadlocks a runaway regex. Python's ``re``
engine is single-threaded and ``GIL``-bound, but the budget enforcer
yields by setting a deadline; if the regex thread is still alive after
the budget elapses, the envelope is returned without blocking the
caller indefinitely. The thread is left to finish (Python provides no
safe primitive to cancel a regex execution mid-flight), so the
upper-bound on a single publish call is ``REDACTION_REGEX_BUDGET_MS *
len(stress_inputs)`` of effective wall-clock latency; for typical
corpora (~10 stress inputs) this is well under a second.

Background threads are marked ``daemon=True`` so a runaway regex
cannot block interpreter shutdown. (The pre-fix comment claimed
``daemon=False`` "silences GC" -- that is incorrect: Python's threading
API does not garbage-collect ``Thread`` objects, and non-daemon
threads merely keep the process alive at interpreter exit.) Because
``re`` provides no safe primitive to cancel a regex execution
mid-flight, the only defense against an attacker-controlled pattern
is to (a) bound the total number of stuck threads and (b) refuse new
budget evaluations once the bound is exceeded.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import re
import threading
import time
from collections.abc import Iterable
from typing import Any, Final

from .errors import RelaySdkError

# 50 ms per-input wall-clock budget (spec AI line 5665). Strict greater-
# than triggers rejection (a matcher that completes in exactly 50 ms is
# accepted; anything strictly over the budget rejects).
REDACTION_REGEX_BUDGET_MS: Final[int] = 50

_ERROR_CODE: Final[str] = "RELAY-REDACT-014"
_HTTP_STATUS: Final[int] = 422

# Maximum number of in-flight runaway regex probe threads the module
# is willing to leak before refusing further work. Past this bound,
# :func:`evaluate_matcher_budget` raises :class:`RelayBudgetExceededError`
# rather than spawn additional threads. The cap is deliberately small:
# a healthy publish flow has zero stuck threads; tens of stuck threads
# is already evidence of an adversarial or pathological matcher
# corpus.
_STUCK_REGEX_THREAD_CAP: Final[int] = 32

# Process-wide counter of regex probe threads that did NOT complete
# within their budget. Decremented when the thread eventually finishes.
# Guarded by ``_STUCK_REGEX_LOCK`` so increment/decrement are atomic
# under the GIL-plus-monitor discipline.
_STUCK_REGEX_LOCK: threading.Lock = threading.Lock()
_STUCK_REGEX_THREADS: int = 0


class RelayBudgetExceededError(RelaySdkError):
    """Raised when the regex-probe thread pool is saturated.

    Reaching this state means more than :data:`_STUCK_REGEX_THREAD_CAP`
    matcher evaluations have left a regex thread alive past its
    budget. The publish flow MUST refuse new matcher evaluations
    until the stuck threads drain (Python provides no safe regex-
    cancel primitive, so they are left to finish naturally).
    """

    code: Final[str] = "RELAY-REDACT-015"
    error_class: Final[str] = "RELAY-REDACT-015"
    http_status: Final[int] = 429


def _evaluate_one(
    compiled: re.Pattern[str],
    text: str,
    budget_s: float,
) -> tuple[bool, float]:
    """Run ``compiled`` against ``text``; return (within_budget,
    measured_seconds).

    Measures wall-clock latency. If the regex thread does not complete
    within ``budget_s``, returns ``(False, measured_so_far)`` immediately
    so the caller can attribute the rejection; the runaway thread is
    left to finish on its own (Python has no safe regex-cancel
    primitive). Subsequent stress inputs are still measured one by one,
    each with its own deadline.
    """
    done = threading.Event()
    # ``state`` lets the probe thread observe whether the caller
    # decided the budget elapsed. The probe thread decrements the
    # process-wide stuck counter on completion iff the caller had
    # already incremented it.
    state = {"overran": False}
    started = time.monotonic()

    def _run() -> None:
        global _STUCK_REGEX_THREADS
        try:
            compiled.search(text)
        finally:
            done.set()
            if state["overran"]:
                with _STUCK_REGEX_LOCK:
                    _STUCK_REGEX_THREADS = max(0, _STUCK_REGEX_THREADS - 1)

    # Daemon=True so a runaway regex thread cannot block interpreter
    # shutdown. Pre-fix code used daemon=False with a comment about
    # "silencing GC"; that was incorrect (Python's threading API does
    # not GC Thread objects, and non-daemon threads keep the process
    # alive at exit).
    t = threading.Thread(target=_run, name="relay-redos-probe", daemon=True)
    t.start()
    completed = done.wait(timeout=budget_s)
    elapsed = time.monotonic() - started
    if not completed:
        # Probe thread did not finish within the budget. Mark the
        # state and bump the process-wide stuck counter so the
        # admission gate can refuse further work once the leak
        # budget is saturated. The probe's ``finally`` block will
        # decrement when (eventually) the regex returns.
        state["overran"] = True
        with _STUCK_REGEX_LOCK:
            _STUCK_REGEX_THREADS += 1
        # Race: if the regex completed between ``done.wait`` timing
        # out and our flip of ``state['overran']``, ``_run`` already
        # ran without decrementing. Detect that here and balance.
        if done.is_set():
            with _STUCK_REGEX_LOCK:
                _STUCK_REGEX_THREADS = max(0, _STUCK_REGEX_THREADS - 1)
        return False, elapsed
    return elapsed * 1000.0 <= REDACTION_REGEX_BUDGET_MS, elapsed


def evaluate_matcher_budget(
    *,
    matcher_id: str,
    pattern: str,
    stress_inputs: Iterable[str],
) -> dict[str, Any] | None:
    """Return ``None`` if ``pattern`` matches every input under the
    50 ms budget.

    Return a structured rejection envelope dict otherwise. The envelope
    keys are stable wire-format names:

    * ``code`` -- ``"RELAY-REDACT-014"``.
    * ``http_status`` -- ``422``.
    * ``matcher_id`` -- echoes the caller-supplied id.
    * ``measured_ms`` -- the measured wall-clock latency (>= 50 ms when
      the regex thread did not complete within the budget).
    * ``offending_input_index`` -- the 0-based index of the first stress
      input that exceeded the budget.

    Raises :class:`RelayBudgetExceededError` when the process-wide
    runaway-thread counter has saturated the stuck-thread cap. The
    publish flow MUST treat this as a hard fail: we cannot safely
    keep launching probe threads if previous probes have not
    terminated.
    """
    with _STUCK_REGEX_LOCK:
        stuck_now = _STUCK_REGEX_THREADS
    if stuck_now >= _STUCK_REGEX_THREAD_CAP:
        raise RelayBudgetExceededError(
            (
                f"refusing matcher evaluation: "
                f"{stuck_now} runaway regex probe threads are still "
                f"alive (cap={_STUCK_REGEX_THREAD_CAP}). Wait for them "
                "to drain or restart the process."
            ),
            details={
                "matcher_id": matcher_id,
                "stuck_threads": stuck_now,
                "cap": _STUCK_REGEX_THREAD_CAP,
            },
        )
    try:
        compiled = re.compile(pattern)
    except re.error as exc:
        # Invalid pattern is also a publish-time rejection, but
        # surfaces a different envelope shape; callers should validate
        # compilation separately. We surface the budget envelope with
        # measured_ms=0 so the caller still gets a structured result.
        return {
            "code": _ERROR_CODE,
            "http_status": _HTTP_STATUS,
            "matcher_id": matcher_id,
            "measured_ms": 0.0,
            "offending_input_index": -1,
            "compile_error": str(exc),
        }

    budget_s = REDACTION_REGEX_BUDGET_MS / 1000.0
    for idx, text in enumerate(stress_inputs):
        within_budget, elapsed_s = _evaluate_one(compiled, text, budget_s)
        if not within_budget:
            measured_ms = elapsed_s * 1000.0
            # Floor the reported measurement to the budget so an over-
            # budget matcher always reports >= REDACTION_REGEX_BUDGET_MS,
            # even when the thread was cancelled exactly at the deadline.
            if measured_ms < REDACTION_REGEX_BUDGET_MS:
                measured_ms = float(REDACTION_REGEX_BUDGET_MS)
            return {
                "code": _ERROR_CODE,
                "http_status": _HTTP_STATUS,
                "matcher_id": matcher_id,
                "measured_ms": measured_ms,
                "offending_input_index": idx,
            }
    return None


__all__ = [
    "REDACTION_REGEX_BUDGET_MS",
    "RelayBudgetExceededError",
    "evaluate_matcher_budget",
]
