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

Background threads are explicitly NOT marked daemonic, so the Python
runtime does not raise during garbage collection. This module is
imported by the SDK at policy-publish time only; it is not part of the
hot-path request/response cycle.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import re
import threading
import time
from collections.abc import Iterable
from typing import Any, Final

# 50 ms per-input wall-clock budget (spec AI line 5665). Strict greater-
# than triggers rejection (a matcher that completes in exactly 50 ms is
# accepted; anything strictly over the budget rejects).
REDACTION_REGEX_BUDGET_MS: Final[int] = 50

_ERROR_CODE: Final[str] = "RELAY-REDACT-014"
_HTTP_STATUS: Final[int] = 422


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
    started = time.monotonic()

    def _run() -> None:
        try:
            compiled.search(text)
        finally:
            done.set()

    t = threading.Thread(target=_run, name="relay-redos-probe", daemon=False)
    t.start()
    # Wait up to budget_s + a small slack so we measure the actual
    # latency rather than wall-clock at exactly budget_s.
    completed = done.wait(timeout=budget_s)
    elapsed = time.monotonic() - started
    if not completed:
        # Thread is still running. Return immediately; the thread will
        # finish on its own. Caller treats this as over-budget.
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
    """
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
    "evaluate_matcher_budget",
]
