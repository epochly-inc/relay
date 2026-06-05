"""Round-3 P1 fix #4: CEL evaluator MUST bound orphaned threads.

Pre-fix, ``RelayCelEvaluator.evaluate`` spawned a fresh ``threading.Thread``
per call with ``join(timeout=...)`` and raised ``RelayCelTimeoutError`` if
the thread did not return in time. The thread was left daemon-running --
cel-python evaluation is not interruptible from another thread, so the
orphan persisted until interpreter exit. Under adversarial inputs (loop
of pathological evaluations) the orphan count grows without bound, a
trivial DoS vector.

The fix tracks live orphans on a class-level set; each evaluate call
prunes terminated threads and refuses to spawn a new orphan when the
cap is reached, raising a structured ``RelayCelResourceExhaustedError``
with code ``RELAY-CEL-008`` and subtype ``RELAY-CEL-RESOURCE-EXHAUSTED``.
After live orphans terminate (cel-python finishes computing), the
tracker prunes them and the evaluator resumes accepting calls.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import contextlib
import time

import pytest
from relay_contracts.errors import RelayCelError
from relay_contracts.evaluator import (
    MAX_ORPHAN_THREADS,
    RelayCelEvaluator,
    RelayCelResourceExhaustedError,
)
from relay_contracts.udf import register_udf


@pytest.fixture(autouse=True)
def _clear_orphan_tracker() -> None:
    """Isolate the PROCESS-WIDE orphan tracker before each test.

    ``_orphaned_thread_tracker`` is class-level state shared by every
    ``RelayCelEvaluator`` instance in the process. A sibling suite's
    timeout test (e.g. ``test_w6_3_timeout`` /
    ``test_w6_1_evaluator``, whose slow-pure-UDF timeout cases leave a
    live daemon orphan) would otherwise leave a live orphan in the
    tracker, so this file's cap-boundary loop would observe ``live ==
    1`` at the start and fire ``RelayCelResourceExhaustedError`` one
    call EARLY (at 63 instead of 64). We do not kill threads (they are
    daemon orphans that terminate on their own); we only drop the
    tracker's references so the live-count these tests measure starts
    from a known-empty baseline -- exactly what the cap-at-64 assertion
    and the docstring already assume.
    """

    with RelayCelEvaluator._orphan_tracker_lock:  # noqa: SLF001
        RelayCelEvaluator._orphaned_thread_tracker.clear()  # noqa: SLF001


@pytest.mark.plumbing
def test_evaluator_orphan_thread_cap_raises_resource_exhausted() -> None:
    """Spamming pathological 1 ms timeouts MUST hit the orphan cap.

    A pure UDF that sleeps 250 ms is registered with a 1 ms wall-clock
    budget; every evaluation will timeout (the thread continues to run
    in the background). After ``MAX_ORPHAN_THREADS`` evaluations the
    next call MUST raise ``RelayCelResourceExhaustedError`` instead of
    spawning yet another orphan.
    """
    def slow_pure(x: int) -> int:
        time.sleep(0.25)
        return x

    udf = register_udf(
        name="orphan_test_slow_pure", fn=slow_pure, pure=True, arity=1
    )
    # 1 ms timeout guarantees every call orphan-leaks the worker thread.
    evaluator = RelayCelEvaluator(timeout_ms=1, udfs=[udf])

    # First MAX_ORPHAN_THREADS calls timeout but DO NOT exceed the cap.
    raised: BaseException | None = None
    for i in range(MAX_ORPHAN_THREADS + 1):
        try:
            evaluator.evaluate("orphan_test_slow_pure(1)")
        except RelayCelResourceExhaustedError as exc:
            raised = exc
            assert i == MAX_ORPHAN_THREADS, (
                f"resource-exhausted fired too early at call {i}; "
                f"expected exactly at {MAX_ORPHAN_THREADS}"
            )
            break
        except RelayCelError:
            # Timeout is expected for the first MAX_ORPHAN_THREADS calls.
            continue
    assert raised is not None, (
        f"after {MAX_ORPHAN_THREADS + 1} pathological evaluations the "
        f"evaluator must raise RelayCelResourceExhaustedError"
    )
    # The structured error carries a stable code + subtype the caller can
    # branch on.
    assert raised.code == "RELAY-CEL-008"
    assert raised.subtype == "RELAY-CEL-RESOURCE-EXHAUSTED"


@pytest.mark.plumbing
def test_evaluator_recovers_after_orphan_threads_terminate() -> None:
    """Once orphan threads finish their sleep, the tracker prunes them
    and the evaluator resumes accepting calls.

    Spawn a SHORT-lived orphan batch (each sleeps just enough to
    outlive the 1 ms timeout but terminate before the next
    iteration), then wait for them all to finish, then assert the
    evaluator accepts a fresh call without raising
    RelayCelResourceExhaustedError.
    """
    def short_pure(x: int) -> int:
        # 50 ms is long enough to exceed the 1 ms budget once but short
        # enough that all spawned orphans finish within the 2 s wait
        # window below.
        time.sleep(0.05)
        return x

    udf = register_udf(
        name="orphan_recovery_short_pure", fn=short_pure, pure=True, arity=1
    )
    evaluator = RelayCelEvaluator(timeout_ms=1, udfs=[udf])

    # Hit the cap. We expect every iteration to timeout (RelayCelError);
    # the orphan tracker accumulates the dead-soon worker threads.
    for _ in range(MAX_ORPHAN_THREADS):
        with contextlib.suppress(RelayCelError):
            evaluator.evaluate("orphan_recovery_short_pure(1)")

    # Wait long enough for every spawned 50 ms orphan to terminate.
    time.sleep(2.0)

    # Next evaluation: cap was reset by pruning -> the call proceeds
    # and the orphan is spawned freshly; we still expect TIMEOUT (not
    # ResourceExhausted) because the budget is 1 ms.
    with pytest.raises(RelayCelError) as excinfo:
        evaluator.evaluate("orphan_recovery_short_pure(1)")
    assert not isinstance(excinfo.value, RelayCelResourceExhaustedError), (
        "after orphan termination + prune, the evaluator should accept "
        "fresh calls and raise the timeout error (not resource-exhausted)"
    )
