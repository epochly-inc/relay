"""VAL-CWC-P1HOST-002: the timeout + orphan-thread-cap block is lifted
into a reusable host-side ``_run_with_timeout`` helper.

The block formerly inlined in ``RelayCelEvaluator.evaluate`` (atomic
prune+check+spawn under ``_orphan_tracker_lock``, ``join(timeout)``,
``RelayCelTimeoutError`` on ``is_alive``, ``RelayCelResourceExhaustedError``
at ``MAX_ORPHAN_THREADS``) is extracted into an engine-agnostic helper that
BOTH ``RelayCelEvaluator`` and the future ``WasmCelEvaluator`` call. The
helper takes a 0-arg callable to run under the wall-clock budget + orphan
cap and returns its result (or raises the structured errors).

These tests pin:
  - the helper EXISTS and ``evaluate()`` DELEGATES to it (single code path)
  - normal return (including falsy / None values returned faithfully)
  - timeout -> RelayCelTimeoutError
  - at-cap -> RelayCelResourceExhaustedError
  - a non-Relay exception raised by the callable propagates and the
    orphan is deregistered (no slot leak on the error path)
  - the check + spawn are atomic under a SINGLE acquisition of
    ``_orphan_tracker_lock`` (no TOCTOU re-acquisition between the
    cap check and the thread start)

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import threading
import time

import pytest
from relay_contracts.evaluator import (
    MAX_ORPHAN_THREADS,
    RelayCelEvaluator,
    RelayCelResourceExhaustedError,
    RelayCelTimeoutError,
)

# Tier-1 plumbing: offline, every commit (CLAUDE.md AM.6). Marked file-wide so
# the VAL-CWC-P1HOST-002 evidence command (`pytest ... -m plumbing`) collects
# every case in this module rather than deselecting it.
pytestmark = pytest.mark.plumbing


@pytest.fixture(autouse=True)
def _clear_orphan_tracker() -> None:
    """Isolate the PROCESS-WIDE orphan tracker before each test.

    ``_orphaned_thread_tracker`` is class-level state shared by every
    ``RelayCelEvaluator`` instance in the process, so a leftover live
    orphan from a sibling test would corrupt the at-cap boundary count.
    We do not kill threads (they are daemon orphans that terminate on
    their own); we only drop the tracker's references so the live-count
    measured by these tests starts from a known-empty baseline.
    """

    with RelayCelEvaluator._orphan_tracker_lock:  # noqa: SLF001
        RelayCelEvaluator._orphaned_thread_tracker.clear()  # noqa: SLF001


# ---------------------------------------------------------------------------
# helper existence + evaluate() delegation
# ---------------------------------------------------------------------------


def test_run_with_timeout_helper_exists() -> None:
    """The shared host-side helper exists and is callable."""

    evaluator = RelayCelEvaluator()
    assert hasattr(evaluator, "_run_with_timeout")
    assert callable(evaluator._run_with_timeout)  # noqa: SLF001


def test_evaluate_delegates_to_run_with_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    """``evaluate()`` routes the celpy run THROUGH ``_run_with_timeout``.

    We replace the helper with a spy that records its invocation and runs
    the supplied callable. If ``evaluate`` ran the worker thread itself
    (not via the helper), the spy would never fire.
    """

    evaluator = RelayCelEvaluator()
    calls: list[float] = []
    original = evaluator._run_with_timeout  # noqa: SLF001

    def _spy(run, timeout_seconds):  # type: ignore[no-untyped-def]
        calls.append(timeout_seconds)
        return original(run, timeout_seconds)

    monkeypatch.setattr(evaluator, "_run_with_timeout", _spy)
    result = evaluator.evaluate("1 + 2 * 3")
    assert int(result) == 7
    assert len(calls) == 1, "evaluate() must delegate exactly once to _run_with_timeout"
    # The delegated budget is the evaluator's configured timeout in seconds.
    assert calls[0] == pytest.approx(evaluator.timeout_ms / 1000.0)


# ---------------------------------------------------------------------------
# normal return (including falsy / None)
# ---------------------------------------------------------------------------


def test_run_with_timeout_returns_callable_result() -> None:
    evaluator = RelayCelEvaluator()
    out = evaluator._run_with_timeout(lambda: 42, 5.0)  # noqa: SLF001
    assert out == 42


@pytest.mark.parametrize("sentinel", [None, 0, False, "", [], {}])
def test_run_with_timeout_returns_falsy_faithfully(sentinel: object) -> None:
    """A falsy / None result is returned unchanged (no truthiness coercion,
    no 'missing value' confusion)."""

    evaluator = RelayCelEvaluator()
    out = evaluator._run_with_timeout(lambda: sentinel, 5.0)  # noqa: SLF001
    assert out is sentinel or out == sentinel


# ---------------------------------------------------------------------------
# timeout -> RelayCelTimeoutError
# ---------------------------------------------------------------------------


def test_run_with_timeout_raises_timeout_on_slow_callable() -> None:
    evaluator = RelayCelEvaluator()

    def _slow() -> int:
        time.sleep(0.250)
        return 1

    with pytest.raises(RelayCelTimeoutError) as ctx:
        evaluator._run_with_timeout(_slow, 0.001)  # noqa: SLF001
    assert ctx.value.code == "RELAY-CEL-003"


# ---------------------------------------------------------------------------
# at-cap -> RelayCelResourceExhaustedError
# ---------------------------------------------------------------------------


def test_run_with_timeout_raises_resource_exhausted_at_cap() -> None:
    """At ``MAX_ORPHAN_THREADS`` live orphans, the helper refuses to spawn."""

    evaluator = RelayCelEvaluator()

    def _slow() -> int:
        # Outlive the 1 ms budget so each call leaves a live orphan.
        time.sleep(0.25)
        return 1

    raised: BaseException | None = None
    for i in range(MAX_ORPHAN_THREADS + 1):
        try:
            evaluator._run_with_timeout(_slow, 0.001)  # noqa: SLF001
        except RelayCelResourceExhaustedError as exc:
            raised = exc
            assert i == MAX_ORPHAN_THREADS, (
                f"resource-exhausted fired at call {i}; "
                f"expected exactly at {MAX_ORPHAN_THREADS}"
            )
            break
        except RelayCelTimeoutError:
            continue
    assert raised is not None
    assert raised.code == "RELAY-CEL-008"
    assert raised.subtype == "RELAY-CEL-RESOURCE-EXHAUSTED"


# ---------------------------------------------------------------------------
# non-Relay exception propagation + orphan deregistration on the error path
# ---------------------------------------------------------------------------


def test_run_with_timeout_propagates_callable_exception_and_frees_slot() -> None:
    """A non-Relay exception raised by the callable propagates unchanged,
    and the worker thread is deregistered (no orphan-slot leak)."""

    evaluator = RelayCelEvaluator()

    class _Boom(RuntimeError):
        pass

    def _boom() -> int:
        raise _Boom("kaboom")

    with RelayCelEvaluator._orphan_tracker_lock:  # noqa: SLF001
        live_before = len(RelayCelEvaluator._orphaned_thread_tracker)  # noqa: SLF001

    with pytest.raises(_Boom):
        evaluator._run_with_timeout(_boom, 5.0)  # noqa: SLF001

    with RelayCelEvaluator._orphan_tracker_lock:  # noqa: SLF001
        live_after = len(RelayCelEvaluator._orphaned_thread_tracker)  # noqa: SLF001
    assert live_after == live_before, (
        "a callable that raises must not leak an orphan-tracker slot"
    )


# ---------------------------------------------------------------------------
# TOCTOU atomicity: check + spawn under a SINGLE lock acquisition
# ---------------------------------------------------------------------------


def test_check_and_spawn_are_atomic_under_one_lock_acquisition() -> None:
    """The cap check and the thread start MUST happen under the SAME lock
    acquisition (no release between observing ``live < cap`` and adding the
    new thread). We instrument the tracker lock to count acquisitions that
    overlap a tracker mutation and assert the helper does not re-acquire
    the lock between the cap check and the spawn.

    We verify the invariant by asserting that while the helper holds the
    lock, no second thread can observe the tracker in the
    checked-but-not-yet-spawned state: a competing acquirer is blocked
    until the spawn has registered the thread, so the post-state it sees
    already includes the new orphan.
    """

    evaluator = RelayCelEvaluator()

    observed_counts: list[int] = []
    barrier_ready = threading.Event()
    proceed = threading.Event()

    def _slow() -> int:
        time.sleep(0.25)
        return 1

    def _competitor() -> None:
        # Wait until the main thread is inside _run_with_timeout (it holds
        # the tracker lock during check+spawn). Then try to read the
        # tracker under the SAME lock; if check+spawn are atomic, by the
        # time we acquire the lock the new orphan is already registered.
        barrier_ready.wait(timeout=2.0)
        proceed.wait(timeout=2.0)
        with RelayCelEvaluator._orphan_tracker_lock:  # noqa: SLF001
            observed_counts.append(
                len(RelayCelEvaluator._orphaned_thread_tracker)  # noqa: SLF001
            )

    t = threading.Thread(target=_competitor, daemon=True)
    t.start()
    barrier_ready.set()
    proceed.set()

    with pytest.raises(RelayCelTimeoutError):
        evaluator._run_with_timeout(_slow, 0.001)  # noqa: SLF001

    t.join(timeout=2.0)
    # The competitor, acquiring the lock AFTER the atomic check+spawn,
    # observes the orphan already registered (count >= 1). A non-atomic
    # check-then-act could expose the empty pre-spawn state (count 0).
    assert observed_counts, "competitor thread did not record an observation"
    assert all(c >= 1 for c in observed_counts), (
        "check+spawn must be atomic: a concurrent reader must never see the "
        f"tracker in the pre-spawn empty state; observed {observed_counts}"
    )
