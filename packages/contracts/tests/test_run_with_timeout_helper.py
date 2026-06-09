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
    """At ``MAX_ORPHAN_THREADS`` live orphans, the helper refuses to spawn.

    Determinism (the load-bearing part): every spawned worker must stay LIVE
    until the cap assertion fires. A wall-clock ``time.sleep(0.25)`` is NOT a
    safe block here -- on a slow / loaded box the ``MAX_ORPHAN_THREADS`` (64)
    iterations can take longer than 250 ms, so the earliest sleepers finish and
    get PRUNED (the helper prunes dead orphans before the cap check), the live
    count never reaches the cap, and the resource-exhausted error never fires
    (flaky). Instead we block each worker on a ``threading.Event`` that is
    released only in the ``finally`` cleanup, so all spawned workers are
    guaranteed live the entire time -- the cap is reached deterministically.
    """

    evaluator = RelayCelEvaluator()

    # Released ONLY in the finally cleanup, so every worker stays a live orphan
    # until the cap assertion has fired (no wall-clock dependence).
    release = threading.Event()

    def _slow() -> int:
        # Block until cleanup releases us. The 1 ms budget elapses long before
        # this returns, so each call leaves a guaranteed-live orphan.
        release.wait(timeout=30.0)
        return 1

    raised: BaseException | None = None
    try:
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
    finally:
        # Release every blocked worker so it terminates promptly; the autouse
        # tracker-clear fixture drops the references for the next test.
        release.set()

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
    new thread).

    We verify the invariant by asserting that while the helper holds the
    lock, no second thread can observe the tracker in the
    checked-but-not-yet-spawned state: a competing acquirer is blocked
    until the spawn has registered the thread, so the post-state it sees
    already includes the new orphan.

    Synchronization (the load-bearing part): the competitor must only
    ATTEMPT the lock AFTER the main thread is *inside* the check+spawn
    critical section. If the competitor were released before the main
    thread acquires the lock (the prior bug), it could acquire the lock
    first and observe the empty pre-spawn tracker (count 0) -- defeating
    the check (the assertion would then be vacuously satisfiable by a
    NON-atomic implementation, since the competitor never races the
    actual critical section). We achieve the ordering by instrumenting the
    tracker lock: a wrapper SIGNALS ``inside_critical_section`` on the main
    thread's acquire and only then is the competitor allowed to attempt the
    (still-held) lock, so it necessarily blocks until the main thread
    releases AFTER registering the orphan.
    """

    evaluator = RelayCelEvaluator()

    observed_counts: list[int] = []
    inside_critical_section = threading.Event()
    # ROBOREV round-2 finding J: the SECOND synchronization point (the handshake).
    # The competitor sets this the INSTANT before it attempts the (held) tracker
    # lock; the main thread BLOCKS inside its still-held critical section until it
    # observes this, PROVING the competitor is genuinely at the lock door (about
    # to block on the held lock) BEFORE the main thread registers the orphan and
    # releases. Without this handshake a non-atomic impl that releases between the
    # cap check and the spawn could pass if the scheduler runs the orphan
    # registration before the competitor ever reached the lock.
    competitor_reached_lock = threading.Event()
    handshake_observed = threading.Event()
    # Set by the competitor the instant it has ACQUIRED the tracker lock, read the
    # tracker count, and RELEASED. The main thread's post-release handoff blocks
    # on this so the lock handoff to the competitor is deterministic (the main
    # thread does not re-acquire until the competitor's observation is recorded).
    competitor_observed = threading.Event()
    # Ensures the deterministic handoff runs on the FIRST main-thread release only
    # (the competitor observes exactly once); later releases stay transparent.
    main_release_handoff_done = threading.Event()

    def _slow() -> int:
        time.sleep(0.25)
        return 1

    real_lock = RelayCelEvaluator._orphan_tracker_lock  # noqa: SLF001
    main_thread = threading.current_thread()

    class _SignallingLock:
        """Proxy around the real tracker lock.

        On the MAIN thread's acquire (the helper's check+spawn critical
        section) it (1) sets ``inside_critical_section`` so the competitor is
        released to attempt the lock only AFTER the main thread already holds
        it, and (2) BLOCKS until ``competitor_reached_lock`` -- the finding-J
        handshake -- so the main thread does not proceed to register the orphan
        and release until the competitor is provably at the (held) lock. The
        competitor acquires/releases the underlying lock transparently.
        Re-entrancy is not required: the helper acquires the tracker lock
        exactly once per call.
        """

        def _main_critical_entry(self) -> None:
            # The main thread now HOLDS the real lock. Release the competitor to
            # attempt the lock, then WAIT for the handshake proving it reached
            # the acquisition attempt (it signals just before blocking on the
            # held lock). Record whether the handshake actually occurred so the
            # test fails loudly if the ordering did not hold (no vacuous pass).
            inside_critical_section.set()
            if competitor_reached_lock.wait(timeout=2.0):
                handshake_observed.set()

        def __enter__(self) -> _SignallingLock:
            real_lock.acquire()
            if threading.current_thread() is main_thread:
                self._main_critical_entry()
            return self

        def _main_release_handoff(self) -> None:
            # After the main thread RELEASES the tracker lock, BLOCK until the
            # competitor -- which the handshake proved is waiting on this lock --
            # has fully ACQUIRED it, recorded its observation, and RELEASED. This
            # makes the lock handoff DETERMINISTIC (no scheduler luck): the main
            # thread never re-acquires the lock until the competitor's observation
            # is on record. Under an ATOMIC check+spawn the competitor only ever
            # gets the lock AFTER the orphan is registered (count >= 1); under a
            # NON-ATOMIC impl that releases the lock BETWEEN the cap check and the
            # spawn, this handoff hands the competitor the lock IN that gap, so it
            # records the empty pre-spawn state (count 0) and the test FAILS. The
            # bounded wait avoids hanging if the competitor never shows (the outer
            # assertions then fail loudly rather than deadlock).
            #
            # Only the FIRST main-thread release performs the handoff (the
            # competitor observes exactly once); later releases (if any) are
            # transparent so they cannot deadlock waiting for a second
            # observation that never comes.
            if main_release_handoff_done.is_set():
                return
            main_release_handoff_done.set()
            competitor_observed.wait(timeout=2.0)

        def __exit__(self, *exc_info: object) -> None:
            is_main = threading.current_thread() is main_thread
            real_lock.release()
            if is_main:
                self._main_release_handoff()

        # Support the helper's `with type(self)._orphan_tracker_lock:` AND
        # any direct acquire/release callers symmetrically. The signature
        # mirrors threading.Lock.acquire exactly (blocking + timeout) so the
        # proxy is a transparent substitute.
        def acquire(self, blocking: bool = True, timeout: float = -1) -> bool:
            acquired = real_lock.acquire(blocking, timeout)
            if acquired and threading.current_thread() is main_thread:
                self._main_critical_entry()
            return acquired

        def release(self) -> None:
            is_main = threading.current_thread() is main_thread
            real_lock.release()
            if is_main:
                self._main_release_handoff()

    def _competitor() -> None:
        # Wait until the MAIN thread is inside _run_with_timeout's critical
        # section (it has acquired the tracker lock for check+spawn).
        inside_critical_section.wait(timeout=2.0)
        # Finding-J handshake: signal that we have REACHED the lock-acquisition
        # attempt the INSTANT before entering the `with` (which blocks on the
        # held lock). The main thread blocks until it sees this, so the orphan
        # registration provably happens while we are genuinely racing the
        # critical section -- not before we ever got here.
        competitor_reached_lock.set()
        with RelayCelEvaluator._orphan_tracker_lock:  # noqa: SLF001
            observed_counts.append(
                len(RelayCelEvaluator._orphaned_thread_tracker)  # noqa: SLF001
            )
        # The observation is recorded and the lock released: release the main
        # thread's deterministic handoff (it blocked after its own release until
        # this point, so it does not re-acquire before we observed).
        competitor_observed.set()

    signalling_lock = _SignallingLock()
    RelayCelEvaluator._orphan_tracker_lock = signalling_lock  # type: ignore[assignment]  # noqa: SLF001
    try:
        t = threading.Thread(target=_competitor, daemon=True)
        t.start()

        with pytest.raises(RelayCelTimeoutError):
            evaluator._run_with_timeout(_slow, 0.001)  # noqa: SLF001

        t.join(timeout=2.0)
    finally:
        RelayCelEvaluator._orphan_tracker_lock = real_lock  # type: ignore[assignment]  # noqa: SLF001

    # The handshake MUST have occurred: the main thread blocked inside its held
    # critical section until the competitor reached the lock attempt. If it did
    # not, the ordering the test relies on never held and the result below would
    # be meaningless -- fail loudly rather than pass vacuously.
    assert handshake_observed.is_set(), (
        "finding-J handshake did not occur: the competitor never reached the "
        "lock-acquisition attempt while the main thread held the critical "
        "section, so the atomicity observation below would be meaningless."
    )
    # The competitor, attempting the lock only AFTER the main thread entered
    # the critical section (and PROVABLY at the lock door per the handshake),
    # necessarily blocks until the atomic check+spawn completes and the orphan
    # is registered: it observes count >= 1. A NON-atomic implementation that
    # released the lock between the cap check and the spawn would expose the
    # empty pre-spawn state (count 0) to the competitor that is now genuinely
    # racing the critical section.
    assert observed_counts, "competitor thread did not record an observation"
    assert all(c >= 1 for c in observed_counts), (
        "check+spawn must be atomic: a concurrent reader must never see the "
        f"tracker in the pre-spawn empty state; observed {observed_counts}"
    )
