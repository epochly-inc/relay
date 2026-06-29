"""Round-3 P1 fix #4: CEL evaluator MUST bound orphaned threads.

Pre-fix, the evaluator spawned a fresh ``threading.Thread`` per call with
``join(timeout=...)`` and raised ``RelayCelTimeoutError`` if the thread did
not return in time. The thread was left daemon-running -- the engine's eval
primitive is not interruptible from another thread, so the orphan persisted
until interpreter exit. Under adversarial inputs (loop of pathological
evaluations) the orphan count grows without bound, a trivial DoS vector.

The fix tracks live orphans on a process-wide module-level set
(``relay_contracts.evaluator._orphaned_thread_tracker``); each evaluate call
prunes terminated threads and refuses to spawn a new orphan when the cap is
reached, raising a structured ``RelayCelResourceExhaustedError`` with code
``RELAY-CEL-008`` and subtype ``RELAY-CEL-RESOURCE-EXHAUSTED``. After live
orphans terminate, the tracker prunes them and the evaluator resumes
accepting calls.

M6 WS-I port: the bound is exercised through ``WasmCelEvaluator.evaluate``
(the single evaluator). The wasm engine hosts no caller-registered UDFs, so
the slow engine call is simulated by a stub per-thread handle whose ``eval``
sleeps past the wall-clock budget -- the EVALUATE path (handle construction,
quarantine-on-timeout, orphan accounting) is the genuine code under test.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import contextlib
import time
from typing import Any

import pytest
import relay_contracts.evaluator as evaluator_module
from relay_contracts.errors import (
    RelayCelError,
    RelayCelResourceExhaustedError,
)
from relay_contracts.evaluator import MAX_ORPHAN_THREADS
from relay_contracts.wasm_backed_evaluator import WasmCelEvaluator


@pytest.fixture(autouse=True)
def _clear_orphan_tracker() -> None:
    """Isolate the PROCESS-WIDE orphan tracker before each test.

    ``_orphaned_thread_tracker`` is module-level state shared by every
    evaluator instance in the process. A sibling suite's timeout test
    (whose slow-eval timeout cases leave a live daemon orphan) would
    otherwise leave a live orphan in the tracker, so this file's
    cap-boundary loop would observe ``live == 1`` at the start and fire
    ``RelayCelResourceExhaustedError`` one call EARLY (at 63 instead of
    64). We do not kill threads (they are daemon orphans that terminate on
    their own); we only drop the tracker's references so the live-count
    these tests measure starts from a known-empty baseline -- exactly what
    the cap-at-64 assertion and the docstring already assume.
    """

    with evaluator_module._orphan_tracker_lock:  # noqa: SLF001
        evaluator_module._orphaned_thread_tracker.clear()  # noqa: SLF001


class _SlowHandle:
    """Stub per-thread engine handle whose ``eval`` sleeps past the budget.

    Mirrors the loader handle's ``eval`` signature; the sleep simulates a
    pathological in-engine evaluation that outlives the wall-clock budget,
    orphaning the worker thread exactly like a real slow engine call.
    """

    def __init__(self, delay_seconds: float) -> None:
        self._delay_seconds = delay_seconds

    def eval(
        self,
        expr: str,
        bindings: Any = None,
        container: Any = None,
        relay_profile: bool = False,
    ) -> dict[str, Any]:
        time.sleep(self._delay_seconds)
        return {"ok": True, "value": {"t": "int", "v": "1"}}


def _slow_evaluator(
    monkeypatch: pytest.MonkeyPatch, delay_seconds: float
) -> WasmCelEvaluator:
    """A WasmCelEvaluator whose per-thread handles always eval slowly.

    ``_new_handle`` is stubbed so the post-timeout quarantine (which discards
    the per-thread handle and builds a fresh one) keeps producing slow
    handles -- every evaluation times out and orphan-leaks its worker.
    """
    evaluator = WasmCelEvaluator(timeout_ms=1)
    monkeypatch.setattr(
        evaluator, "_new_handle", lambda: _SlowHandle(delay_seconds)
    )
    return evaluator


@pytest.mark.plumbing
def test_evaluator_orphan_thread_cap_raises_resource_exhausted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Spamming pathological 1 ms timeouts MUST hit the orphan cap.

    Every evaluation times out (the stubbed engine call sleeps 250 ms against
    a 1 ms wall-clock budget; the worker thread continues in the background).
    After ``MAX_ORPHAN_THREADS`` evaluations the next call MUST raise
    ``RelayCelResourceExhaustedError`` instead of spawning yet another orphan.
    """
    evaluator = _slow_evaluator(monkeypatch, 0.25)

    # First MAX_ORPHAN_THREADS calls timeout but DO NOT exceed the cap.
    raised: BaseException | None = None
    for i in range(MAX_ORPHAN_THREADS + 1):
        try:
            evaluator.evaluate("1 + 1")
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
def test_evaluator_recovers_after_orphan_threads_terminate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Once orphan threads finish their sleep, the tracker prunes them
    and the evaluator resumes accepting calls.

    Spawn a SHORT-lived orphan batch (each sleeps just enough to
    outlive the 1 ms timeout but terminate before the next
    iteration), then wait for them all to finish, then assert the
    evaluator accepts a fresh call without raising
    RelayCelResourceExhaustedError.
    """
    evaluator = _slow_evaluator(monkeypatch, 0.05)

    # Hit the cap. We expect every iteration to timeout (RelayCelError);
    # the orphan tracker accumulates the dead-soon worker threads.
    for _ in range(MAX_ORPHAN_THREADS):
        with contextlib.suppress(RelayCelError):
            evaluator.evaluate("1 + 1")

    # Wait long enough for every spawned 50 ms orphan to terminate.
    time.sleep(2.0)

    # Next evaluation: cap was reset by pruning -> the call proceeds
    # and the orphan is spawned freshly; we still expect TIMEOUT (not
    # ResourceExhausted) because the budget is 1 ms.
    with pytest.raises(RelayCelError) as excinfo:
        evaluator.evaluate("1 + 1")
    assert not isinstance(excinfo.value, RelayCelResourceExhaustedError), (
        "after orphan termination + prune, the evaluator should accept "
        "fresh calls and raise the timeout error (not resource-exhausted)"
    )
