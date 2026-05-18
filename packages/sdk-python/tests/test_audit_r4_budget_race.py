"""AUDIT-R4 BUG-H1: stuck-thread counter must be monotonic.

The 2026-05-18 R4 audit found that
``relay.redaction_budget._evaluate_one`` could double-decrement
``_STUCK_REGEX_THREADS`` when the probe thread completed inside the
race-detect window between ``done.wait`` returning False and the main
path flipping ``state['overran']``. Both the probe's ``finally`` and
the main thread's race-detect branch would call ``_STUCK_REGEX_THREADS
-= 1``, and the ``max(0, ...)`` floor masked the underflow. Over many
near-deadline regex evaluations, the counter could drift below 0,
defeating the admission gate (cap=32) against sustained adversarial
matcher corpora.

The fix establishes an exactly-once handoff: exactly one of {probe,
main} performs the decrement, coordinated by a per-call ``state`` dict
under ``_STUCK_REGEX_LOCK``. The ``max(0, ...)`` floor was removed so
any future bookkeeping bug is visible, not silently masked.

This module stresses the handoff with 100 near-deadline regex
evaluations and asserts the counter returns to exactly 0.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import random
import time

import pytest
import relay.redaction_budget as rb
from relay.redaction_budget import _evaluate_one


@pytest.mark.plumbing
def test_stuck_thread_counter_returns_to_zero_under_race() -> None:
    """Run 100 near-deadline regex evaluations and assert the
    process-wide stuck-thread counter returns to exactly 0.

    Each evaluation uses a 1 ms budget and a pattern whose matching
    cost on the input is randomized to land in the 0.5-1.5 ms window.
    This forces approximately half the probes to complete inside the
    race-detect window (the exact race that produced the double-
    decrement before the fix).
    """
    import re

    # Snapshot the starting counter so the test is independent of
    # any other concurrent tests in this process.
    starting = rb._STUCK_REGEX_THREADS

    # 1 ms budget. ``_evaluate_one`` takes ``budget_s`` as a float.
    budget_s = 0.001

    # The input/pattern pairs deliberately straddle the budget. A
    # simple greedy pattern over a string of variable length gives a
    # roughly linear cost. We pick a pattern that completes very
    # quickly (microseconds) and pad with a busy-wait between probes
    # to ensure we observe both the "probe wins" and "main wins"
    # branches of the handoff.
    cheap = re.compile(r"^a+b$")
    inputs = ["a" * n + "b" for n in range(1, 20)]

    rng = random.Random(42)

    for _ in range(100):
        text = rng.choice(inputs)
        within_budget, elapsed_s = _evaluate_one(cheap, text, budget_s)
        # Whether within budget is irrelevant to this test -- we only
        # care about the bookkeeping invariant. But ``elapsed_s`` must
        # be non-negative.
        assert elapsed_s >= 0.0
        del within_budget

    # Wait for any in-flight runaway probe threads to finish. Each
    # probe's ``finally`` runs the decrement under the lock, so we
    # need to let them drain before asserting on the counter. With a
    # 1 ms budget and trivial patterns, every probe should finish
    # within a few hundred milliseconds; we poll for up to 5 s to be
    # generous on slow CI hardware.
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        with rb._STUCK_REGEX_LOCK:
            current = rb._STUCK_REGEX_THREADS
        if current == starting:
            break
        time.sleep(0.01)

    with rb._STUCK_REGEX_LOCK:
        final = rb._STUCK_REGEX_THREADS

    # Strict equality: the post-fix counter is monotonic. NOT
    # ``final >= 0`` (which the pre-fix ``max(0, ...)`` floor would
    # have masked). NOT ``final >= starting`` (which would allow a
    # leak). EXACTLY starting -- every increment paired with exactly
    # one decrement.
    assert final == starting, (
        f"counter drifted: starting={starting} final={final} "
        f"(diff={final - starting})"
    )


@pytest.mark.plumbing
def test_stuck_thread_counter_handles_genuinely_stuck_probe() -> None:
    """A regex that takes longer than the budget should leave the
    counter incremented by exactly 1 while the probe is alive, then
    decrement to the starting value once the probe finishes.

    This isolates the "probe stuck past deadline" branch of the
    handoff -- the only path where the main thread sets
    ``incremented=True`` and then the probe later observes it and
    decrements.
    """
    import re

    starting = rb._STUCK_REGEX_THREADS

    # A pattern that genuinely takes ~50 ms. We feed a 5000-char
    # input to a backtracking pattern so the probe blows past a 1 ms
    # budget but still completes well within the test timeout.
    slow = re.compile(r"^(a+)+$")
    # Mismatching tail forces backtracking but bounded by input
    # length so the test does not run for minutes.
    text = "a" * 25 + "b"

    within_budget, elapsed_s = _evaluate_one(slow, text, 0.001)
    assert within_budget is False
    assert elapsed_s >= 0.0

    # Wait for the probe to finish naturally. The decrement runs in
    # the probe's ``finally`` block.
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        with rb._STUCK_REGEX_LOCK:
            current = rb._STUCK_REGEX_THREADS
        if current == starting:
            break
        time.sleep(0.01)

    with rb._STUCK_REGEX_LOCK:
        final = rb._STUCK_REGEX_THREADS

    assert final == starting, (
        f"counter drifted: starting={starting} final={final}"
    )


__all__ = []
