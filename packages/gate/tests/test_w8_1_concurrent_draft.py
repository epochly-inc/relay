"""W8.1 plumbing tests: VAL-W8-007 concurrent-draft conflict.

Verifies the DraftLock returns RELAY-GATE-014 when a second worker
submits a draft for the same (gate_id, scope_type, scope_id, round)
key. Also exercises pipeline-level rejection.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime

import pytest
from _w8_1_helpers import (
    GATE_ID_SCRUTINY,
    SCOPE_ID,
    SCOPE_TYPE,
    make_draft,
    make_gate,
    make_pipeline,
)
from relay_gate_engine import (
    DraftLock,
    DraftLockConflictError,
)
from relay_schemas.error_codes import RelayErrorCode


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-007")
def test_two_different_workers_conflict() -> None:
    """Two workers, same (gate, scope, round) -> second receives RELAY-GATE-014."""
    lock = DraftLock()
    lock.acquire(
        gate_id=GATE_ID_SCRUTINY,
        scope_type=SCOPE_TYPE,
        scope_id=SCOPE_ID,
        round=1,
        worker_id="worker-A",
        draft_id="draft-A",
    )
    with pytest.raises(DraftLockConflictError) as ei:
        lock.acquire(
            gate_id=GATE_ID_SCRUTINY,
            scope_type=SCOPE_TYPE,
            scope_id=SCOPE_ID,
            round=1,
            worker_id="worker-B",
            draft_id="draft-B",
        )
    assert ei.value.code == RelayErrorCode.RELAY_GATE_014
    assert ei.value.payload["holding_worker_id"] == "worker-A"
    assert ei.value.payload["rejected_worker_id"] == "worker-B"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-007")
def test_same_worker_same_draft_is_idempotent() -> None:
    """Same (worker_id, draft_id) re-entry is permitted (at-least-once)."""
    lock = DraftLock()
    lock.acquire(
        gate_id=GATE_ID_SCRUTINY,
        scope_type=SCOPE_TYPE,
        scope_id=SCOPE_ID,
        round=1,
        worker_id="worker-A",
        draft_id="draft-A",
    )
    # Second acquire with identical args MUST NOT raise.
    lock.acquire(
        gate_id=GATE_ID_SCRUTINY,
        scope_type=SCOPE_TYPE,
        scope_id=SCOPE_ID,
        round=1,
        worker_id="worker-A",
        draft_id="draft-A",
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-007")
def test_same_worker_different_draft_id_conflicts() -> None:
    """Same worker, different draft_id, same key -> conflict."""
    lock = DraftLock()
    lock.acquire(
        gate_id=GATE_ID_SCRUTINY,
        scope_type=SCOPE_TYPE,
        scope_id=SCOPE_ID,
        round=1,
        worker_id="worker-A",
        draft_id="draft-A",
    )
    with pytest.raises(DraftLockConflictError) as ei:
        lock.acquire(
            gate_id=GATE_ID_SCRUTINY,
            scope_type=SCOPE_TYPE,
            scope_id=SCOPE_ID,
            round=1,
            worker_id="worker-A",
            draft_id="draft-B-different",
        )
    assert ei.value.code == RelayErrorCode.RELAY_GATE_014


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-007")
def test_release_then_reacquire_works() -> None:
    """release(holder) -> next worker can acquire the same key."""
    lock = DraftLock()
    lock.acquire(
        gate_id=GATE_ID_SCRUTINY,
        scope_type=SCOPE_TYPE,
        scope_id=SCOPE_ID,
        round=1,
        worker_id="worker-A",
        draft_id="draft-A",
    )
    assert lock.is_held(
        gate_id=GATE_ID_SCRUTINY,
        scope_type=SCOPE_TYPE,
        scope_id=SCOPE_ID,
        round=1,
    )
    released = lock.release(
        gate_id=GATE_ID_SCRUTINY,
        scope_type=SCOPE_TYPE,
        scope_id=SCOPE_ID,
        round=1,
        worker_id="worker-A",
    )
    assert released is True
    # Now worker-B can acquire.
    lock.acquire(
        gate_id=GATE_ID_SCRUTINY,
        scope_type=SCOPE_TYPE,
        scope_id=SCOPE_ID,
        round=1,
        worker_id="worker-B",
        draft_id="draft-B",
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-007")
def test_release_by_non_holder_rejected() -> None:
    lock = DraftLock()
    lock.acquire(
        gate_id=GATE_ID_SCRUTINY,
        scope_type=SCOPE_TYPE,
        scope_id=SCOPE_ID,
        round=1,
        worker_id="worker-A",
        draft_id="draft-A",
    )
    with pytest.raises(DraftLockConflictError):
        lock.release(
            gate_id=GATE_ID_SCRUTINY,
            scope_type=SCOPE_TYPE,
            scope_id=SCOPE_ID,
            round=1,
            worker_id="worker-IMPOSTER",
        )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-007")
def test_parallel_acquire_exactly_one_wins() -> None:
    """Threading test: two threads racing -> exactly one acquires.

    Uses a barrier so both threads attempt the acquire at the same
    moment. The lock's threading.Lock serializes; one thread observes
    a free key and inserts, the other observes the insertion and
    raises DraftLockConflictError.
    """
    lock = DraftLock()
    barrier = threading.Barrier(2)

    def _worker(worker_id: str, draft_id: str) -> str:
        barrier.wait(timeout=2.0)
        try:
            lock.acquire(
                gate_id=GATE_ID_SCRUTINY,
                scope_type=SCOPE_TYPE,
                scope_id=SCOPE_ID,
                round=1,
                worker_id=worker_id,
                draft_id=draft_id,
            )
            return "ok"
        except DraftLockConflictError as exc:
            return f"conflict:{exc.code}"

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(_worker, "worker-A", "draft-A"),
            pool.submit(_worker, "worker-B", "draft-B"),
        ]
        results = [f.result() for f in as_completed(futures)]

    # Exactly one ok, exactly one conflict with RELAY-GATE-014.
    assert sorted(results) == sorted(["ok", f"conflict:{RelayErrorCode.RELAY_GATE_014}"])


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-007")
def test_pipeline_releases_lock_on_success(evaluator) -> None:
    """After a successful run_gate, the lock is released and another
    worker can acquire the same key (e.g., for restart in a later round).
    """
    pipeline = make_pipeline(evaluator)
    now = datetime(2026, 5, 14, 12, 0, 30, tzinfo=UTC)
    gate = make_gate(gate_id=GATE_ID_SCRUTINY, gate_name="scrutiny")
    draft = make_draft(gate_id=GATE_ID_SCRUTINY)

    pipeline.run_gate(
        gate_name="scrutiny", gate=gate, draft=draft, now=now,
    )
    # The lock for this (gate, scope, round) MUST be released after run_gate.
    assert pipeline.draft_lock.is_held(
        gate_id=GATE_ID_SCRUTINY,
        scope_type=SCOPE_TYPE,
        scope_id=SCOPE_ID,
        round=1,
    ) is False


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-007")
def test_different_rounds_do_not_conflict() -> None:
    """Same (gate, scope) but different round -> no conflict."""
    lock = DraftLock()
    lock.acquire(
        gate_id=GATE_ID_SCRUTINY,
        scope_type=SCOPE_TYPE,
        scope_id=SCOPE_ID,
        round=1,
        worker_id="worker-A",
        draft_id="draft-A",
    )
    # Different round -> should succeed.
    lock.acquire(
        gate_id=GATE_ID_SCRUTINY,
        scope_type=SCOPE_TYPE,
        scope_id=SCOPE_ID,
        round=2,
        worker_id="worker-B",
        draft_id="draft-B",
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-007")
def test_invalid_round_rejected() -> None:
    lock = DraftLock()
    with pytest.raises(ValueError):
        lock.acquire(
            gate_id=GATE_ID_SCRUTINY,
            scope_type=SCOPE_TYPE,
            scope_id=SCOPE_ID,
            round=0,
            worker_id="worker-A",
            draft_id="draft-A",
        )
