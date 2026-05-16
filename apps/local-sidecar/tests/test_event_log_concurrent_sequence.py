"""Concurrent-appender ingest_sequence monotonicity guard.

VAL-W2-006 requires ``ingest_sequence`` to be strictly monotonic across
all rows of the event log. A prior implementation read the next sequence
value OUTSIDE the atomic-write primitive's lock, then passed a
precomputed line to ``local_atomic_file_write``. Two concurrent appenders
could observe the same prior count and emit duplicate sequence numbers.

The fix moves sequence computation into a ``body_fn`` closure that runs
INSIDE the portalocker exclusive lock. This test exercises the race by
spawning N threads that each call ``append_event`` once with a distinct
event type; it then reads the log back and asserts all N sequence
numbers are unique and cover ``range(N)`` exactly.

Plumbing tier, tier-1, offline. No external services touched.
"""
from __future__ import annotations

import threading
from pathlib import Path

import pytest
from relay_sidecar.event_log import append_event, read_event_log


@pytest.mark.plumbing
def test_append_event_concurrent_writers_no_duplicate_sequence(tmp_path: Path) -> None:
    """20 concurrent appenders MUST produce 20 distinct sequence numbers."""
    n = 20
    barrier = threading.Barrier(n)
    errors: list[BaseException] = []

    def worker(i: int) -> None:
        barrier.wait()
        try:
            append_event(
                "test.race",
                actor_kind="control_plane",
                payload={"i": i},
                home=tmp_path,
            )
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
        assert not t.is_alive(), "appender thread did not finish within 30s"

    assert errors == [], f"unexpected appender errors: {errors!r}"

    rows = read_event_log(home=tmp_path)
    assert len(rows) == n, f"expected {n} rows, got {len(rows)}"
    sequences = sorted(row.ingest_sequence for row in rows)
    assert sequences == list(range(n)), (
        f"sequence numbers must cover range({n}) exactly without duplicates; got {sequences}"
    )


@pytest.mark.plumbing
def test_append_event_first_call_starts_at_sequence_zero(tmp_path: Path) -> None:
    """First append on a fresh home directory produces ingest_sequence=0."""
    entry = append_event("test.first", home=tmp_path)
    assert entry.ingest_sequence == 0
