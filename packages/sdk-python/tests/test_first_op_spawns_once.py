"""VAL-W3-002: the first SDK operation triggers exactly one sidecar spawn.

Calling the first SDK operation that requires the sidecar -- here
``Relay(project_key=...).trace(...)`` -- MUST cause exactly one sidecar
process to spawn OR one attach to an existing sidecar. The evidence is the
file-based event log: the count of rows with ``event_type`` in
``{'sidecar.spawned', 'sidecar.attached'}`` between operation start and
completion MUST equal 1.

A second ``trace()`` on the same client reuses the cached connection and
MUST NOT add another spawn/attach row.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import pytest
from relay import Relay
from relay_sidecar.event_log import count_events

_VALID_KEY = "01ARZ3NDEKTSV4RRFFQ69G5FAV"


def _spawn_or_attach_count(relay_home) -> int:
    """Return the combined sidecar.spawned + sidecar.attached row count."""
    return count_events("sidecar.spawned", home=relay_home) + count_events(
        "sidecar.attached", home=relay_home
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-002")
def test_first_trace_triggers_exactly_one_spawn_or_attach(
    relay_home_tmp,
    stop_sidecar,
) -> None:
    """The first trace() yields exactly one spawn/attach event_log row."""
    stop_sidecar.append(relay_home_tmp)

    # t0: before any operation, the event log has zero spawn/attach rows.
    assert _spawn_or_attach_count(relay_home_tmp) == 0

    r = Relay(project_key=_VALID_KEY, relay_home=relay_home_tmp)
    stop_sidecar.track(r)
    # Still zero after construction (VAL-W3-003 overlap).
    assert _spawn_or_attach_count(relay_home_tmp) == 0

    # The first operation.
    r.trace("first-op")

    # t1: exactly one spawn OR attach row.
    count_after_first = _spawn_or_attach_count(relay_home_tmp)
    assert count_after_first == 1, (
        f"first SDK operation produced {count_after_first} spawn/attach "
        "rows; expected exactly 1"
    )

    # A second operation on the SAME client reuses the cached connection:
    # no new spawn/attach row.
    r.trace("second-op")
    assert _spawn_or_attach_count(relay_home_tmp) == 1, (
        "a second trace() on the same client added another spawn/attach "
        "row; the connection should be cached"
    )

    r.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-002")
def test_second_client_same_home_attaches_not_respawns(
    relay_home_tmp,
    stop_sidecar,
) -> None:
    """A second Relay instance against a live sidecar attaches (no respawn)."""
    stop_sidecar.append(relay_home_tmp)

    r1 = Relay(project_key=_VALID_KEY, relay_home=relay_home_tmp)
    stop_sidecar.track(r1)
    r1.trace("op")
    # Exactly one spawn so far.
    assert count_events("sidecar.spawned", home=relay_home_tmp) == 1
    assert count_events("sidecar.attached", home=relay_home_tmp) == 0

    # A fresh client, same RELAY_HOME, sidecar already running.
    r2 = Relay(project_key=_VALID_KEY, relay_home=relay_home_tmp)
    r2.trace("op")

    # Still exactly one spawn; the second client attached.
    assert count_events("sidecar.spawned", home=relay_home_tmp) == 1, (
        "the second client respawned instead of attaching"
    )
    assert count_events("sidecar.attached", home=relay_home_tmp) == 1
    # Combined, the second client's first op still yielded exactly one row.
    assert _spawn_or_attach_count(relay_home_tmp) == 2

    r1.close()
    r2.close()
