"""VAL-W2-009: STALE_PID state clears the lockfile and respawns.

Seed a lockfile with PID 999999 (assumed dead); ``acquire_or_attach``
MUST clear the lockfile via ``local_atomic_file_write(body=b"")``,
emit a ``sidecar.stale_pid_cleared`` event-log row, then spawn fresh.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from relay_sidecar.event_log import count_events, read_event_log
from relay_sidecar.lockfile import (
    LockfileBody,
    resolve_lockfile_path,
    serialize_lockfile_body,
)
from relay_sidecar.primitives import local_atomic_file_write
from relay_sidecar.spawn import acquire_or_attach


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-009")
def test_stale_pid_clears_and_respawns(relay_home_tmp: Path) -> None:
    # Seed a lockfile with a guaranteed-dead PID.
    stale_body = LockfileBody(
        pid=999999,
        port=50050,
        launched_at="2026-05-01T00:00:00Z",
        launched_by="ghost-user",
        sidecar_version="0.0.0",
        bearer_token_digest="sha256-" + "c" * 64,
    )
    lockfile = resolve_lockfile_path(relay_home_tmp)
    local_atomic_file_write(
        lockfile,
        serialize_lockfile_body(stale_body),
        mode=0o600,
    )
    assert lockfile.exists()

    # Run acquire_or_attach with a real-pid runner.
    new_pid = os.getpid()
    decision = acquire_or_attach(
        home=relay_home_tmp,
        process_runner=lambda: (new_pid, 50051),
    )
    assert decision.action == "stale_pid_cleared_and_spawned"
    assert decision.lockfile_body.pid == new_pid
    assert decision.lockfile_body.pid != stale_body.pid

    # The event log MUST contain a sidecar.stale_pid_cleared row.
    stale_rows = count_events("sidecar.stale_pid_cleared", home=relay_home_tmp)
    assert stale_rows == 1, f"expected 1 stale-pid event; observed {stale_rows}"

    # The cleared row must reference the prior pid in its payload.
    entries = read_event_log(home=relay_home_tmp)
    cleared = next(
        e for e in entries if e.event_type == "sidecar.stale_pid_cleared"
    )
    assert cleared.payload.get("prior_pid") == stale_body.pid
    assert cleared.payload.get("prior_port") == stale_body.port

    # And the new lockfile must carry the new pid.
    assert decision.lockfile_body.port == 50051
