"""VAL-ISO-027: malformed (non-empty corrupt) lockfile must not wedge startup.

A non-empty but unparseable canonical lockfile (e.g. partial bytes left by a
process that crashed mid-serialize, or on-disk corruption) used to permanently
wedge ``acquire_or_attach``: ``_classify_and_act`` read the file, called
``parse_lockfile_body`` and re-raised the ``SidecarError``
(RELAY-SIDECAR-001 LOCKFILE-MALFORMED) instead of treating it as a clearable
state -- contradicting the four-state recovery design and the inline comment
that promised "Treat malformed-but-present lockfile as a clearable state".

This module pins two behaviours:

  * A malformed non-empty lockfile is CLEARED (via the atomic primitive) under
    the held decision lock, a ``sidecar.malformed_lockfile_cleared`` audit row
    is emitted, and startup proceeds with a fresh spawn.
  * A VALID lockfile pointing at a live PID on a bound port still BLOCKS
    (``attached``); the malformed-recovery path must not clear a valid one.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import os
import socket
from pathlib import Path

import pytest
from relay_sidecar.event_log import count_events, read_event_log
from relay_sidecar.lockfile import (
    LockfileBody,
    resolve_lockfile_path,
    serialize_lockfile_body,
)
from relay_sidecar.primitives import local_atomic_file_write
from relay_sidecar.spawn import _now_rfc3339_z, acquire_or_attach


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-027")
def test_malformed_lockfile_is_cleared_and_respawns(relay_home_tmp: Path) -> None:
    # Seed a non-empty but unparseable canonical lockfile.
    lockfile = resolve_lockfile_path(relay_home_tmp)
    local_atomic_file_write(lockfile, b"{ this is not valid lockfile json ", mode=0o600)
    assert lockfile.exists()
    assert lockfile.stat().st_size > 0

    new_pid = os.getpid()
    # Must NOT raise SidecarError -- must clear and spawn.
    decision = acquire_or_attach(
        home=relay_home_tmp,
        process_runner=lambda: (new_pid, 50061),
    )
    assert decision.action == "malformed_lockfile_cleared_and_spawned"
    assert decision.lockfile_body.pid == new_pid
    assert decision.lockfile_body.port == 50061

    # Exactly one malformed-cleared audit row is emitted.
    cleared = count_events(
        "sidecar.malformed_lockfile_cleared", home=relay_home_tmp
    )
    assert cleared == 1, f"expected 1 malformed-cleared event; observed {cleared}"

    entries = read_event_log(home=relay_home_tmp)
    row = next(
        e for e in entries if e.event_type == "sidecar.malformed_lockfile_cleared"
    )
    assert row.actor_kind == "control_plane"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-027")
def test_valid_live_lockfile_is_not_cleared(relay_home_tmp: Path) -> None:
    # Bind a real port and point a VALID lockfile at this live process.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    port = s.getsockname()[1]
    try:
        body = LockfileBody(
            pid=os.getpid(),
            port=port,
            launched_at=_now_rfc3339_z(),
            launched_by="test-user",
            sidecar_version="0.0.0",
            bearer_token_digest="sha256-" + "d" * 64,
        )
        lockfile = resolve_lockfile_path(relay_home_tmp)
        local_atomic_file_write(
            lockfile, serialize_lockfile_body(body), mode=0o600
        )

        decision = acquire_or_attach(
            home=relay_home_tmp,
            process_runner=lambda: (os.getpid(), port + 1),
        )
        # A valid, live lockfile blocks: ATTACHED, not cleared.
        assert decision.action == "attached"
        assert decision.lockfile_body.pid == os.getpid()
        assert decision.lockfile_body.port == port
        # No malformed-cleared event was emitted for a valid lockfile.
        assert (
            count_events("sidecar.malformed_lockfile_cleared", home=relay_home_tmp)
            == 0
        )
    finally:
        s.close()
