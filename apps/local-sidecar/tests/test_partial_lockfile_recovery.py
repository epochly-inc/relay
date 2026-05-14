"""VAL-W2-050: partial lockfile (interrupted atomic-rename) is detected and cleared.

``local_atomic_file_write`` writes to a sibling tempfile via
``tempfile.mkstemp(prefix=destination.name + ".", dir=parent)`` and
then ``os.replace(tmp, destination)``. If the process dies between
fsync and rename, the orphan ``<lockfile>.<random>`` tmp file is left
on disk. The next ``acquire_or_attach`` MUST detect the orphan, clear
it, and proceed to the standard four-state classifier without raising
``RELAY-SIDECAR-LOCKFILE-MALFORMED``.

The recovery helper ``relay_sidecar.recovery.recover_partial_lockfile``
implements the detection: any file in the lockfile directory whose
name starts with ``<lockfile-name>.`` is treated as orphan-tmp and
removed.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from relay_sidecar.lockfile import resolve_lockfile_path
from relay_sidecar.recovery import recover_partial_lockfile
from relay_sidecar.spawn import acquire_or_attach


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-050")
def test_partial_lockfile_tmp_is_detected_and_removed(
    relay_home_tmp: Path,
) -> None:
    """An orphan ``<lockfile>.<random>`` tmpfile is removed by recovery."""
    lockfile = resolve_lockfile_path(relay_home_tmp)
    # Manually seed the orphan in the lockfile directory.
    orphan_path = lockfile.parent / (lockfile.name + ".abc123def")
    orphan_path.write_bytes(b'{"partial_write_marker": true}')
    assert orphan_path.exists()
    assert not lockfile.exists()

    removed = recover_partial_lockfile(lockfile)
    assert removed is True, (
        "recover_partial_lockfile should report removal=True when an orphan is cleared"
    )
    assert not orphan_path.exists(), "orphan tmp must be unlinked"
    assert not lockfile.exists(), "real lockfile should remain absent"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-050")
def test_partial_lockfile_recovery_then_acquire_or_attach_spawns_clean(
    relay_home_tmp: Path,
) -> None:
    """After clearing an orphan, ``acquire_or_attach`` spawns without LOCKFILE-MALFORMED."""
    lockfile = resolve_lockfile_path(relay_home_tmp)
    orphan = lockfile.parent / (lockfile.name + ".XYZ987")
    orphan.write_bytes(b"not-valid-json {malformed")
    assert orphan.exists()

    # Recovery clears the orphan first.
    recover_partial_lockfile(lockfile)
    assert not orphan.exists()

    # Now spawn should proceed via the NO_LOCKFILE branch.
    decision = acquire_or_attach(
        home=relay_home_tmp,
        process_runner=lambda: (os.getpid(), 50060),
    )
    assert decision.action == "spawned", (
        f"expected NO_LOCKFILE -> spawned; got {decision.action!r}"
    )
    assert decision.lockfile_body.port == 50060


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-050")
def test_recover_partial_lockfile_returns_false_on_clean_dir(
    relay_home_tmp: Path,
) -> None:
    """No orphan tmp present -> recovery is a no-op returning False."""
    lockfile = resolve_lockfile_path(relay_home_tmp)
    assert recover_partial_lockfile(lockfile) is False


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-050")
def test_recover_partial_lockfile_does_not_remove_real_lockfile(
    relay_home_tmp: Path,
) -> None:
    """The real lockfile (no ``.<suffix>``) is left alone."""
    lockfile = resolve_lockfile_path(relay_home_tmp)
    lockfile.write_bytes(b'{"valid": true}')
    assert recover_partial_lockfile(lockfile) is False
    assert lockfile.exists()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-050")
def test_recover_partial_lockfile_handles_multiple_orphans(
    relay_home_tmp: Path,
) -> None:
    """Multiple orphan tmps are all removed in one pass."""
    lockfile = resolve_lockfile_path(relay_home_tmp)
    orphans = [
        lockfile.parent / (lockfile.name + f".tmp{i}") for i in range(3)
    ]
    for o in orphans:
        o.write_bytes(b"orphan")
    assert all(o.exists() for o in orphans)

    removed = recover_partial_lockfile(lockfile)
    assert removed is True
    assert all(not o.exists() for o in orphans)
