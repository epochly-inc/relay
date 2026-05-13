"""VAL-W2-003: Lockfile POSIX mode is 0o600 on macOS and Linux.

Any other mode (0644, 0640, ...) MUST cause the sidecar to refuse to
start with ``RELAY-SIDECAR-LOCKFILE-INSECURE``.

Skipped on Windows (where ACL hardening replaces chmod).
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest
from relay_sidecar.errors import (
    RELAY_SIDECAR_LOCKFILE_INSECURE,
    RELAY_SIDECAR_LOCKFILE_INSECURE_CODE,
    SidecarError,
)
from relay_sidecar.lockfile import resolve_lockfile_path
from relay_sidecar.spawn import acquire_or_attach

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX-only test")


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-003")
def test_lockfile_mode_after_spawn_is_0600(relay_home_tmp: Path) -> None:
    acquire_or_attach(
        home=relay_home_tmp,
        process_runner=lambda: (os.getpid(), 50010),
    )
    lockfile = resolve_lockfile_path(relay_home_tmp)
    mode = stat.S_IMODE(os.stat(lockfile).st_mode)
    assert mode == 0o600, f"observed mode={oct(mode)} expected=0o600"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-003")
def test_lockfile_with_insecure_mode_rejected_on_next_spawn(
    relay_home_tmp: Path,
) -> None:
    """If something tampers with the lockfile mode, sidecar refuses to attach."""
    # Run an initial spawn to create the lockfile correctly.
    acquire_or_attach(
        home=relay_home_tmp,
        process_runner=lambda: (os.getpid(), 50011),
    )
    lockfile = resolve_lockfile_path(relay_home_tmp)
    assert lockfile.exists()
    # Tamper: chmod to 0o644 (world-readable).
    os.chmod(lockfile, 0o644)
    # Next acquire_or_attach MUST raise INSECURE.
    with pytest.raises(SidecarError) as exc:
        acquire_or_attach(
            home=relay_home_tmp,
            process_runner=lambda: (os.getpid(), 50012),
        )
    assert exc.value.code == RELAY_SIDECAR_LOCKFILE_INSECURE_CODE
    assert exc.value.error_class == RELAY_SIDECAR_LOCKFILE_INSECURE


# Suppress unused-import warning.
_ = sys
