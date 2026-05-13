"""VAL-W2-004: Windows lockfile ACL grants only the spawning user.

Required ACE shape (Windows only):

  - DACL contains EXACTLY one ACE.
  - ACE SID == ``win32security.LookupAccountName(None, GetUserName())``.
  - Access mask == ``FILE_GENERIC_READ | FILE_GENERIC_WRITE``.
  - SIDs absent: Everyone (S-1-1-0), Users (S-1-5-32-545),
    Authenticated Users (S-1-5-11), SYSTEM (S-1-5-18).

Failing ACL -> ``RELAY-SIDECAR-LOCKFILE-WINDOWS-ACL``.

Skipped on non-Windows platforms so macOS / Linux CI never run this.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "win32", reason="Windows-only ACL test (VAL-W2-004)"
)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-004")
def test_windows_acl_single_ace_spawning_user(  # pragma: no cover
    relay_home_tmp: Path,
) -> None:
    """The lockfile DACL has exactly one ACE for the spawning user.

    This test only runs on the ``windows-latest`` CI runner; on macOS /
    Linux the module-level skipif marker bypasses it cleanly.
    """
    import ntsecuritycon
    import win32api
    import win32security
    from relay_sidecar.lockfile import resolve_lockfile_path
    from relay_sidecar.spawn import acquire_or_attach

    acquire_or_attach(
        home=relay_home_tmp,
        process_runner=lambda: (os.getpid(), 50020),
    )
    lockfile = resolve_lockfile_path(relay_home_tmp)
    assert lockfile.exists()

    sd = win32security.GetFileSecurity(
        str(lockfile), win32security.DACL_SECURITY_INFORMATION
    )
    dacl = sd.GetSecurityDescriptorDacl()
    assert dacl is not None, "DACL missing on lockfile"
    ace_count = dacl.GetAceCount()
    assert ace_count == 1, f"observed {ace_count} ACEs; expected exactly 1"

    user_name = win32api.GetUserName()
    expected_sid, _, _ = win32security.LookupAccountName(None, user_name)

    _, observed_mask, observed_sid = dacl.GetAce(0)
    expected_mask = (
        ntsecuritycon.FILE_GENERIC_READ | ntsecuritycon.FILE_GENERIC_WRITE
    )
    assert observed_mask == expected_mask, (
        f"access mask observed={observed_mask} expected={expected_mask}"
    )
    assert str(observed_sid) == str(expected_sid), "SID mismatch"

    # Negative SIDs: Everyone, Users, AuthenticatedUsers, SYSTEM all absent.
    sids_we_must_not_grant = {
        "S-1-1-0",  # Everyone
        "S-1-5-32-545",  # Users
        "S-1-5-11",  # Authenticated Users
        "S-1-5-18",  # SYSTEM
    }
    assert str(observed_sid) not in sids_we_must_not_grant
