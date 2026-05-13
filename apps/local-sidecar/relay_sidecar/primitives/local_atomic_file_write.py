"""``local_atomic_file_write`` (atomic-persistence primitive #4).

Per CLAUDE.md keystone invariant #8 + spec H: the only sanctioned write
path for local files under sidecar-owned paths (~/.relay/sidecar.lock,
~/.relay/event_log.jsonl, etc.). Direct ``open(..., 'w')`` against these
paths is a banned pattern.

Behavior contract:

  - Writes ``body`` (bytes) to a sibling tempfile in the same directory
    as ``path`` so the atomic rename is filesystem-local.
  - Calls ``fsync`` on the tempfile fd before rename.
  - On POSIX, sets the tempfile mode to ``mode`` (default 0o600) BEFORE
    rename so the destination never appears world-readable, even briefly.
  - On Windows, applies an explicit DACL granting only the spawning user's
    SID FILE_GENERIC_READ + FILE_GENERIC_WRITE; all other SIDs absent.
    Falls back to a documented warning when pywin32 is unavailable (POSIX
    test runners on macOS will hit this branch via the platform skip).
  - ``os.replace(tmp, path)`` is the atomic rename. On POSIX this is
    atomic across rename(2); on Windows os.replace also overwrites.
  - Supports an append mode (``append=True``) for the local event-log
    JSONL writer (VAL-W2-006): we read the existing body, prepend it to
    the new payload, and re-write atomically. NOT a true streaming
    append, but preserves the atomic-rename invariant for the audit
    trail. Acquires an exclusive portalocker lock for the duration of
    the read-modify-write to serialize concurrent append calls (VAL-
    W2-006 expects exactly-one ``sidecar.spawned`` row under N=10
    concurrent contention).
  - The exclusive portalocker lock is held on the destination ``path``
    itself, not on a sibling lockfile, so concurrent writers see a
    consistent view of the file's content.

Cross-platform:

  - POSIX (macOS, Linux): ``os.chmod`` + ``fcntl.flock`` (wrapped via
    portalocker).
  - Windows: ``portalocker`` uses ``msvcrt.locking``. ACL hardening
    delegated to ``_apply_windows_acl``; absent pywin32 we log a
    structured warning instead of raising so non-Windows test runs
    that exercise this code path (via direct unit tests) don't fail.

VAL-W2-005 enforcement: a grep guard test asserts that this module is
the only writer of ``sidecar.lock`` bytes anywhere under
``apps/local-sidecar/`` and ``packages/cli/``.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import contextlib
import os
import sys
import tempfile
from pathlib import Path

import portalocker

# Re-exported for callers that pass the keyword; matches spec H signature.
DEFAULT_MODE: int = 0o600


def local_atomic_file_write(
    path: Path | str,
    body: bytes,
    *,
    mode: int = DEFAULT_MODE,
    append: bool = False,
) -> None:
    """Atomic write of ``body`` to ``path``.

    Args:
        path: Destination path. Parent directory MUST exist (caller is
            responsible for ``parent.mkdir(parents=True, exist_ok=True)``
            ahead of the call so this primitive remains a pure write).
        body: Raw bytes to write. ``b""`` is permitted (used by
            VAL-W2-009 STALE_PID branch to clear the lockfile).
        mode: POSIX permission bits. Default 0o600. Ignored on Windows
            (where ACL hardening takes over).
        append: If True, prepend ``body`` with the current file's content
            (atomic read-modify-write). Used by the local JSONL event
            log writer. Defaults to False.

    Raises:
        FileNotFoundError: parent directory missing.
        PermissionError: filesystem refuses the rename or mode change.
        OSError: any other I/O failure.
    """
    destination = Path(path)
    parent = destination.parent
    if not parent.is_dir():
        raise FileNotFoundError(
            f"local_atomic_file_write: parent directory missing: {parent}"
        )

    # Acquire an exclusive portalocker lock on the destination so concurrent
    # writers serialize. We must create the destination if it doesn't exist
    # so portalocker has something to lock. portalocker.Lock handles both
    # POSIX (fcntl.flock) and Windows (msvcrt.locking) under the hood.
    #
    # Strategy: open the destination in r+b mode (read+write, no truncate)
    # to acquire the lock; on FileNotFoundError create it as b"" first.
    # This keeps the lock acquisition independent of the body content.
    lock_target = destination
    if not lock_target.exists():
        # Create an empty file we can immediately lock. Mode is applied
        # below in the same atomic write; this initial create is followed
        # by the rename so the visible mode is correct end-to-end.
        with contextlib.suppress(FileExistsError):
            fd = os.open(
                str(lock_target),
                os.O_CREAT | os.O_RDWR | os.O_CLOEXEC,
                0o600 if os.name != "nt" else 0o666,
            )
            os.close(fd)

    # portalocker.LOCK_EX is blocking; the call returns once the lock is
    # acquired. We deliberately do NOT pass a timeout because portalocker
    # warns "timeout has no effect in blocking mode" and the workspace
    # pyproject has filterwarnings=['error'] (treats warnings as failures).
    # Concurrent contention is bounded by the caller's external timeout.
    with portalocker.Lock(
        str(lock_target),
        mode="r+b",
        flags=portalocker.LOCK_EX,
    ) as locked:
        if append:
            existing = locked.read()
            payload = existing + body
        else:
            payload = body

        # Write to a sibling tempfile (same directory for cross-device-safe
        # atomic rename).
        fd, tmp_name = tempfile.mkstemp(
            prefix=destination.name + ".",
            dir=str(parent),
        )
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(payload)
                f.flush()
                os.fsync(f.fileno())
            # Apply mode/ACL BEFORE rename so the destination never has
            # a window of broader permissions.
            if os.name == "nt":
                _apply_windows_acl(tmp_name)
            else:
                os.chmod(tmp_name, mode)
            # Atomic rename. os.replace overwrites on both POSIX and
            # Windows.
            os.replace(tmp_name, str(destination))
        except BaseException:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp_name)
            raise


def _apply_windows_acl(path: str) -> None:
    """Apply a single-ACE DACL granting only the spawning user (Windows).

    Per VAL-W2-004: the DACL MUST contain exactly one ACE for the spawning
    user's SID with FILE_GENERIC_READ | FILE_GENERIC_WRITE. Everyone,
    Users, Authenticated Users, and SYSTEM SIDs MUST be absent.

    On non-Windows platforms this function is a no-op (POSIX paths use
    chmod instead). When pywin32 is unavailable the function logs a
    structured warning via ``warnings.warn`` so the caller is informed
    but the write proceeds (the function is only invoked from
    ``local_atomic_file_write`` which has already established the POSIX
    fallback chmod path).
    """
    if sys.platform != "win32":
        return
    try:  # pragma: no cover (Windows-only)
        import ntsecuritycon
        import win32api
        import win32security
    except ImportError:  # pragma: no cover
        import warnings

        warnings.warn(
            "pywin32 not available; cannot apply Windows ACL hardening. "
            "Install via `pip install pywin32` for VAL-W2-004 enforcement.",
            RuntimeWarning,
            stacklevel=3,
        )
        return

    user_name = win32api.GetUserName()  # pragma: no cover (Windows-only)
    # LookupAccountName returns (SID, domain, type).
    user_sid, _, _ = win32security.LookupAccountName(  # pragma: no cover
        None, user_name
    )

    # Build a DACL with a single ACE granting the user the canonical pair.
    dacl = win32security.ACL()  # pragma: no cover
    dacl.AddAccessAllowedAce(  # pragma: no cover
        win32security.ACL_REVISION,
        ntsecuritycon.FILE_GENERIC_READ | ntsecuritycon.FILE_GENERIC_WRITE,
        user_sid,
    )

    # Apply with PROTECTED_DACL_SECURITY_INFORMATION so inherited ACEs
    # (Everyone, SYSTEM, etc.) are explicitly stripped.
    sd = win32security.SECURITY_DESCRIPTOR()  # pragma: no cover
    sd.SetSecurityDescriptorDacl(1, dacl, 0)  # pragma: no cover
    win32security.SetFileSecurity(  # pragma: no cover
        path,
        (
            win32security.DACL_SECURITY_INFORMATION
            | win32security.PROTECTED_DACL_SECURITY_INFORMATION
        ),
        sd,
    )


__all__ = ["DEFAULT_MODE", "local_atomic_file_write"]
