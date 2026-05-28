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
    concurrent contention; W3.1 VAL-W3-006 additionally requires that
    nine concurrent ``sidecar.attached`` appends are ALL retained).
  - The exclusive portalocker lock is held on a STABLE sibling lock
    file ``<path>.wlock`` -- NOT on the destination ``path`` itself.
    This is load-bearing for concurrent appends: ``os.replace`` swaps
    the destination's inode on every write, so a peer process that was
    blocked waiting for a lock held on the OLD destination fd would,
    on acquiring it, be holding a lock on an orphaned (already-renamed-
    away) inode and would then read stale content -- silently dropping
    the previous writer's appended line. A sibling lock file whose
    inode is never renamed gives every writer a single consistent
    serialization point; each writer reads the destination's CURRENT
    content fresh inside the critical section.

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
from collections.abc import Callable
from pathlib import Path

import portalocker

# Re-exported for callers that pass the keyword; matches spec H signature.
DEFAULT_MODE: int = 0o600


def local_atomic_file_write(
    path: Path | str,
    body: bytes | None = None,
    *,
    mode: int = DEFAULT_MODE,
    append: bool = False,
    body_fn: Callable[[bytes], bytes] | None = None,
) -> None:
    """Atomic write of ``body`` to ``path``.

    Args:
        path: Destination path. Parent directory MUST exist (caller is
            responsible for ``parent.mkdir(parents=True, exist_ok=True)``
            ahead of the call so this primitive remains a pure write).
        body: Raw bytes to write. ``b""`` is permitted (used by
            VAL-W2-009 STALE_PID branch to clear the lockfile). Mutually
            exclusive with ``body_fn``.
        mode: POSIX permission bits. Default 0o600. Ignored on Windows
            (where ACL hardening takes over).
        append: If True, prepend ``body`` with the current file's content
            (atomic read-modify-write). Used by the local JSONL event
            log writer. Defaults to False. Mutually exclusive with
            ``body_fn``.
        body_fn: Optional callback invoked INSIDE the exclusive lock with
            the destination's current bytes (b"" when absent). Must return
            the full bytes to write to the destination. Enables atomic
            read-modify-write that depends on the existing content (for
            example: line-count + append used by the event-log
            ingest-sequence assignment). Mutually exclusive with ``body``
            and with ``append``. When ``body_fn`` is supplied, ``body``
            must be ``None``.

    Raises:
        FileNotFoundError: parent directory missing.
        PermissionError: filesystem refuses the rename or mode change.
        OSError: any other I/O failure.
        ValueError: arguments are inconsistent (both ``body`` and
            ``body_fn`` provided; neither provided; ``body_fn`` combined
            with ``append=True``).
    """
    # Argument validation. ``body_fn`` is mutually exclusive with both
    # ``body`` and ``append``: it already composes the full payload from
    # the existing content, so combining it with the legacy append-concat
    # path would double-count.
    if body_fn is not None:
        if body is not None:
            raise ValueError(
                "local_atomic_file_write: 'body' and 'body_fn' are mutually "
                "exclusive; pass exactly one."
            )
        if append:
            raise ValueError(
                "local_atomic_file_write: 'body_fn' implies its own "
                "read-modify-write; do not combine with append=True."
            )
    elif body is None:
        raise ValueError(
            "local_atomic_file_write: must supply either 'body' or 'body_fn'."
        )

    destination = Path(path)
    parent = destination.parent
    if not parent.is_dir():
        raise FileNotFoundError(
            f"local_atomic_file_write: parent directory missing: {parent}"
        )

    # Acquire an exclusive portalocker lock on a STABLE sibling lock file
    # so concurrent writers serialize. portalocker.Lock handles both POSIX
    # (fcntl.flock) and Windows (msvcrt.locking) under the hood.
    #
    # Why a sibling lock file and NOT the destination itself: this
    # primitive writes the payload to a tempfile and then ``os.replace``s
    # it over the destination. ``os.replace`` swaps the destination's
    # inode. A peer process that blocked waiting for a lock held on the
    # OLD destination fd would, on acquiring it, hold a lock on an inode
    # that has already been renamed away -- losing mutual exclusion and,
    # for append mode, silently dropping the previous writer's line. The
    # sibling lock file's inode is created once and NEVER renamed, so it
    # is a single consistent serialization point for every writer.
    #
    # The lock file name is ``.<destination-name>.wlock``: the leading dot
    # keeps it OUT of the ``<destination-name>.`` mkstemp-prefix space, so
    # ``recovery.recover_partial_lockfile`` (which unlinks orphan
    # ``<lockfile>.*`` tempfiles) never removes the live lock file.
    lock_path = parent / ("." + destination.name + ".wlock")
    if not lock_path.exists():
        # Create the stable lock file once. It is intentionally never
        # unlinked: it carries no data, only the advisory lock.
        with contextlib.suppress(FileExistsError):
            # ``os.O_CLOEXEC`` is POSIX-only; Windows lacks the
            # exec-inheritance model the flag controls. Use 0 (no-op)
            # on Windows so the open succeeds without the attribute.
            cloexec_flag = getattr(os, "O_CLOEXEC", 0)
            fd = os.open(
                str(lock_path),
                os.O_CREAT | os.O_RDWR | cloexec_flag,
                0o600 if os.name != "nt" else 0o666,
            )
            os.close(fd)

    # portalocker.LOCK_EX is blocking; the call returns once the lock is
    # acquired. We deliberately do NOT pass a timeout because portalocker
    # warns "timeout has no effect in blocking mode" and the workspace
    # pyproject has filterwarnings=['error'] (treats warnings as failures).
    # Concurrent contention is bounded by the caller's external timeout.
    with portalocker.Lock(
        str(lock_path),
        mode="r+b",
        flags=portalocker.LOCK_EX,
    ):
        if body_fn is not None or append:
            # Read the destination's CURRENT content fresh inside the
            # critical section -- NOT through the lock-file fd. Because
            # the lock is held, no peer can be mid-replace, so this read
            # observes a fully-committed prior write. Both ``append`` and
            # ``body_fn`` paths depend on this serialized read.
            try:
                existing = destination.read_bytes()
            except FileNotFoundError:
                existing = b""
            if body_fn is not None:
                # Caller-supplied callback composes the full payload from
                # the existing bytes. The lock is held for the duration
                # of the callback; the callback observes a fully-committed
                # prior state. Used by ``append_event`` for sequence
                # assignment that depends on the current line count.
                payload = body_fn(existing)
            else:
                # body is non-None here because argument validation above
                # rejected ``append=True`` with ``body=None``.
                assert body is not None  # noqa: S101
                payload = existing + body
        else:
            assert body is not None  # noqa: S101
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
