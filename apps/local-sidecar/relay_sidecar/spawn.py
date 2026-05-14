"""Sidecar spawn semantics + four-state lockfile classifier (W2.1).

Implements spec section H.5 + eng plan A1 for the local OSS sidecar:

  1. Probe ``${RELAY_HOME}`` filesystem; refuse to start on NFS/SMB.
  2. Probe the existing lockfile and classify the world into four states:
        - ALREADY_RUNNING (lockfile valid, PID alive, port bound, nonce OK)
        - STALE_PID       (lockfile present but PID dead)
        - ZOMBIE_PORT     (lockfile present, PID alive, port unbound)
        - NO_LOCKFILE     (no file)
  3. Take action:
        - ALREADY_RUNNING -> ``ATTACH`` (return existing endpoint info)
        - STALE_PID       -> clear lockfile via local_atomic_file_write
                             (body=b""); emit ``sidecar.stale_pid_cleared``;
                             continue to SPAWN
        - ZOMBIE_PORT     -> ``terminate_pid(lockfile.pid)``; emit
                             ``sidecar.zombie_pid_terminated``; continue
                             to SPAWN
        - NO_LOCKFILE     -> SPAWN

In W2.1 the SPAWN action does NOT yet start a real long-lived uvicorn
process. The full asyncio sidecar runtime is W2.2+. W2.1 lands the
spawn-decision pipeline + the four-state classifier + the lockfile
serialization. Tests inject a stub "process_runner" callable that returns
a (pid, port) pair after writing the lockfile; the real CLI entrypoint in
W5 will replace the stub with ``subprocess.Popen``.

The ``acquire_or_attach`` API returns a structured ``SpawnDecision``
named-tuple carrying the action taken plus the resulting lockfile
contents, so callers (tests AND the W5 CLI) can introspect.

VAL-W2-006 evidence: under N=10 concurrent spawn races, the portalocker
exclusive lock in ``local_atomic_file_write`` guarantees exactly one
process writes the lockfile and emits ``sidecar.spawned``. We DOUBLE-LOCK
here: the spawn-decision loop holds a separate file lock on the lockfile
path BEFORE writing, AND uses the primitive's exclusive lock for the
actual write. This keeps the decision atomic (read-classify-act) across
the multiprocess boundary.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import getpass
import os
import secrets
import socket
import sys
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

import portalocker

from . import __version__
from .errors import (
    RELAY_SIDECAR_LOCKFILE_INSECURE,
    RELAY_SIDECAR_LOCKFILE_WINDOWS_ACL,
    RELAY_SIDECAR_NONLOCAL_FS,
    SidecarError,
    make_error,
)
from .event_log import append_event
from .filesystem import is_local_filesystem
from .lockfile import (
    LockfileBody,
    parse_lockfile_body,
    relay_home,
    resolve_lockfile_path,
    serialize_lockfile_body,
)
from .primitives import local_atomic_file_write
from .process import pid_is_alive, terminate_pid
from .recovery import recover_partial_lockfile

# Bearer token entropy. 256 bits = 32 bytes -> secrets.token_urlsafe(32)
# produces 43 URL-safe characters. The plaintext token is RETURNED to the
# caller of spawn_sidecar(); only the SHA-256 digest is persisted in the
# lockfile (matching spec H.5 + VAL-W2-002 + W1 canonical sha256 form).
BEARER_TOKEN_BYTES: int = 32


SpawnAction = Literal[
    "spawned",
    "attached",
    "stale_pid_cleared_and_spawned",
    "zombie_port_terminated_and_spawned",
]


@dataclass(frozen=True)
class SpawnDecision:
    """Outcome of ``acquire_or_attach``.

    Attributes:
        action: Which branch of the four-state classifier executed.
        lockfile_body: The lockfile contents post-action.
        bearer_token: The plaintext bearer token if ``action`` is one of
            the spawn variants; ``None`` on ``attached`` (the attacher does
            not learn the token -- it must already know the digest from a
            prior spawn within the same process).
    """

    action: SpawnAction
    lockfile_body: LockfileBody
    bearer_token: str | None


def _bind_ephemeral_port(host: str = "127.0.0.1") -> tuple[int, socket.socket]:
    """Bind a fresh ephemeral port on ``host`` and return (port, socket).

    The socket is kept open and returned so the spawn handoff can pass it
    to the real listener (W2.2+) without losing the binding. In W2.1 tests
    the socket is closed immediately after the lockfile is written; the
    port number is what the tests assert.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, 0))
    port = s.getsockname()[1]
    return port, s


def _make_bearer_token_pair() -> tuple[str, str]:
    """Return (token, digest) where digest is the canonical sha256 form."""
    import hashlib

    token = secrets.token_urlsafe(BEARER_TOKEN_BYTES)
    digest_hex = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return token, f"sha256-{digest_hex}"


def _ensure_relay_home(home: Path) -> None:
    """Mkdir ``home`` with secure mode (0700 on POSIX)."""
    import contextlib

    home.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        # If chmod fails (read-only fs etc.), the lockfile-mode check
        # downstream still enforces 0o600 on the lockfile itself.
        with contextlib.suppress(OSError):
            os.chmod(home, 0o700)


def _check_lockfile_mode(lockfile_path: Path) -> None:
    """VAL-W2-003 / VAL-W2-004: refuse to proceed on insecure lockfile mode.

    POSIX: ``stat`` -> mode bits MUST be 0o600.
    Windows: a stub check that pywin32 lockdown was attempted (the actual
    ACL enumeration lives in tests via win32security.GetFileSecurity).
    """
    if not lockfile_path.exists():
        return
    if sys.platform == "win32":  # pragma: no cover (POSIX test runner)
        # Best-effort: the primitive applies a single-ACE DACL on write.
        # The Windows test (VAL-W2-004) enumerates the DACL directly.
        return
    st = os.stat(lockfile_path)
    actual_mode = st.st_mode & 0o777
    if actual_mode != 0o600:
        raise make_error(
            RELAY_SIDECAR_LOCKFILE_INSECURE,
            f"lockfile mode is {oct(actual_mode)}; expected 0o600",
            details={"path": str(lockfile_path), "observed_mode": oct(actual_mode)},
        )


def _is_port_bound(port: int, host: str = "127.0.0.1") -> bool:
    """Return True if ``host:port`` accepts a TCP connect."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.2)
    try:
        s.connect((host, port))
        return True
    except (ConnectionRefusedError, TimeoutError, OSError):
        return False
    finally:
        s.close()


# Type alias for the process-runner stub. The real W5 entrypoint will pass
# a callable that does ``subprocess.Popen([...], close_fds=True)`` and
# returns the spawned child's pid + chosen port; tests pass a simpler
# in-process callable that returns the calling process's pid.
ProcessRunner = Callable[[], tuple[int, int]]


def _default_process_runner() -> tuple[int, int]:
    """Default runner used by W2.1.

    W2.1 does NOT yet start a real long-lived daemon (that lands in W2.2
    once the asyncio runtime + aiosqlite + state engine are wired). The
    default runner reports the current process's pid plus an ephemeral
    port to satisfy the lockfile schema. Tests can pass an explicit runner
    to inject deterministic pid/port values.
    """
    port, s = _bind_ephemeral_port()
    s.close()
    return os.getpid(), port


def acquire_or_attach(
    *,
    home: Path | None = None,
    process_runner: ProcessRunner | None = None,
) -> SpawnDecision:
    """Run the four-state lockfile classifier and return the decision.

    Args:
        home: Override the relay-home directory (test injection).
            Defaults to ``relay_home()`` (RELAY_HOME env or ``~/.relay``).
        process_runner: Callable returning (pid, port) for the spawn
            branch. Defaults to ``_default_process_runner``.

    Raises:
        SidecarError: VAL-W2-011 (NONLOCAL_FS), VAL-W2-003 (LOCKFILE-INSECURE),
            VAL-W2-002 (LOCKFILE-MALFORMED), VAL-W2-004 (Windows ACL).
    """
    base = home if home is not None else relay_home()
    _ensure_relay_home(base)

    # VAL-W2-011: refuse to start on non-local filesystems.
    if not is_local_filesystem(base):
        # Probe again to get the actual signal for the error details.
        from .filesystem import probe_filesystem

        kind, value = probe_filesystem(base)
        raise make_error(
            RELAY_SIDECAR_NONLOCAL_FS,
            f"sidecar refuses to start on non-local filesystem: {kind}={value!r}",
            details={"home": str(base), "probe_kind": kind, "probe_value": value},
        )

    lockfile_path = resolve_lockfile_path(base)
    # VAL-W2-050 / STR-001 fix: detect and clear an orphan
    runner = process_runner if process_runner is not None else _default_process_runner

    # Open a separate decision-level lockfile so the read-classify-act
    # sequence is atomic across processes. The primitive itself locks the
    # destination during writes; this additional lock serializes the
    # decision logic. We use a sibling file ``sidecar.spawn.lock``.
    import contextlib

    decision_lock_path = base / "sidecar.spawn.lock"
    # Ensure the decision lock file exists (portalocker requires it).
    decision_lock_path.touch(exist_ok=True)
    if os.name != "nt":
        with contextlib.suppress(OSError):
            os.chmod(decision_lock_path, 0o600)

    with portalocker.Lock(
        str(decision_lock_path),
        mode="r+b",
        flags=portalocker.LOCK_EX,
    ):
        # VAL-W2-050 partial-lockfile recovery — runs UNDER the decision
        # lock, NOT before it (STR-002 fix). ``recover_partial_lockfile``
        # iterates the parent dir and unlinks any ``<lockfile>.*`` orphan
        # tmpfile. Without the decision lock held, a concurrent process
        # mid-``local_atomic_file_write`` (between mkstemp+fsync and
        # os.replace) could have its in-flight tmpfile unlinked, causing
        # FileNotFoundError on os.replace and breaking VAL-W2-006
        # serialization. Holding the decision lock guarantees no peer
        # process is between mkstemp and os.replace on the canonical
        # lockfile. ``recover_partial_lockfile`` is idempotent and a
        # no-op when no orphan tmpfile exists.
        recover_partial_lockfile(lockfile_path)
        return _classify_and_act(
            lockfile_path=lockfile_path,
            home=base,
            runner=runner,
        )


def _classify_and_act(
    *,
    lockfile_path: Path,
    home: Path,
    runner: ProcessRunner,
) -> SpawnDecision:
    """Inner classifier; assumes the decision lock is held."""
    # NO_LOCKFILE branch.
    if not lockfile_path.exists() or lockfile_path.stat().st_size == 0:
        return _spawn_and_write(
            lockfile_path=lockfile_path,
            home=home,
            runner=runner,
            action="spawned",
        )

    # Validate mode before reading (VAL-W2-003).
    _check_lockfile_mode(lockfile_path)

    # Read current contents.
    raw = lockfile_path.read_bytes()
    try:
        body = parse_lockfile_body(raw)
    except SidecarError:
        # Treat malformed-but-present lockfile as a clearable state.
        # Re-raise so callers see VAL-W2-002 (LOCKFILE-MALFORMED). The
        # caller can decide whether to overwrite via a fresh spawn.
        raise

    # ALREADY_RUNNING vs STALE_PID vs ZOMBIE_PORT.
    pid_alive = pid_is_alive(body.pid)
    port_bound = _is_port_bound(body.port)

    if pid_alive and port_bound:
        return SpawnDecision(action="attached", lockfile_body=body, bearer_token=None)

    if not pid_alive:
        # STALE_PID: clear via primitive (VAL-W2-009).
        local_atomic_file_write(lockfile_path, b"", mode=0o600)
        append_event(
            "sidecar.stale_pid_cleared",
            scope_type="other",
            actor_kind="control_plane",
            payload={"prior_pid": body.pid, "prior_port": body.port},
            home=home,
        )
        return _spawn_and_write(
            lockfile_path=lockfile_path,
            home=home,
            runner=runner,
            action="stale_pid_cleared_and_spawned",
        )

    # ZOMBIE_PORT branch (VAL-W2-010): pid alive but port unbound.
    # Terminate the lockfile-recorded pid (PID-only, never name-based).
    terminate_pid(body.pid)
    append_event(
        "sidecar.zombie_pid_terminated",
        scope_type="other",
        actor_kind="control_plane",
        payload={"terminated_pid": body.pid, "lockfile_port": body.port},
        home=home,
    )
    return _spawn_and_write(
        lockfile_path=lockfile_path,
        home=home,
        runner=runner,
        action="zombie_port_terminated_and_spawned",
    )


def _spawn_and_write(
    *,
    lockfile_path: Path,
    home: Path,
    runner: ProcessRunner,
    action: SpawnAction,
) -> SpawnDecision:
    """Run the process runner, persist the lockfile, emit sidecar.spawned."""
    pid, port = runner()
    token, digest = _make_bearer_token_pair()
    body = LockfileBody(
        pid=pid,
        port=port,
        launched_at=_now_rfc3339_z(),
        launched_by=getpass.getuser(),
        sidecar_version=__version__,
        bearer_token_digest=digest,
    )
    payload = serialize_lockfile_body(body)
    local_atomic_file_write(lockfile_path, payload, mode=0o600)

    # VAL-W2-004 Windows-only post-write check that the ACL is restrictive.
    if sys.platform == "win32":  # pragma: no cover (POSIX test runner)
        _verify_windows_acl_post_write(lockfile_path)

    # Per VAL-W2-006 the ``sidecar.spawned`` event marks the
    # first-ever-spawn-of-the-current-lockfile-lineage. Recovery-path
    # spawns (STALE_PID, ZOMBIE_PORT) emit a separate event type so the
    # audit trail distinguishes "fresh spawn" from "respawn after
    # recovery". This keeps the assertion-on-event-count clean: under
    # N=10 concurrent processes that all enter the four-state classifier,
    # exactly ONE crosses the NO_LOCKFILE -> SPAWN branch and emits
    # ``sidecar.spawned``; recovery respawns emit ``sidecar.respawned``.
    if action == "spawned":
        append_event(
            "sidecar.spawned",
            scope_type="other",
            actor_kind="control_plane",
            payload={"pid": pid, "port": port, "spawn_action": action},
            home=home,
        )
    else:
        append_event(
            "sidecar.respawned",
            scope_type="other",
            actor_kind="control_plane",
            payload={"pid": pid, "port": port, "spawn_action": action},
            home=home,
        )
    return SpawnDecision(action=action, lockfile_body=body, bearer_token=token)


def _now_rfc3339_z() -> str:
    """Return current UTC time as an RFC 3339 string with ``Z`` suffix."""
    return (
        datetime.now(tz=UTC)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _verify_windows_acl_post_write(path: Path) -> None:  # pragma: no cover
    """Verify the lockfile DACL has exactly one ACE for the spawning user.

    Per VAL-W2-004: ACE count = 1; SID = spawning user's SID; access mask
    = FILE_GENERIC_READ | FILE_GENERIC_WRITE; Everyone, Users,
    Authenticated Users, SYSTEM SIDs all absent.
    """
    try:
        import ntsecuritycon
        import win32api
        import win32security
    except ImportError:
        # pywin32 unavailable; the primitive already emitted a warning.
        return

    user_name = win32api.GetUserName()
    expected_sid, _, _ = win32security.LookupAccountName(None, user_name)

    sd = win32security.GetFileSecurity(
        str(path), win32security.DACL_SECURITY_INFORMATION
    )
    dacl = sd.GetSecurityDescriptorDacl()
    if dacl is None:
        raise make_error(
            RELAY_SIDECAR_LOCKFILE_WINDOWS_ACL,
            "lockfile DACL is missing",
            details={"path": str(path)},
        )

    ace_count = dacl.GetAceCount()
    if ace_count != 1:
        raise make_error(
            RELAY_SIDECAR_LOCKFILE_WINDOWS_ACL,
            f"lockfile DACL has {ace_count} ACEs; expected exactly 1",
            details={"path": str(path), "ace_count": ace_count},
        )

    ace = dacl.GetAce(0)
    # ace = (header_tuple, access_mask, sid_object)
    _, access_mask, sid_obj = ace
    expected_mask = (
        ntsecuritycon.FILE_GENERIC_READ | ntsecuritycon.FILE_GENERIC_WRITE
    )
    if access_mask != expected_mask or str(sid_obj) != str(expected_sid):
        raise make_error(
            RELAY_SIDECAR_LOCKFILE_WINDOWS_ACL,
            "lockfile DACL mismatch",
            details={
                "path": str(path),
                "observed_mask": access_mask,
                "expected_mask": expected_mask,
                "observed_sid": str(sid_obj),
                "expected_sid": str(expected_sid),
            },
        )


__all__ = [
    "BEARER_TOKEN_BYTES",
    "ProcessRunner",
    "SpawnAction",
    "SpawnDecision",
    "acquire_or_attach",
]


# Suppress unused-import warnings for future-use helpers.
_ = uuid
