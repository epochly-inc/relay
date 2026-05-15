"""``rly sidecar`` subcommands (W5.2 VAL-W5-008b/011..018).

Subcommand surface:

  * ``rly sidecar start``    -- VAL-W5-011: idempotent attach-or-spawn.
  * ``rly sidecar status``   -- VAL-W5-012: four-state classifier outcome.
  * ``rly sidecar stop``     -- VAL-W5-013: PID-only termination.
  * ``rly sidecar restart``  -- VAL-W5-014: bounded stop+start window.
  * ``rly sidecar install``  -- VAL-W5-015..018: pinned-URL bundle install
                                with digest + Sigstore verification, atomic
                                file write.

Per CLAUDE.md keystone invariants:

  * #3 manifest is source of truth: lifecycle commands NEVER kill processes
    by name. ``stop`` reads the PID from ``${RELAY_HOME}/sidecar.lock`` and
    delegates to :func:`relay_sidecar.process.terminate_pid` which is the
    sole sanctioned termination path. Name-based termination utilities
    (CLAUDE.md banned pattern #1) are forbidden in this module.
  * #8 atomic persistence: ``install`` writes the bundle bytes through
    :func:`relay_sidecar.primitives.local_atomic_file_write` (one of the
    four primitives). Direct ``open(install_path, 'wb')`` is banned.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

import httpx
import typer
from relay_sidecar.lockfile import (
    LockfileBody,
    parse_lockfile_body,
    relay_home,
    resolve_lockfile_path,
)
from relay_sidecar.process import pid_is_alive, terminate_pid
from relay_sidecar.spawn import acquire_or_attach

from ..bundle import (
    BundleInstallError,
    install_bundle,
)
from ..errors import build_envelope, emit_envelope
from ..exit_codes import (
    EXIT_4XX_AUTH_HANDOFF,
    EXIT_4XX_BLOCK,
    EXIT_CASSETTE_MISS,
    EXIT_CLI_USAGE,
    EXIT_SUCCESS,
)
from ..output import emit_json

# -----------------------------------------------------------------------------
# Schema-version constants (one per stdout JSON envelope shape)
# -----------------------------------------------------------------------------

SIDECAR_START_SCHEMA: Final[str] = "relay.cli.sidecar_start.v1"
SIDECAR_STATUS_SCHEMA: Final[str] = "relay.cli.sidecar_status.v1"
SIDECAR_STOP_SCHEMA: Final[str] = "relay.cli.sidecar_stop.v1"
SIDECAR_RESTART_SCHEMA: Final[str] = "relay.cli.sidecar_restart.v1"
SIDECAR_INSTALL_SCHEMA: Final[str] = "relay.cli.sidecar_install.v1"

# Bounded restart window. Per VAL-W5-014: failure to come back up within 5s
# exits 4 with RELAY-CLI-SIDECAR-RESTART-TIMEOUT. The default downtime
# budget is 5000ms; the value is configurable via --timeout-ms.
DEFAULT_RESTART_TIMEOUT_MS: Final[int] = 5000

# Health-check polling interval during restart wait.
RESTART_POLL_INTERVAL_S: Final[float] = 0.05

# Wire codes referenced verbatim from contract.md VAL-W5-014.
RELAY_CLI_SIDECAR_RESTART_TIMEOUT: Final[str] = "RELAY-CLI-SIDECAR-RESTART-TIMEOUT"

# Wire status states (per VAL-W5-012).
STATUS_RUNNING: Final[str] = "running"
STATUS_STOPPED: Final[str] = "stopped"
STATUS_STALE_LOCKFILE: Final[str] = "stale_lockfile"
STATUS_ORPHAN_PROCESS: Final[str] = "orphan_process"

# Spawn action wire values (mirrors relay_sidecar.spawn.SpawnAction).
ACTION_SPAWNED: Final[str] = "spawned"
ACTION_ATTACHED: Final[str] = "attached"
ACTION_STALE_PID_CLEARED: Final[str] = "stale_pid_cleared_and_spawned"
ACTION_ZOMBIE_PORT_TERMINATED: Final[str] = "zombie_port_terminated_and_spawned"

# Test-seam env vars: when set, the start/restart commands DO NOT actually
# fork uvicorn; they record the requested pid/port and return immediately.
# This keeps tier-1 plumbing tests deterministic without binding real ports
# or spawning real long-lived processes.
ENV_FAKE_SPAWN_PID: Final[str] = "RELAY_CLI_TEST_FAKE_SPAWN_PID"
ENV_FAKE_SPAWN_PORT: Final[str] = "RELAY_CLI_TEST_FAKE_SPAWN_PORT"


# -----------------------------------------------------------------------------
# Typer app construction
# -----------------------------------------------------------------------------


def build_sidecar_app() -> typer.Typer:
    """Construct the ``rly sidecar`` sub-Typer with all five commands wired.

    Returned as a function (not a module-level instance) so :mod:`relay_cli.main`
    can pass the same ``cls=`` Typer-group subclass it uses elsewhere when
    re-importing for tests. The default constructor here uses the standard
    Typer group so the module is import-safe without main's machinery.
    """
    app = typer.Typer(
        name="sidecar",
        help=(
            "Manage the local Relay sidecar: start, stop, status, restart, install. "
            "Lifecycle commands NEVER kill processes by name; PID is read from "
            "the sidecar lockfile."
        ),
        no_args_is_help=False,
        rich_markup_mode=None,
        add_completion=False,
        context_settings={"help_option_names": ["-h", "--help"]},
    )

    @app.callback(invoke_without_command=True)
    def _root(ctx: typer.Context) -> None:
        if ctx.invoked_subcommand is None:
            # No subcommand: emit the same not-implemented envelope main.py
            # used to ship for the stub. The new behavior shows help.
            from ..main import _emit_not_implemented  # local import: avoid cycle

            _emit_not_implemented("sidecar", "w5.2")

    app.command("start")(_cmd_start)
    app.command("status")(_cmd_status)
    app.command("stop")(_cmd_stop)
    app.command("restart")(_cmd_restart)
    app.command("install")(_cmd_install)
    return app


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------


def _now_rfc3339_z() -> str:
    """Return the current UTC time as an RFC 3339 ``Z`` string."""
    return (
        datetime.now(tz=UTC)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _read_lockfile_body(lockfile_path: Path) -> LockfileBody | None:
    """Read and parse the sidecar lockfile, or return None if absent/empty."""
    if not lockfile_path.exists() or lockfile_path.stat().st_size == 0:
        return None
    raw = lockfile_path.read_bytes()
    try:
        return parse_lockfile_body(raw)
    except Exception:
        # Malformed lockfile -- treat as not-attached for status purposes.
        # The caller decides whether to surface this via STATUS_STALE_LOCKFILE.
        return None


def _is_port_bound(port: int, host: str = "127.0.0.1") -> bool:
    """Return True if ``host:port`` accepts a TCP connect."""
    import socket

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.2)
    try:
        s.connect((host, port))
        return True
    except (ConnectionRefusedError, TimeoutError, OSError):
        return False
    finally:
        s.close()


def _emit_install_error(exc: BundleInstallError) -> int:
    """Emit a wire envelope for a bundle install failure and return exit code.

    Per the contract assertions:
      - VAL-W5-015 (RELAY-CLI-USAGE-014, forbidden --url) -> exit 64
        (CLI usage). The canonical exit-code mapper does not know the
        non-numeric token, so this branch is mapped explicitly.
      - VAL-W5-016 (RELAY-CLI-SIDECAR-SIGNATURE-INVALID) -> exit 1.
      - VAL-W5-017 (RELAY-CLI-SIDECAR-DIGEST-MISMATCH) -> exit 1.
      - All other install failures default to exit 1 (4xx block).
    """
    from ..bundle import RELAY_CLI_USAGE_014

    envelope = build_envelope(
        code=exc.code,
        http_status=exc.http_status,
        message=exc.message,
        blocked_surface="rly sidecar install",
        retry_advice="do_not_retry",
        details=exc.details,
    )
    emit_envelope(envelope)
    if exc.code == RELAY_CLI_USAGE_014:
        return EXIT_CLI_USAGE
    return EXIT_4XX_BLOCK


# -----------------------------------------------------------------------------
# rly sidecar start (VAL-W5-011)
# -----------------------------------------------------------------------------


def _fake_process_runner_or_default() -> Any:
    """Return a process runner honoring the test-seam env vars.

    When ``RELAY_CLI_TEST_FAKE_SPAWN_PID`` and ``..._PORT`` are set, returns
    a callable that yields the requested (pid, port) pair without binding
    a real socket or forking. Tests use this to drive the spawn pipeline
    deterministically.

    When unset, returns ``None`` so :func:`acquire_or_attach` falls through
    to its built-in :func:`_default_process_runner`. Production callers
    rely on this default; the W5.2 ship does NOT yet wire a forked
    ``run_uvicorn`` daemon (that lands when the SDK auto-spawn pattern is
    promoted to the CLI in a future feature).
    """
    pid_env = os.environ.get(ENV_FAKE_SPAWN_PID, "").strip()
    port_env = os.environ.get(ENV_FAKE_SPAWN_PORT, "").strip()
    if not pid_env or not port_env:
        return None
    try:
        pid_val = int(pid_env)
        port_val = int(port_env)
    except ValueError:
        return None
    if pid_val <= 0 or not (1 <= port_val <= 65535):
        return None

    def _fake_runner() -> tuple[int, int]:
        return pid_val, port_val

    return _fake_runner


def _cmd_start(
    home: str = typer.Option(
        "",
        "--home",
        help="Override RELAY_HOME (test seam).",
    ),
) -> None:
    """``rly sidecar start`` -- attach if running, else spawn (VAL-W5-011)."""
    base_home = Path(home).expanduser() if home else relay_home()
    runner = _fake_process_runner_or_default()
    decision = acquire_or_attach(home=base_home, process_runner=runner)
    body = decision.lockfile_body

    # All three spawn variants (spawned, stale_pid_cleared_and_spawned,
    # zombie_port_terminated_and_spawned) surface as the wire token "spawned"
    # so callers can distinguish without parsing the recovery-action enum.
    # The event_log already records the four-state recovery breakdown.
    wire_action = "attached" if decision.action == ACTION_ATTACHED else "spawned"

    payload: dict[str, Any] = {
        "schema_version": SIDECAR_START_SCHEMA,
        "action": wire_action,
        "pid": body.pid,
        "port": body.port,
        "sidecar_version": body.sidecar_version,
        "lockfile_path": str(resolve_lockfile_path(base_home)),
    }
    emit_json(payload)
    raise typer.Exit(code=EXIT_SUCCESS)


# -----------------------------------------------------------------------------
# rly sidecar status (VAL-W5-012)
# -----------------------------------------------------------------------------


def _classify_status(
    body: LockfileBody | None, lockfile_path: Path
) -> tuple[str, int]:
    """Return (state, exit_code) per the four-state classifier.

    Per VAL-W5-012:
      - "running" -> 0
      - "stopped" -> 1
      - "stale_lockfile" -> 3 (preconditions not met)
      - "orphan_process" -> 3
    """
    if body is None:
        # No lockfile (or malformed). Either NO_LOCKFILE or a partially
        # written one. Surface as "stopped" if the file doesn't exist;
        # surface as "stale_lockfile" if the file exists but parsed empty.
        if not lockfile_path.exists() or lockfile_path.stat().st_size == 0:
            return STATUS_STOPPED, EXIT_4XX_BLOCK
        return STATUS_STALE_LOCKFILE, EXIT_4XX_AUTH_HANDOFF  # exit 3
    pid_alive = pid_is_alive(body.pid)
    port_bound = _is_port_bound(body.port)
    if pid_alive and port_bound:
        return STATUS_RUNNING, EXIT_SUCCESS
    if not pid_alive:
        # Lockfile records a dead PID -> stale_lockfile, exit 3.
        return STATUS_STALE_LOCKFILE, EXIT_4XX_AUTH_HANDOFF
    # PID alive but port unbound -> orphan_process, exit 3.
    return STATUS_ORPHAN_PROCESS, EXIT_4XX_AUTH_HANDOFF


def _cmd_status(
    home: str = typer.Option(
        "",
        "--home",
        help="Override RELAY_HOME (test seam).",
    ),
) -> None:
    """``rly sidecar status`` -- four-state classifier outcome (VAL-W5-012)."""
    base_home = Path(home).expanduser() if home else relay_home()
    base_home.mkdir(parents=True, exist_ok=True)
    lockfile_path = resolve_lockfile_path(base_home)
    body = _read_lockfile_body(lockfile_path)
    state, exit_code = _classify_status(body, lockfile_path)

    uptime_seconds: int | None = None
    if body is not None and state == STATUS_RUNNING:
        try:
            launched_dt = datetime.fromisoformat(
                body.launched_at.replace("Z", "+00:00")
            )
            uptime_seconds = max(
                0, int((datetime.now(tz=UTC) - launched_dt).total_seconds())
            )
        except (ValueError, AttributeError):
            uptime_seconds = None

    payload: dict[str, Any] = {
        "schema_version": SIDECAR_STATUS_SCHEMA,
        "state": state,
        "pid": body.pid if body is not None else None,
        "port": body.port if body is not None else None,
        "sidecar_version": body.sidecar_version if body is not None else None,
        "uptime_seconds": uptime_seconds,
        "lockfile_path": str(lockfile_path),
    }
    emit_json(payload)
    raise typer.Exit(code=exit_code)


# -----------------------------------------------------------------------------
# rly sidecar stop (VAL-W5-013)
# -----------------------------------------------------------------------------


def _cmd_stop(
    home: str = typer.Option(
        "",
        "--home",
        help="Override RELAY_HOME (test seam).",
    ),
    quiesce_timeout_seconds: float = typer.Option(
        5.0,
        "--timeout",
        help="Seconds to wait for graceful exit before SIGKILL (POSIX).",
    ),
) -> None:
    """``rly sidecar stop`` -- PID-only termination (VAL-W5-013)."""
    base_home = Path(home).expanduser() if home else relay_home()
    lockfile_path = resolve_lockfile_path(base_home)
    body = _read_lockfile_body(lockfile_path)
    if body is None:
        # No lockfile or malformed: nothing to stop. Surface a structured
        # "no-op" result; exit 0 because absence of a sidecar is the
        # post-condition the user requested.
        payload: dict[str, Any] = {
            "schema_version": SIDECAR_STOP_SCHEMA,
            "action": "noop",
            "pid": None,
            "port": None,
            "lockfile_path": str(lockfile_path),
        }
        emit_json(payload)
        raise typer.Exit(code=EXIT_SUCCESS)

    pid = body.pid
    if not pid_is_alive(pid):
        payload = {
            "schema_version": SIDECAR_STOP_SCHEMA,
            "action": "already_stopped",
            "pid": pid,
            "port": body.port,
            "lockfile_path": str(lockfile_path),
        }
        emit_json(payload)
        raise typer.Exit(code=EXIT_SUCCESS)

    # PID-only termination via the sanctioned helper. Name-based termination
    # utilities (CLAUDE.md banned pattern #1) are forbidden in this module.
    success = terminate_pid(pid, timeout_s=float(quiesce_timeout_seconds))
    payload = {
        "schema_version": SIDECAR_STOP_SCHEMA,
        "action": "stopped" if success else "stop_failed",
        "pid": pid,
        "port": body.port,
        "lockfile_path": str(lockfile_path),
    }
    emit_json(payload)
    raise typer.Exit(code=EXIT_SUCCESS if success else EXIT_4XX_BLOCK)


# -----------------------------------------------------------------------------
# rly sidecar restart (VAL-W5-014)
# -----------------------------------------------------------------------------


def _wait_for_health(
    base_url: str,
    *,
    timeout_ms: int,
    bearer_digest: str,
) -> bool:
    """Poll ``${base_url}/health`` until 200 or ``timeout_ms`` elapses.

    Uses a short-lived httpx client. Returns True on first 200 response,
    False if the deadline elapsed without success.
    """
    deadline = time.monotonic() + (timeout_ms / 1000.0)
    headers = {"X-Relay-Bearer-Digest": bearer_digest}
    with httpx.Client(timeout=httpx.Timeout(1.0)) as client:
        while time.monotonic() < deadline:
            try:
                resp = client.get(f"{base_url}/health", headers=headers)
                if resp.status_code == 200:
                    return True
            except httpx.HTTPError:
                pass
            time.sleep(RESTART_POLL_INTERVAL_S)
    return False


def _cmd_restart(
    home: str = typer.Option(
        "",
        "--home",
        help="Override RELAY_HOME (test seam).",
    ),
    timeout_ms: int = typer.Option(
        DEFAULT_RESTART_TIMEOUT_MS,
        "--timeout-ms",
        help="Maximum downtime in ms before RELAY-CLI-SIDECAR-RESTART-TIMEOUT.",
    ),
) -> None:
    """``rly sidecar restart`` -- bounded stop+start (VAL-W5-014)."""
    base_home = Path(home).expanduser() if home else relay_home()
    lockfile_path = resolve_lockfile_path(base_home)
    body = _read_lockfile_body(lockfile_path)
    previous_pid: int | None = body.pid if body is not None else None

    started_at = time.monotonic()
    runner = _fake_process_runner_or_default()
    # Step 1: stop (best-effort; absent sidecar -> immediate spawn). When the
    # fake-spawn test seam is active the lockfile records a synthetic PID
    # (typically the test runner's own); calling ``terminate_pid`` on it
    # would kill the test process. Skip the terminate step under the seam
    # and rely on ``acquire_or_attach``'s ZOMBIE_PORT/STALE_PID branches to
    # advance the state.
    if runner is None and body is not None and pid_is_alive(body.pid):
        terminate_pid(body.pid, timeout_s=min(5.0, timeout_ms / 1000.0))

    # Step 2: spawn fresh via acquire_or_attach.
    decision = acquire_or_attach(home=base_home, process_runner=runner)
    new_body = decision.lockfile_body
    new_pid = new_body.pid

    # Step 3: bounded health wait. Skipped when the test seam pid+port are
    # used (they don't actually bind a socket); detect the test seam via
    # the env vars and fast-path success.
    if runner is not None:
        downtime_ms = int((time.monotonic() - started_at) * 1000)
    else:
        # Production path: poll the new sidecar's /health.
        ok = _wait_for_health(
            f"http://127.0.0.1:{new_body.port}",
            timeout_ms=timeout_ms,
            bearer_digest=new_body.bearer_token_digest,
        )
        downtime_ms = int((time.monotonic() - started_at) * 1000)
        if not ok or downtime_ms > timeout_ms:
            envelope = build_envelope(
                code=RELAY_CLI_SIDECAR_RESTART_TIMEOUT,
                http_status=504,
                message=(
                    f"sidecar did not answer /health within {timeout_ms}ms after restart"
                ),
                blocked_surface="rly sidecar restart",
                retry_advice="after_fix",
                details={
                    "previous_pid": previous_pid,
                    "new_pid": new_pid,
                    "downtime_ms": downtime_ms,
                    "timeout_ms": timeout_ms,
                },
            )
            emit_envelope(envelope)
            raise typer.Exit(code=EXIT_CASSETTE_MISS)  # exit 4 per VAL-W5-014

    payload: dict[str, Any] = {
        "schema_version": SIDECAR_RESTART_SCHEMA,
        "action": "restarted",
        "previous_pid": previous_pid,
        "new_pid": new_pid,
        "port": new_body.port,
        "downtime_ms": downtime_ms,
        "lockfile_path": str(lockfile_path),
    }
    emit_json(payload)
    raise typer.Exit(code=EXIT_SUCCESS)


# -----------------------------------------------------------------------------
# rly sidecar install (VAL-W5-015..018)
# -----------------------------------------------------------------------------


def _cmd_install(
    home: str = typer.Option(
        "",
        "--home",
        help="Override RELAY_HOME (test seam).",
    ),
    manifest: str = typer.Option(
        "",
        "--manifest",
        help=(
            "Override the pinned manifest path (test seam). Production uses "
            "packages/cli/src/sidecar_install/bundle_manifest.json."
        ),
    ),
) -> None:
    """``rly sidecar install`` -- pinned-URL install with verification.

    VAL-W5-015: refuses any URL not present in the pinned manifest. The CLI
    intentionally does NOT expose a ``--url`` flag.
    VAL-W5-016: Sigstore signature is verified before the bundle is moved.
    VAL-W5-017: SHA-256 digest is verified independently before signature.
    VAL-W5-018: install path is written through ``local_atomic_file_write``.
    """
    base_home = Path(home).expanduser() if home else relay_home()
    manifest_path = Path(manifest).expanduser() if manifest else None
    try:
        result = install_bundle(
            home=base_home,
            manifest_path=manifest_path,
        )
    except BundleInstallError as exc:
        code = _emit_install_error(exc)
        raise typer.Exit(code=code) from exc

    payload: dict[str, Any] = {
        "schema_version": SIDECAR_INSTALL_SCHEMA,
        "action": "installed",
        "sidecar_version": result.sidecar_version,
        "install_path": str(result.install_path),
        "bundle_url": result.bundle_url,
        "bundle_digest": result.bundle_digest,
        "host_os": result.host_os,
        "host_arch": result.host_arch,
        "trust_root": result.trust_root,
        "bytes_written": result.bytes_written,
    }
    emit_json(payload)
    raise typer.Exit(code=EXIT_SUCCESS)


__all__ = [
    "ACTION_ATTACHED",
    "ACTION_SPAWNED",
    "DEFAULT_RESTART_TIMEOUT_MS",
    "ENV_FAKE_SPAWN_PID",
    "ENV_FAKE_SPAWN_PORT",
    "RELAY_CLI_SIDECAR_RESTART_TIMEOUT",
    "SIDECAR_INSTALL_SCHEMA",
    "SIDECAR_RESTART_SCHEMA",
    "SIDECAR_START_SCHEMA",
    "SIDECAR_STATUS_SCHEMA",
    "SIDECAR_STOP_SCHEMA",
    "STATUS_ORPHAN_PROCESS",
    "STATUS_RUNNING",
    "STATUS_STALE_LOCKFILE",
    "STATUS_STOPPED",
    "build_sidecar_app",
]


# Suppress unused-import for subprocess/sys (kept for later wiring).
_ = subprocess
_ = sys
