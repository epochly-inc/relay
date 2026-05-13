"""W2.6 force-stop CLI helper for the local sidecar.

Reads the PID from the lockfile (NEVER by process name; CLAUDE.md
process safety + spec H.5 + manifest service.local-sidecar.pid_source)
and sends the platform-native force-stop signal:

  - POSIX: SIGUSR1 (the sidecar's lifespan installs a loop-bound
    handler that runs the force-stop path: emit one
    ``sidecar.forced_stop`` event_log row BEFORE killing the
    in-flight transaction; lockfile NOT cleared so next spawn
    classifies STALE_PID).
  - Windows: SIGTERM (no SIGUSR1 on Windows; degrades to graceful
    drain). The W5 CLI surfaces a warning when force-stop is invoked
    on Windows so users know they're getting graceful drain
    semantics, NOT post-mortem forensic semantics.

Usage::

    python -m relay_sidecar.scripts.force_stop [--home /path/to/relay-home]

Exit codes::

    0 -- signal sent successfully (process was alive at signal time)
    1 -- lockfile missing or unreadable
    2 -- lockfile body malformed
    3 -- recorded PID is not alive (sidecar already exited)
    4 -- signal delivery failed for any other reason

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from relay_sidecar.errors import SidecarError
from relay_sidecar.lockfile import parse_lockfile_body, resolve_lockfile_path
from relay_sidecar.process import pid_is_alive
from relay_sidecar.quiesce import force_stop_signal_number


def force_stop(*, home: Path | None = None) -> int:
    """Send the force-stop signal to the sidecar named by the lockfile.

    Args:
        home: Override the relay-home directory. Defaults to
            ``${RELAY_HOME}`` or ``~/.relay``.

    Returns:
        Process exit code per the module-level docstring contract.
    """
    lockfile_path = resolve_lockfile_path(home)
    if not lockfile_path.exists():
        sys.stderr.write(
            f"force_stop: lockfile missing at {lockfile_path}; "
            "no sidecar to stop\n"
        )
        return 1
    try:
        raw = lockfile_path.read_bytes()
    except OSError as e:
        sys.stderr.write(f"force_stop: cannot read lockfile {lockfile_path}: {e}\n")
        return 1
    try:
        body = parse_lockfile_body(raw)
    except SidecarError as e:
        sys.stderr.write(f"force_stop: lockfile malformed: {e}\n")
        return 2
    pid = body.pid
    if not pid_is_alive(pid):
        sys.stderr.write(
            f"force_stop: recorded PID {pid} is not alive; "
            "sidecar already exited\n"
        )
        return 3
    signum = force_stop_signal_number()
    try:
        os.kill(pid, signum)
    except OSError as e:
        sys.stderr.write(
            f"force_stop: signal {signum} delivery to PID {pid} failed: {e}\n"
        )
        return 4
    sys.stdout.write(
        f"force_stop: signal {signum} sent to PID {pid} "
        f"(sidecar version {body.sidecar_version})\n"
    )
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="relay-sidecar-force-stop",
        description=(
            "Send the platform-native force-stop signal to the local "
            "sidecar named by the lockfile. NEVER kills by process "
            "name; only by PID recorded in the lockfile."
        ),
    )
    parser.add_argument(
        "--home",
        type=Path,
        default=None,
        help=(
            "Override the relay-home directory; defaults to "
            "${RELAY_HOME} or ~/.relay."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    ns = parser.parse_args(argv)
    return force_stop(home=ns.home)


if __name__ == "__main__":  # pragma: no cover (subprocess-only entrypoint)
    sys.exit(main())
