"""VAL-W3-006: SDK auto-spawn race is serialized via portalocker.

Ten simultaneous first-operation calls -- separate OS processes, all
calling ``Relay(...).trace(...)`` for the first time against the SAME
``RELAY_HOME`` -- MUST result in exactly ONE ``sidecar.spawned`` event_log
row and NINE ``sidecar.attached`` rows, and all ten subprocesses MUST exit
0.

The serialization itself is provided by ``relay_sidecar.spawn``'s
portalocker exclusive decision lock (cross-links W2 VAL-W2-006); this test
proves the SDK auto-spawn path inherits that guarantee end to end.

Separate OS processes (not threads) are required: the file lock is a
cross-process primitive.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest
from relay_sidecar.event_log import count_events

_VALID_KEY = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
_N_WORKERS = 10

# Each worker subprocess: wait on a file-based barrier until all N workers
# are present (widening the race window), then construct a Relay client
# and call trace(). Print the resulting connection's pid/port + whether it
# spawned as JSON on stdout. Exit 0 on success, non-zero on any exception.
_WORKER_SCRIPT = textwrap.dedent(
    """
    import json
    import sys
    import time
    from pathlib import Path

    for _p in json.loads(sys.argv[1]):
        if _p:
            sys.path.insert(0, _p)

    relay_home = Path(sys.argv[2])
    barrier_path = Path(sys.argv[3])
    n_workers = int(sys.argv[4])
    project_key = sys.argv[5]

    # File-based barrier: append our marker, then wait for all N markers.
    with open(barrier_path, "a", encoding="utf-8") as f:
        f.write("x\\n")
    deadline = time.monotonic() + 15.0
    while time.monotonic() < deadline:
        try:
            n = len(barrier_path.read_text(encoding="utf-8").splitlines())
        except OSError:
            n = 0
        if n >= n_workers:
            break
        time.sleep(0.01)

    try:
        from relay import Relay
        r = Relay(project_key=project_key, relay_home=relay_home)
        conn = r.trace("race-op")
        out = {
            "ok": True,
            "pid": conn.pid,
            "port": conn.port,
            "spawned": conn.spawned,
        }
        sys.stdout.write(json.dumps(out))
        sys.stdout.flush()
        # Keep the client (and its httpx pool) alive briefly so peers can
        # finish their /health attaches against the live sidecar.
        time.sleep(2.0)
        r.close()
    except BaseException as e:
        sys.stdout.write(json.dumps({"ok": False, "error": repr(e)}))
        sys.stdout.flush()
        sys.exit(1)
    """
).strip()


def _sys_path_arg() -> str:
    """JSON-encode sys.path: argv elements cannot contain a NUL byte."""
    return json.dumps(list(sys.path))


def _stop_sidecar(relay_home: Path) -> None:
    """SIGTERM the lockfile-recorded sidecar PID (PID-only, never by name)."""
    lockfile = relay_home / "sidecar.lock"
    if not lockfile.exists() or lockfile.stat().st_size == 0:
        return
    try:
        body = json.loads(lockfile.read_text(encoding="utf-8"))
        pid = int(body["pid"])
    except (OSError, json.JSONDecodeError, KeyError, ValueError, TypeError):
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError, OSError):
        return
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except (ProcessLookupError, OSError):
            return
        time.sleep(0.05)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-006")
def test_ten_concurrent_first_ops_yield_one_spawn_nine_attach(
    tmp_path: Path,
) -> None:
    """10 concurrent first-ops: exactly 1 spawn, 9 attach, all exit 0."""
    relay_home = tmp_path / "relay-home"
    relay_home.mkdir(parents=True, exist_ok=True)
    barrier_path = tmp_path / "barrier"

    env = dict(os.environ)
    env["RELAY_HOME"] = str(relay_home)
    env.pop("RELAY_NO_AUTOSPAWN", None)

    procs: list[subprocess.Popen[str]] = []
    try:
        for _ in range(_N_WORKERS):
            procs.append(
                subprocess.Popen(
                    [
                        sys.executable,
                        "-c",
                        _WORKER_SCRIPT,
                        _sys_path_arg(),
                        str(relay_home),
                        str(barrier_path),
                        str(_N_WORKERS),
                        _VALID_KEY,
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    env=env,
                )
            )

        results: list[dict] = []
        exit_codes: list[int] = []
        for proc in procs:
            stdout, stderr = proc.communicate(timeout=90)
            exit_codes.append(proc.returncode)
            assert proc.returncode == 0, (
                f"worker exited {proc.returncode}\n"
                f"stdout={stdout!r}\nstderr={stderr!r}"
            )
            results.append(json.loads(stdout.strip()))
    finally:
        for proc in procs:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)
        _stop_sidecar(relay_home)

    # All ten workers succeeded.
    assert len(results) == _N_WORKERS
    assert all(r["ok"] for r in results)
    assert all(code == 0 for code in exit_codes)

    # Exactly one worker reports spawned=True; nine report spawned=False.
    spawned_flags = [r["spawned"] for r in results]
    assert spawned_flags.count(True) == 1, (
        f"expected exactly 1 spawning worker, got {spawned_flags.count(True)}"
    )
    assert spawned_flags.count(False) == _N_WORKERS - 1

    # All ten workers converged on the SAME sidecar pid + port.
    pids = {r["pid"] for r in results}
    ports = {r["port"] for r in results}
    assert len(pids) == 1, f"workers saw multiple sidecar pids: {pids}"
    assert len(ports) == 1, f"workers saw multiple sidecar ports: {ports}"

    # The event log: exactly one sidecar.spawned, exactly nine sidecar.attached.
    spawned = count_events("sidecar.spawned", home=relay_home)
    attached = count_events("sidecar.attached", home=relay_home)
    assert spawned == 1, f"expected 1 sidecar.spawned row, got {spawned}"
    assert attached == _N_WORKERS - 1, (
        f"expected {_N_WORKERS - 1} sidecar.attached rows, got {attached}"
    )
