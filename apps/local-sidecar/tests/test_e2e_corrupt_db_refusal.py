"""End-to-end VAL-W2-051: corrupt SQLite refuses startup at the production surface.

This test bypasses the W2.7 unit-level helpers in
``test_corrupted_db_refusal.py`` (which monkeypatch
``recovery.exit_with_structured_error``) and instead spawns a real
sidecar subprocess via ``relay_sidecar.runtime.run_uvicorn``. The
subprocess hits the wired ``recover_or_refuse`` call BEFORE entering the
asyncio loop, observes corruption, calls ``sys.exit(3)``, and the parent
test asserts the structured envelope on stderr + exit code 3.

This is the STR-001 verification that
``recover_or_refuse`` is actually invoked by the production startup path
(runtime.run_uvicorn + the lifespan probe), not just by direct unit
tests of the helper. Without the wiring, the subprocess would proceed
to ``SidecarDatabase.open()`` against a corrupt file and fail with an
sqlite OperationalError (no structured envelope, wrong exit code).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import contextlib
import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

_SUBPROCESS_SCRIPT = textwrap.dedent(
    """
    import sys
    from pathlib import Path

    sys.path.insert(0, sys.argv[1])
    sys.path.insert(0, sys.argv[2])

    from relay_sidecar.health import HealthState
    from relay_sidecar.runtime import run_uvicorn

    relay_home = Path(sys.argv[3])
    db_path = Path(sys.argv[4])
    health = HealthState(
        port=0,
        bearer_token="t-test-token",
        bearer_token_digest=(
            "sha256-0000000000000000000000000000000000000000000000000000000000000000"
        ),
    )
    # run_uvicorn synchronously calls recover_or_refuse BEFORE entering
    # the asyncio loop. On a corrupt DB, recovery emits the JSON envelope
    # to stderr and sys.exit(3). The exit code propagates through the
    # Python interpreter unmolested.
    run_uvicorn(
        health=health,
        host="127.0.0.1",
        port=0,
        sqlite_path=db_path,
        relay_home_override=relay_home,
    )
    """
).strip()


def _seed_corrupted_db(db_path: Path) -> None:
    """Write SQLite-magic-prefixed garbage that quick_check rejects."""
    db_path.write_bytes(b"SQLite format 3\x00" + b"\xff" * 200)


def _spawn_sidecar_subprocess(
    *,
    relay_home: Path,
    db_path: Path,
    timeout_s: float = 30.0,
) -> tuple[int, str, str]:
    """Spawn the sidecar via run_uvicorn; return (returncode, stdout, stderr).

    The subprocess invokes ``run_uvicorn`` directly. On the corruption
    path, the recovery probe sys.exit(3) before uvicorn binds any port,
    so the subprocess returns quickly. ``timeout_s`` is the upper bound
    on how long we wait for the corruption-refusal exit.

    No monkey-patching of ``exit_with_structured_error`` happens here:
    the subprocess executes the production ``sys.exit`` path verbatim.
    """
    repo_root = Path(__file__).resolve().parents[3]
    pkg_root = repo_root / "apps" / "local-sidecar"
    schemas_root = repo_root / "packages" / "schemas" / "python"

    proc = subprocess.Popen(
        [
            sys.executable,
            "-c",
            _SUBPROCESS_SCRIPT,
            str(pkg_root),
            str(schemas_root),
            str(relay_home),
            str(db_path),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout_s)
    except subprocess.TimeoutExpired as e:
        # The PID came from this process's own subprocess.Popen; we kill
        # by THAT PID via proc.kill (which uses os.kill internally on the
        # captured pid). NEVER name-based.
        proc.kill()
        with contextlib.suppress(subprocess.TimeoutExpired):
            stdout, stderr = proc.communicate(timeout=5.0)
        raise AssertionError(
            f"sidecar subprocess did not exit within {timeout_s}s on a corrupt DB"
        ) from e
    return proc.returncode, stdout, stderr


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-051")
def test_e2e_corrupt_db_subprocess_exits_3_with_structured_envelope(
    tmp_path: Path,
) -> None:
    """Real subprocess: corrupt DB -> exit 3 + RELAY-SIDECAR-DB-CORRUPT on stderr."""
    relay_home = tmp_path / "relay-home"
    relay_home.mkdir(parents=True, exist_ok=True)
    db_path = relay_home / "sidecar.db"
    _seed_corrupted_db(db_path)
    db_size_before = db_path.stat().st_size

    returncode, stdout, stderr = _spawn_sidecar_subprocess(
        relay_home=relay_home,
        db_path=db_path,
    )

    assert returncode == 3, (
        f"VAL-W2-051: corrupt DB sidecar must exit 3; observed rc={returncode}\n"
        f"stdout={stdout!r}\nstderr={stderr!r}"
    )

    # The structured envelope is the LAST single-line JSON object on stderr.
    # uvicorn / asyncio may print prelude noise, but recovery's envelope is
    # the last newline-terminated JSON line emitted before sys.exit.
    envelope_lines = [
        line.strip()
        for line in stderr.splitlines()
        if line.strip().startswith("{") and line.strip().endswith("}")
    ]
    assert envelope_lines, (
        f"VAL-W2-051: stderr must carry the JSON envelope; got: {stderr!r}"
    )
    envelope = json.loads(envelope_lines[-1])
    assert envelope["code"] == "RELAY-SIDECAR-010", envelope
    assert envelope["error_class"] == "RELAY-SIDECAR-DB-CORRUPT", envelope
    assert "integrity_check" in envelope["details"], envelope
    assert envelope["details"]["db_path"] == str(db_path), envelope

    # The recovery path MUST NOT clobber the corrupt DB file.
    db_size_after = db_path.stat().st_size
    assert db_size_after == db_size_before, (
        f"VAL-W2-051: recovery clobbered the DB file: "
        f"before={db_size_before} after={db_size_after}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-051")
def test_e2e_corrupt_db_subprocess_does_not_open_aiosqlite_connection(
    tmp_path: Path,
) -> None:
    """Recovery sys.exit BEFORE SidecarDatabase.open: no -wal sibling appears.

    Production wiring guarantees ``recover_or_refuse`` runs synchronously
    BEFORE ``SidecarDatabase`` is constructed. If the wiring regressed
    and aiosqlite opened the corrupt file, SQLite would create the
    ``<db>-wal`` sibling on the WAL-mode connection. We assert the
    sibling never materialises as positive evidence the wiring held.
    """
    relay_home = tmp_path / "relay-home"
    relay_home.mkdir(parents=True, exist_ok=True)
    db_path = relay_home / "sidecar.db"
    _seed_corrupted_db(db_path)

    returncode, _stdout, _stderr = _spawn_sidecar_subprocess(
        relay_home=relay_home,
        db_path=db_path,
    )
    assert returncode == 3, returncode
    wal_sibling = db_path.parent / (db_path.name + "-wal")
    shm_sibling = db_path.parent / (db_path.name + "-shm")
    assert not wal_sibling.exists(), (
        "VAL-W2-051: sidecar opened the corrupt DB despite recovery wiring; "
        f"-wal sibling appeared at {wal_sibling}"
    )
    assert not shm_sibling.exists(), (
        "VAL-W2-051: sidecar opened the corrupt DB despite recovery wiring; "
        f"-shm sibling appeared at {shm_sibling}"
    )
