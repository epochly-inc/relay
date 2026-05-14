"""End-to-end VAL-W2-054: schema-version mismatch refuses startup at production surface.

This test seeds a SQLite db file carrying an unknown
``_sidecar_schema_version.version`` value, spawns a real sidecar
subprocess via ``run_uvicorn``, and asserts the subprocess exits with
code 5 carrying the structured ``RELAY-SIDECAR-SCHEMA-VERSION-UNKNOWN``
envelope on stderr.

This is the STR-001 verification that ``recover_or_refuse``'s
schema-version branch is wired into production startup, not just into
unit tests of the helper. Without the wiring the subprocess would
proceed to ``SidecarDatabase.open`` -> migrations runner, which on
SQLite has no built-in version-mismatch refusal and would silently
re-apply migrations against an unexpected schema state.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import contextlib
import json
import sqlite3
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
from relay_sidecar.recovery import SUPPORTED_SCHEMA_VERSION

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
    run_uvicorn(
        health=health,
        host="127.0.0.1",
        port=0,
        sqlite_path=db_path,
        relay_home_override=relay_home,
    )
    """
).strip()


def _seed_db_with_unknown_schema_version(db_path: Path, version: int) -> None:
    """Create a minimal valid DB carrying ``_sidecar_schema_version.version=<version>``."""
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS _sidecar_schema_version ("
            "  id INTEGER PRIMARY KEY CHECK (id = 0), "
            "  version INTEGER NOT NULL CHECK (version > 0), "
            "  installed_at TEXT NOT NULL"
            ")"
        )
        conn.execute(
            "INSERT OR REPLACE INTO _sidecar_schema_version (id, version, installed_at) "
            "VALUES (0, ?, '2026-05-13T00:00:00.000000Z')",
            (version,),
        )
        conn.commit()
    finally:
        conn.close()


def _spawn_sidecar_subprocess(
    *,
    relay_home: Path,
    db_path: Path,
    timeout_s: float = 30.0,
) -> tuple[int, str, str]:
    """Spawn run_uvicorn; return (returncode, stdout, stderr)."""
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
        proc.kill()
        with contextlib.suppress(subprocess.TimeoutExpired):
            stdout, stderr = proc.communicate(timeout=5.0)
        raise AssertionError(
            f"sidecar subprocess did not exit within {timeout_s}s on schema mismatch"
        ) from e
    return proc.returncode, stdout, stderr


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-054")
def test_e2e_unknown_schema_version_subprocess_exits_5_with_envelope(
    tmp_path: Path,
) -> None:
    """Real subprocess: unknown schema_version -> exit 5 + RELAY-SIDECAR-SCHEMA-VERSION-UNKNOWN."""
    relay_home = tmp_path / "relay-home"
    relay_home.mkdir(parents=True, exist_ok=True)
    db_path = relay_home / "sidecar.db"
    unknown_version = SUPPORTED_SCHEMA_VERSION + 100
    _seed_db_with_unknown_schema_version(db_path, unknown_version)

    returncode, stdout, stderr = _spawn_sidecar_subprocess(
        relay_home=relay_home,
        db_path=db_path,
    )
    assert returncode == 5, (
        f"VAL-W2-054: schema-version-mismatch sidecar must exit 5; "
        f"observed rc={returncode}\nstdout={stdout!r}\nstderr={stderr!r}"
    )

    envelope_lines = [
        line.strip()
        for line in stderr.splitlines()
        if line.strip().startswith("{") and line.strip().endswith("}")
    ]
    assert envelope_lines, (
        f"VAL-W2-054: stderr must carry the JSON envelope; got: {stderr!r}"
    )
    envelope = json.loads(envelope_lines[-1])
    assert envelope["code"] == "RELAY-SIDECAR-013", envelope
    assert envelope["error_class"] == "RELAY-SIDECAR-SCHEMA-VERSION-UNKNOWN", envelope
    details = envelope["details"]
    assert details["observed_version"] == unknown_version, details
    assert details["supported_version"] == SUPPORTED_SCHEMA_VERSION, details
    assert details["db_path"] == str(db_path), details


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-054")
def test_e2e_unknown_schema_version_subprocess_does_not_clobber_db(
    tmp_path: Path,
) -> None:
    """Recovery refusal MUST NOT mutate the on-disk DB file."""
    relay_home = tmp_path / "relay-home"
    relay_home.mkdir(parents=True, exist_ok=True)
    db_path = relay_home / "sidecar.db"
    unknown_version = SUPPORTED_SCHEMA_VERSION + 100
    _seed_db_with_unknown_schema_version(db_path, unknown_version)

    sha_before = db_path.read_bytes()

    returncode, _stdout, _stderr = _spawn_sidecar_subprocess(
        relay_home=relay_home,
        db_path=db_path,
    )
    assert returncode == 5, returncode
    sha_after = db_path.read_bytes()
    assert sha_after == sha_before, (
        "VAL-W2-054: recovery refusal mutated the DB file"
    )

    # Re-read the schema_version row directly to prove it is unchanged.
    conn = sqlite3.connect(str(db_path))
    try:
        cur = conn.execute(
            "SELECT version FROM _sidecar_schema_version WHERE id = 0"
        )
        row = cur.fetchone()
    finally:
        conn.close()
    assert row is not None and int(row[0]) == unknown_version
