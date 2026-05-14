"""End-to-end VAL-W2-050: orphan partial lockfile cleared at the production surface.

This test seeds an orphan ``<lockfile>.<random>`` tempfile in the
relay-home directory and invokes ``acquire_or_attach`` in a real
subprocess (NOT via direct helper calls in-process). The subprocess
exercises the production wiring landed by the STR-001 fix:
``spawn.acquire_or_attach`` now invokes ``recover_partial_lockfile``
BEFORE the four-state classifier runs.

Without the wiring, the orphan would persist on disk and the classifier
would still operate on the canonical lockfile (which is initially
missing) -- BUT the orphan accumulates across restarts and is the
on-disk signal that the prior run died between fsync and rename. The
test asserts the orphan is unconditionally cleared, the canonical
lockfile is written by the spawn path, and no
``RELAY-SIDECAR-LOCKFILE-MALFORMED`` error escapes.

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
    import json
    import os
    import sys
    from pathlib import Path

    sys.path.insert(0, sys.argv[1])
    sys.path.insert(0, sys.argv[2])

    relay_home = Path(sys.argv[3])
    os.environ["RELAY_HOME"] = str(relay_home)

    from relay_sidecar.lockfile import resolve_lockfile_path
    from relay_sidecar.spawn import acquire_or_attach

    lockfile_path = resolve_lockfile_path(relay_home)

    def _enumerate_siblings():
        # Return every sibling of the lockfile whose name starts with
        # ``<lockfile>.`` (the mkstemp prefix). The canonical lockfile
        # itself is excluded.
        return sorted(
            str(p)
            for p in lockfile_path.parent.iterdir()
            if p.name != lockfile_path.name
            and p.name.startswith(lockfile_path.name + ".")
        )

    pre_orphans = _enumerate_siblings()

    # Run the full acquire_or_attach flow with a deterministic
    # process_runner returning (os.getpid(), 50061). The four-state
    # classifier should see NO_LOCKFILE (the canonical lockfile is
    # absent), spawn, write the canonical lockfile, return action=spawned.
    decision = acquire_or_attach(
        home=relay_home,
        process_runner=lambda: (os.getpid(), 50061),
    )
    post_orphans = _enumerate_siblings()
    lockfile_after = lockfile_path.read_bytes().decode("utf-8")

    sys.stdout.write(
        json.dumps(
            {
                "action": decision.action,
                "pre_orphans": pre_orphans,
                "post_orphans": post_orphans,
                "canonical_lockfile_exists": lockfile_path.exists(),
                "canonical_lockfile_size": lockfile_path.stat().st_size,
                "lockfile_after_json": lockfile_after,
            }
        )
    )
    """
).strip()


def _spawn_acquire_or_attach_subprocess(
    *,
    relay_home: Path,
    timeout_s: float = 30.0,
) -> tuple[int, str, str]:
    """Spawn the acquire_or_attach probe; return (returncode, stdout, stderr).

    No monkey-patching of recovery happens here. The subprocess runs the
    production ``acquire_or_attach`` code path verbatim.
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
            f"acquire_or_attach subprocess did not exit within {timeout_s}s"
        ) from e
    return proc.returncode, stdout, stderr


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-050")
def test_e2e_partial_lockfile_subprocess_clears_orphan_and_respawns_clean(
    tmp_path: Path,
) -> None:
    """Orphan ``.tmp`` -> subprocess clears it -> canonical spawn proceeds."""
    relay_home = tmp_path / "relay-home"
    relay_home.mkdir(parents=True, exist_ok=True)
    lockfile_name = "sidecar.lock"
    # Seed a malformed orphan tempfile mimicking an interrupted atomic
    # rename. The bytes are intentionally NOT valid JSON to prove no
    # RELAY-SIDECAR-LOCKFILE-MALFORMED escapes.
    orphan_path = relay_home / (lockfile_name + ".XYZ987-malformed")
    orphan_path.write_bytes(b"{partial-write-marker malformed bytes")
    assert orphan_path.exists()

    returncode, stdout, stderr = _spawn_acquire_or_attach_subprocess(
        relay_home=relay_home,
    )
    assert returncode == 0, (
        f"acquire_or_attach subprocess must exit 0 after recovering an "
        f"orphan tempfile; observed rc={returncode}\n"
        f"stdout={stdout!r}\nstderr={stderr!r}"
    )
    # No RELAY-SIDECAR-LOCKFILE-MALFORMED on stderr.
    assert "RELAY-SIDECAR-LOCKFILE-MALFORMED" not in stderr, (
        f"VAL-W2-050: orphan tempfile triggered LOCKFILE-MALFORMED; "
        f"recovery wiring is missing.\nstderr={stderr!r}"
    )

    # Parse the subprocess result envelope.
    payload = json.loads(stdout.strip().splitlines()[-1])
    assert payload["action"] == "spawned", (
        f"expected NO_LOCKFILE -> spawned; got {payload['action']!r}"
    )
    # The orphan was visible to the subprocess BEFORE acquire_or_attach.
    assert str(orphan_path) in payload["pre_orphans"], (
        f"VAL-W2-050: subprocess did not observe the seeded orphan: {payload}"
    )
    # The orphan was removed AFTER acquire_or_attach (the wiring fired).
    assert payload["post_orphans"] == [], (
        f"VAL-W2-050: orphan tempfile persisted after acquire_or_attach; "
        f"wiring is missing. post_orphans={payload['post_orphans']!r}"
    )
    assert payload["canonical_lockfile_exists"] is True
    assert payload["canonical_lockfile_size"] > 0
    # The canonical lockfile must be valid JSON carrying pid + port.
    body = json.loads(payload["lockfile_after_json"])
    assert body["port"] == 50061
    assert isinstance(body["pid"], int) and body["pid"] > 0

    # On-host filesystem state matches the subprocess's view.
    assert not orphan_path.exists()
    assert (relay_home / lockfile_name).exists()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-050")
def test_e2e_partial_lockfile_subprocess_handles_multiple_orphans(
    tmp_path: Path,
) -> None:
    """Multiple orphan tempfiles are all cleared by the production wiring."""
    relay_home = tmp_path / "relay-home"
    relay_home.mkdir(parents=True, exist_ok=True)
    lockfile_name = "sidecar.lock"
    orphans = [
        relay_home / (lockfile_name + f".tmp{i}") for i in range(3)
    ]
    for o in orphans:
        o.write_bytes(b"garbage")

    returncode, stdout, _stderr = _spawn_acquire_or_attach_subprocess(
        relay_home=relay_home,
    )
    assert returncode == 0, returncode
    payload = json.loads(stdout.strip().splitlines()[-1])
    assert payload["action"] == "spawned"
    assert sorted(payload["pre_orphans"]) == sorted(str(o) for o in orphans)
    assert payload["post_orphans"] == []
    for o in orphans:
        assert not o.exists(), f"orphan {o} persisted after acquire_or_attach"
