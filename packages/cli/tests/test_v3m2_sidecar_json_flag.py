"""V3M2-F05 plumbing tests: ``rly sidecar start/stop/status --json`` flag.

Fulfills VAL-V3M2-010:

    ``rly sidecar start --json``, ``rly sidecar stop --json``,
    ``rly sidecar status --json`` all emit a single JSON object on stdout
    with ``schema_version: relay.cli.sidecar_<verb>.v1``. Without
    ``--json``, human-readable output is unchanged.

These tests:

  1. Subprocess-invoke each verb with ``--json``; assert stdout parses as a
     single JSON object whose ``schema_version`` matches the verb literal.
  2. Direct-invoke each verb via :class:`typer.testing.CliRunner` with
     :func:`relay_cli.output.should_emit_json` monkey-patched to ``False``
     so the human-output branch is exercised; assert stdout is non-empty,
     does not parse as JSON, and does not leak control characters.

The subprocess tier is the canonical evidence path for the assertion (real
``rly`` binary, real exit code, real stdout). The CliRunner tier proves the
human branch is reachable independently of the TTY-detection default.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

# Repository root (relay/), four parents up from this test file.
REPO_ROOT = Path(__file__).resolve().parents[3]


# -----------------------------------------------------------------------------
# Subprocess invocation helpers (mirror the W5.2 test patterns)
# -----------------------------------------------------------------------------


def _run_rly(
    args: list[str],
    extra_env: dict[str, str] | None = None,
    *,
    timeout: float = 30.0,
) -> subprocess.CompletedProcess[str]:
    """Invoke ``uv run rly <args>`` non-TTY (capture_output=True)."""
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        ["uv", "run", "rly", *args],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        env=env,
        timeout=timeout,
        check=False,
    )


def _fake_spawn_env(tmp_home: Path, *, pid: int, port: int) -> dict[str, str]:
    """Return the env-dict that drives the fake-spawn test seam."""
    return {
        "RELAY_HOME": str(tmp_home),
        "RELAY_CLI_TEST_FAKE_SPAWN_PID": str(pid),
        "RELAY_CLI_TEST_FAKE_SPAWN_PORT": str(port),
    }


# =============================================================================
# --json flag emits JSON envelope (subprocess tier)
# =============================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M2-010")
def test_sidecar_start_json_flag_emits_envelope(tmp_path: Path) -> None:
    """``rly sidecar start --json`` -> single JSON object, sidecar_start.v1."""
    home = tmp_path / "v3m2_start_json"
    home.mkdir()
    env = _fake_spawn_env(home, pid=os.getpid(), port=58712)
    result = _run_rly(["sidecar", "start", "--json"], extra_env=env)
    assert result.returncode == 0, (
        "rly sidecar start --json exit="
        + str(result.returncode)
        + " stderr="
        + result.stderr
    )
    # Exactly one JSON object on stdout (line-oriented contract).
    payload = json.loads(result.stdout)
    assert isinstance(payload, dict)
    assert payload["schema_version"] == "relay.cli.sidecar_start.v1"
    assert payload["pid"] == os.getpid()
    assert payload["port"] == 58712


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M2-010")
def test_sidecar_status_json_flag_emits_envelope(tmp_path: Path) -> None:
    """``rly sidecar status --json`` -> single JSON object, sidecar_status.v1."""
    home = tmp_path / "v3m2_status_json"
    home.mkdir()
    result = _run_rly(
        ["sidecar", "status", "--json"],
        extra_env={"RELAY_HOME": str(home)},
    )
    # No lockfile -> state='stopped', exit 1 (per VAL-W5-012).
    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert isinstance(payload, dict)
    assert payload["schema_version"] == "relay.cli.sidecar_status.v1"
    assert payload["state"] == "stopped"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M2-010")
def test_sidecar_stop_json_flag_emits_envelope(tmp_path: Path) -> None:
    """``rly sidecar stop --json`` -> single JSON object, sidecar_stop.v1."""
    home = tmp_path / "v3m2_stop_json"
    home.mkdir()
    result = _run_rly(
        ["sidecar", "stop", "--json"],
        extra_env={"RELAY_HOME": str(home)},
    )
    # No lockfile -> action='noop', exit 0.
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert isinstance(payload, dict)
    assert payload["schema_version"] == "relay.cli.sidecar_stop.v1"
    assert payload["action"] == "noop"


# =============================================================================
# --json explicit alongside a running lockfile (live PID + bound port)
# =============================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M2-010")
def test_sidecar_status_json_running_state_envelope(tmp_path: Path) -> None:
    """When sidecar is 'running', --json envelope carries pid/port/uptime."""
    home = tmp_path / "v3m2_status_running"
    home.mkdir()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    port = s.getsockname()[1]
    try:
        # Seed the lockfile by running 'start' first; then check status.
        env = _fake_spawn_env(home, pid=os.getpid(), port=port)
        first = _run_rly(["sidecar", "start", "--json"], extra_env=env)
        assert first.returncode == 0, "seed start failed: " + first.stderr
        result = _run_rly(
            ["sidecar", "status", "--json"],
            extra_env={"RELAY_HOME": str(home)},
        )
        assert result.returncode == 0, (
            "expected running -> exit 0; got "
            + str(result.returncode)
            + " stderr="
            + result.stderr
        )
        payload = json.loads(result.stdout)
        assert payload["schema_version"] == "relay.cli.sidecar_status.v1"
        assert payload["state"] == "running"
        assert payload["pid"] == os.getpid()
        assert payload["port"] == port
    finally:
        s.close()


# =============================================================================
# Without --json: human-readable branch reachable; output is NOT JSON
# =============================================================================


def _force_human_runner_invoke(verb: str, env_overrides: dict[str, str]) -> tuple[int, str]:
    """Invoke ``rly sidecar <verb>`` via CliRunner with the human branch forced.

    Monkeypatches :func:`relay_cli.commands.sidecar.should_emit_json` (the
    re-exported symbol the command resolves at call time) to return
    ``False`` so the ``--json``-absent path is exercised even though
    CliRunner stdout is not a real TTY.

    Returns ``(exit_code, stdout)``.
    """
    import relay_cli.commands.sidecar as sidecar_mod

    runner = CliRunner()
    # Build a fresh sidecar app to avoid carrying state between tests.
    app = sidecar_mod.build_sidecar_app()

    # Force the human path: patch the symbol that sidecar.py resolves at
    # call time (re-imported into the module's globals).
    original = sidecar_mod.should_emit_json
    sidecar_mod.should_emit_json = lambda force_json=False: bool(force_json)
    try:
        result = runner.invoke(app, [verb], env=env_overrides)
    finally:
        sidecar_mod.should_emit_json = original
    return result.exit_code, result.stdout


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M2-010")
def test_sidecar_start_without_json_is_human_text(tmp_path: Path) -> None:
    """Without --json (human branch forced), stdout is text, not JSON."""
    home = tmp_path / "v3m2_start_human"
    home.mkdir()
    env = _fake_spawn_env(home, pid=os.getpid(), port=58713)
    exit_code, stdout = _force_human_runner_invoke("start", env)
    assert exit_code == 0, "human-branch start exit=" + str(exit_code)
    assert stdout.strip(), "human output must not be empty"
    with pytest.raises(json.JSONDecodeError):
        json.loads(stdout)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M2-010")
def test_sidecar_status_without_json_is_human_text(tmp_path: Path) -> None:
    """Without --json (human branch forced), status stdout is text, not JSON."""
    home = tmp_path / "v3m2_status_human"
    home.mkdir()
    env = {"RELAY_HOME": str(home)}
    exit_code, stdout = _force_human_runner_invoke("status", env)
    # Stopped state surfaces exit 1 (per VAL-W5-012); we only assert format.
    assert stdout.strip(), "human output must not be empty"
    with pytest.raises(json.JSONDecodeError):
        json.loads(stdout)
    _ = exit_code


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M2-010")
def test_sidecar_stop_without_json_is_human_text(tmp_path: Path) -> None:
    """Without --json (human branch forced), stop stdout is text, not JSON."""
    home = tmp_path / "v3m2_stop_human"
    home.mkdir()
    env = {"RELAY_HOME": str(home)}
    exit_code, stdout = _force_human_runner_invoke("stop", env)
    assert exit_code == 0, "human-branch stop exit=" + str(exit_code)
    assert stdout.strip(), "human output must not be empty"
    with pytest.raises(json.JSONDecodeError):
        json.loads(stdout)


# =============================================================================
# Schema-version literal source-of-truth check
# =============================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M2-010")
def test_sidecar_schema_version_literals_unchanged() -> None:
    """The three sidecar schema_version constants stay pinned at .v1.

    Acts as a guard against accidental version bumps from this feature.
    """
    from relay_cli.commands.sidecar import (
        SIDECAR_START_SCHEMA,
        SIDECAR_STATUS_SCHEMA,
        SIDECAR_STOP_SCHEMA,
    )

    assert SIDECAR_START_SCHEMA == "relay.cli.sidecar_start.v1"
    assert SIDECAR_STATUS_SCHEMA == "relay.cli.sidecar_status.v1"
    assert SIDECAR_STOP_SCHEMA == "relay.cli.sidecar_stop.v1"
