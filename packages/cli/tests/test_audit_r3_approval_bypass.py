"""Audit-r3 tier-1 plumbing tests: BUG-B4 approval_required CLI bypass.

Per CLAUDE.md keystone invariant #6 the human single-use approval token
is the ONLY way to satisfy an ``approval_required`` fixture in replay.
Prior to audit-r3 the CLI's ``--allow-side-effects=approval_required``
flag silently waived the contract; the codes RELAY-REPLAY-031/032/033
defined in ``relay_sidecar.side_effect_markers`` were never raised at
the CLI surface.

This module asserts the post-fix behavior:

  * ``--allow-side-effects=approval_required`` is rejected by the CLI
    with a targeted error message.
  * A fixture declaring ``approval_required`` causes
    ``rly replay run`` (without ``--approval-token``) to emit a
    structured envelope carrying wire code ``RELAY-REPLAY-031``.
  * ``approval_required`` is removed from the parser's accepted set;
    the only accepted classes are ``mutating`` and
    ``external_irreversible``.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]


def _run_rly(
    args: list[str],
    extra_env: dict[str, str] | None = None,
    *,
    timeout: float = 30.0,
) -> subprocess.CompletedProcess[str]:
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


def _sample_call(*, idx: int, side_effect_class: str) -> dict[str, Any]:
    return {
        "provider": "openai",
        "model": "gpt-4o-mini",
        "request": {"messages": [{"role": "user", "content": f"hi {idx}"}]},
        "response": {"id": f"chatcmpl-{idx}", "choices": [{"index": 0}]},
        "timestamp": f"2026-05-14T00:00:0{idx}Z",
        "side_effect_class": side_effect_class,
    }


def _record_env(home: Path, src_path: Path) -> dict[str, str]:
    return {
        "RELAY_HOME": str(home),
        "RELAY_CLI_REPLAY_RECORD_SOURCE": str(src_path),
        "RELAY_CLI_REPLAY_RECORD_SESSION_ID": "00000000000000000000000001",
        "RELAY_CLI_REPLAY_RECORD_RECORDED_AT": "2026-05-14T00:00:00.000000Z",
        "RELAY_CLI_REPLAY_RECORD_MANIFEST_HASH": "sha256-" + ("a" * 64),
    }


# ----------------------------------------------------------------------------
# Pure-function parser tests (no subprocess; fastest tier-1 plumbing)
# ----------------------------------------------------------------------------


@pytest.mark.plumbing
def test_allow_side_effects_rejects_approval_required_token() -> None:
    """BUG-B4: the parser must reject ``approval_required`` explicitly."""
    from relay_cli.commands.replay import _parse_allow_side_effects

    with pytest.raises(ValueError) as exc:
        _parse_allow_side_effects("approval_required")
    msg = str(exc.value)
    assert "approval_required cannot be bypassed" in msg, (
        f"expected targeted message; got {msg!r}"
    )
    assert "--approval-token" in msg


@pytest.mark.plumbing
def test_allow_side_effects_rejects_approval_required_mixed_in_csv() -> None:
    """BUG-B4: approval_required mixed with valid tokens still raises."""
    from relay_cli.commands.replay import _parse_allow_side_effects

    with pytest.raises(ValueError):
        _parse_allow_side_effects("mutating,approval_required")
    with pytest.raises(ValueError):
        _parse_allow_side_effects("approval_required,external_irreversible")


@pytest.mark.plumbing
def test_allow_side_effects_dangerous_set_excludes_approval_required() -> None:
    """BUG-B4: the dangerous-classes set must not contain approval_required."""
    from relay_cli.commands.replay import (
        _DANGEROUS_SIDE_EFFECTS,
        SIDE_EFFECT_APPROVAL_REQUIRED,
        SIDE_EFFECT_EXTERNAL_IRREVERSIBLE,
        SIDE_EFFECT_MUTATING,
    )

    assert SIDE_EFFECT_MUTATING in _DANGEROUS_SIDE_EFFECTS
    assert SIDE_EFFECT_EXTERNAL_IRREVERSIBLE in _DANGEROUS_SIDE_EFFECTS
    assert SIDE_EFFECT_APPROVAL_REQUIRED not in _DANGEROUS_SIDE_EFFECTS, (
        "approval_required must not be subtractable via --allow-side-effects"
    )


@pytest.mark.plumbing
def test_allow_side_effects_accepts_mutating_and_external_irreversible() -> None:
    """BUG-B4 regression: the two classes that are still permitted must work."""
    from relay_cli.commands.replay import _parse_allow_side_effects

    assert _parse_allow_side_effects("mutating") == {"mutating"}
    assert _parse_allow_side_effects("external_irreversible") == {
        "external_irreversible"
    }
    assert _parse_allow_side_effects("mutating,external_irreversible") == {
        "mutating",
        "external_irreversible",
    }


# ----------------------------------------------------------------------------
# Subprocess-driven end-to-end: approval_required fixture path
# ----------------------------------------------------------------------------


@pytest.mark.plumbing
def test_replay_run_rejects_approval_required_fixture_without_token(
    tmp_path: Path,
) -> None:
    """BUG-B4: a fixture declaring approval_required without --approval-token
    must surface RELAY-REPLAY-031 and exit 4xx."""
    home = tmp_path / "relay_home_approval"
    home.mkdir()
    src = tmp_path / "calls.json"
    src.write_text(
        json.dumps(
            [_sample_call(idx=0, side_effect_class="approval_required")]
        ),
        encoding="utf-8",
    )

    rec = _run_rly(
        ["replay", "record", "--run-id", "run-approval-1"],
        extra_env=_record_env(home, src),
    )
    assert rec.returncode == 0, "record stderr=" + rec.stderr
    case_id = json.loads(rec.stdout)["replay_case_id"]

    run = _run_rly(
        ["replay", "run", "--case", case_id],
        extra_env={"RELAY_HOME": str(home)},
    )
    assert run.returncode != 0, (
        "approval_required fixture must NOT silently play back; "
        "stdout=" + run.stdout + " stderr=" + run.stderr
    )
    # Envelope on stderr.
    err_lines = [line for line in run.stderr.strip().splitlines() if line.strip()]
    err = json.loads(err_lines[-1])
    assert err["code"] == "RELAY-REPLAY-031", (
        f"expected RELAY-REPLAY-031; got envelope={err!r}"
    )
    assert err["http_status"] == 403


@pytest.mark.plumbing
def test_replay_run_rejects_approval_required_bypass_via_flag(
    tmp_path: Path,
) -> None:
    """BUG-B4: passing --allow-side-effects=approval_required must be
    rejected by the CLI parser (not silently accepted)."""
    home = tmp_path / "relay_home_approval_flag"
    home.mkdir()
    src = tmp_path / "calls.json"
    src.write_text(
        json.dumps(
            [_sample_call(idx=0, side_effect_class="approval_required")]
        ),
        encoding="utf-8",
    )

    rec = _run_rly(
        ["replay", "record", "--run-id", "run-approval-2"],
        extra_env=_record_env(home, src),
    )
    assert rec.returncode == 0
    case_id = json.loads(rec.stdout)["replay_case_id"]

    run = _run_rly(
        [
            "replay",
            "run",
            "--case",
            case_id,
            "--allow-side-effects",
            "approval_required",
        ],
        extra_env={"RELAY_HOME": str(home)},
    )
    assert run.returncode != 0, (
        "approval_required CLI bypass must be rejected; stdout="
        + run.stdout
        + " stderr="
        + run.stderr
    )
    err_lines = [line for line in run.stderr.strip().splitlines() if line.strip()]
    err = json.loads(err_lines[-1])
    assert err["code"] == "RELAY-CLI-USAGE-ALLOW-SIDE-EFFECTS"
    assert "approval_required cannot be bypassed" in err["message"]


@pytest.mark.plumbing
def test_replay_run_with_approval_token_proceeds(tmp_path: Path) -> None:
    """BUG-B4 positive path: supplying --approval-token allows the run to
    proceed past the approval gate (token validity is the sidecar's
    responsibility -- the CLI enforces presence only)."""
    home = tmp_path / "relay_home_approval_token"
    home.mkdir()
    src = tmp_path / "calls.json"
    src.write_text(
        json.dumps(
            [_sample_call(idx=0, side_effect_class="approval_required")]
        ),
        encoding="utf-8",
    )

    rec = _run_rly(
        ["replay", "record", "--run-id", "run-approval-3"],
        extra_env=_record_env(home, src),
    )
    assert rec.returncode == 0
    case_id = json.loads(rec.stdout)["replay_case_id"]

    run = _run_rly(
        [
            "replay",
            "run",
            "--case",
            case_id,
            "--approval-token",
            "dummy-token-presence-only",
        ],
        extra_env={"RELAY_HOME": str(home)},
    )
    assert run.returncode == 0, (
        "approval_required + valid presence token should proceed; "
        "stdout=" + run.stdout + " stderr=" + run.stderr
    )
    payload = json.loads(run.stdout)
    assert payload["mode"] == "cassette"
    assert payload["entries_played"] == 1


@pytest.mark.plumbing
def test_marker_module_codes_match_cli_constant() -> None:
    """BUG-B4: the CLI must reuse the sidecar marker module's code constant
    so the wire form stays consistent across the two surfaces."""
    from relay_cli.commands.replay import RELAY_REPLAY_APPROVAL_REQUIRED
    from relay_sidecar.side_effect_markers import (
        RELAY_REPLAY_APPROVAL_REQUIRED as MARKER_CODE,
    )

    assert RELAY_REPLAY_APPROVAL_REQUIRED == MARKER_CODE == "RELAY-REPLAY-031"
