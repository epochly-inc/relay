"""VAL-ISO-042: `rly gate evaluate` must not let a non-dict HTTP-200 body
escape as an uncaught traceback.

Structural-review P2. The CLI exit-code contract (spec section P.1)
promises a STRUCTURED error envelope for EVERY outcome -- an uncaught
``AttributeError`` bubbling out of the command callback violates that
contract even though the top-level wrapper in ``main.py`` masks it as a
generic ``RELAY-CLI-070`` envelope.

The defect:

  * ``_get_decision`` (gate.py ~line 470) wrapped ``resp.json()`` in
    ``{"_resolved": True, "payload": resp.json()}`` WITHOUT validating
    that the decoded body is a dict. A real sidecar that returns HTTP 200
    with a bare array / string / number / null body produced a non-dict
    ``payload``.
  * The polling loop then did ``payload = decision.get("payload", decision)``
    and ``_emit_decision_envelope(payload, ...)`` -> ``payload.get(
    "failed_assertions", [])`` and ``payload.get("action", "accept")``.
    On a list/str/int/None payload those ``.get`` calls raise
    ``AttributeError`` -- escaping the command and surfacing as a generic
    ``RELAY-CLI-070`` (programming-error) envelope whose
    ``traceback_summary`` ends in ``gate.py`` rather than the gate
    command's OWN structured ``RELAY-GATE-INTERNAL`` envelope.
  * The env-gated fixture path (gate.py ~line 232) had the identical
    unguarded ``.get`` on ``json.loads(fixture)``.

The fix validates the decoded body is a dict BEFORE dereferencing ``.get``
and emits the structured ``RELAY-GATE-INTERNAL`` envelope (exit 70,
``blocked_surface="rly gate evaluate"``) reusing the existing internal-error
emission in gate.py -- instead of letting AttributeError escape.

These tests exercise the REAL httpx polling path in-process (the
``test_iso_033`` pattern: ``monkeypatch.setattr(httpx, "get", ...)`` +
calling the command callback and catching ``SystemExit``) so the
``_get_decision`` ``resp.json()`` seam is hit directly, plus a subprocess
test for the env-gated fixture path.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

import httpx
import pytest
import typer
from relay_cli.commands import gate as gate_mod
from relay_cli.exit_codes import EXIT_SUCCESS, EXIT_UNCAUGHT_INTERNAL

REPO_ROOT = Path(__file__).resolve().parents[3]


class _FakeResp:
    """Minimal httpx.Response stand-in for monkeypatched transport."""

    def __init__(self, status_code: int, body: Any) -> None:
        self.status_code = status_code
        self._body = body

    def json(self) -> Any:
        return self._body


@pytest.fixture(autouse=True)
def _reset_cancel_state() -> Any:
    saved = dict(gate_mod._CANCELLED)
    gate_mod._CANCELLED.clear()
    gate_mod._CANCELLED["flag"] = False
    yield
    gate_mod._CANCELLED.clear()
    gate_mod._CANCELLED.update(saved)


def _seed_draft_and_decision(
    monkeypatch: pytest.MonkeyPatch,
    *,
    draft_id: str,
    decision_body: Any,
    decision_status: int = 200,
) -> None:
    """Wire httpx.post (draft create) and httpx.get (poll) for one cycle.

    The draft POST returns a 200 with a well-formed draft record; the
    decision GET returns ``decision_status`` with ``decision_body`` so the
    polling loop resolves on the first poll.
    """

    def _fake_post(url: str, *args: Any, **kwargs: Any) -> _FakeResp:
        return _FakeResp(200, {"draft_id": draft_id, "draft_ttl_seconds": 30})

    def _fake_get(url: str, *args: Any, **kwargs: Any) -> _FakeResp:
        return _FakeResp(decision_status, decision_body)

    monkeypatch.setattr(httpx, "post", _fake_post)
    monkeypatch.setattr(httpx, "get", _fake_get)
    # Ensure no env seam short-circuits the real httpx path.
    for var in (
        gate_mod.ENV_GATE_FIXTURE,
        gate_mod.ENV_GATE_DRAFT_RESPONSE,
        gate_mod.ENV_GATE_DECISION_RESPONSES,
    ):
        monkeypatch.delenv(var, raising=False)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-042")
@pytest.mark.parametrize("body", [[], None, "a-string", 7, 3.14, True])
def test_polling_non_dict_200_emits_structured_internal_not_traceback(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    body: Any,
) -> None:
    """A 200 with a non-dict JSON body on the polling path MUST surface the
    gate command's structured RELAY-GATE-INTERNAL envelope (exit 70), NOT
    an uncaught AttributeError.

    RED on pre-fix code: ``_get_decision`` wrapped the non-dict body and the
    loop's ``payload.get(...)`` raised AttributeError.
    """
    _seed_draft_and_decision(
        monkeypatch, draft_id="draft-iso042", decision_body=body
    )

    # The callback raises typer.Exit (a RuntimeError subclass, NOT
    # SystemExit) when invoked in-process; main.py translates .exit_code
    # to a process exit. RED on pre-fix code: AttributeError escapes here.
    with pytest.raises(typer.Exit) as exc:
        gate_mod.cmd_gate_evaluate(gate_id="g-iso042")

    # Exit 70 (EXIT_UNCAUGHT_INTERNAL) -- the documented internal-error code.
    assert exc.value.exit_code == EXIT_UNCAUGHT_INTERNAL, (
        f"expected exit {EXIT_UNCAUGHT_INTERNAL}; got {exc.value.exit_code} "
        f"for body={body!r}"
    )

    captured = capsys.readouterr()
    # The structured envelope is on stderr (emit_envelope writes stderr).
    last_line = captured.err.strip().splitlines()[-1]
    envelope = json.loads(last_line)
    assert envelope["code"] == "RELAY-GATE-INTERNAL", (
        f"expected RELAY-GATE-INTERNAL; got {envelope['code']} "
        f"for body={body!r}"
    )
    assert envelope["blocked_surface"] == "rly gate evaluate"
    # No raw Python traceback header ever leaks (VAL-W5-004).
    assert "Traceback (most recent call last):" not in captured.err
    # And the gate command did NOT escape into the generic uncaught wrapper:
    # the structured envelope's code is the gate-specific internal code, not
    # the catch-all RELAY-CLI-070 that the AttributeError used to produce.
    assert envelope["code"] != "RELAY-CLI-070"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-042")
def test_polling_well_formed_dict_still_resolves_accept(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Regression: a well-formed dict decision payload still resolves to the
    correct accept envelope + exit 0 (unchanged by the guard)."""
    decision = {
        "gate_decision_id": "gd-iso042",
        "action": "accept",
        "round": 1,
        "failed_assertions": [],
        "evidence_bundle_id": "bundle-iso042",
        "signature": "sha256-feedface",
        "trace_id": "trace-iso042",
    }
    _seed_draft_and_decision(
        monkeypatch, draft_id="draft-iso042", decision_body=decision
    )

    with pytest.raises(typer.Exit) as exc:
        gate_mod.cmd_gate_evaluate(gate_id="g-iso042")

    assert exc.value.exit_code == EXIT_SUCCESS

    captured = capsys.readouterr()
    payload = json.loads(captured.out.strip().splitlines()[-1])
    assert payload["schema_version"] == "relay.cli.gate_evaluate.v1"
    assert payload["action"] == "accept"
    assert payload["gate_decision_id"] == "gd-iso042"
    assert payload["failed_assertions"] == []


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-042")
def test_polling_well_formed_dict_block_resolves_exit_1(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Regression: a well-formed block decision still resolves to exit 1."""
    decision = {
        "gate_decision_id": "gd-iso042-block",
        "action": "block",
        "round": 1,
        "failed_assertions": [{"id": "VAL-X", "reason": "policy"}],
    }
    _seed_draft_and_decision(
        monkeypatch, draft_id="draft-iso042b", decision_body=decision
    )

    with pytest.raises(typer.Exit) as exc:
        gate_mod.cmd_gate_evaluate(gate_id="g-iso042b")

    assert exc.value.exit_code == 1

    captured = capsys.readouterr()
    payload = json.loads(captured.out.strip().splitlines()[-1])
    assert payload["action"] == "block"
    assert len(payload["failed_assertions"]) == 1


# ---------------------------------------------------------------------------
# Gate fail-open on unknown/missing action (re-hunt gate-evaluate, HIGH).
# A dict decision whose `action` is missing or not in {accept,block,remediate}
# must NOT silently become exit 0 (accept): _exit_for_action's catch-all
# returned EXIT_SUCCESS and the action default fabricated "accept", so a
# malformed/unexpected decision PASSED the CI merge gate. It must fail CLOSED
# with the structured RELAY-GATE-INTERNAL envelope (exit 70), like any other
# malformed-decision case (keystone #2: a pass without a valid decision is not
# a pass).
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-042")
@pytest.mark.parametrize(
    "decision",
    [
        # Unrecognized action value (typo / unknown / spec-foreign).
        {"gate_decision_id": "gd-x", "action": "invalid", "round": 1},
        {"gate_decision_id": "gd-x", "action": "deny", "round": 1},
        {"gate_decision_id": "gd-x", "action": "", "round": 1},
        {"gate_decision_id": "gd-x", "action": None, "round": 1},
        # Action field entirely ABSENT (previously fabricated as "accept").
        {"gate_decision_id": "gd-x", "round": 1, "failed_assertions": []},
    ],
)
def test_polling_unknown_or_missing_action_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    decision: dict[str, Any],
) -> None:
    """A dict decision with an unknown/missing action MUST fail CLOSED
    (exit 70, RELAY-GATE-INTERNAL), never exit 0 (accept)."""
    _seed_draft_and_decision(
        monkeypatch, draft_id="draft-failopen", decision_body=decision
    )
    with pytest.raises(typer.Exit) as exc:
        gate_mod.cmd_gate_evaluate(gate_id="g-failopen")
    assert exc.value.exit_code == EXIT_UNCAUGHT_INTERNAL, (
        f"unknown/missing action MUST fail closed (exit {EXIT_UNCAUGHT_INTERNAL}), "
        f"got {exc.value.exit_code} for decision={decision!r}"
    )
    captured = capsys.readouterr()
    last_line = captured.err.strip().splitlines()[-1]
    envelope = json.loads(last_line)
    assert envelope["code"] == "RELAY-GATE-INTERNAL"
    assert envelope["blocked_surface"] == "rly gate evaluate"
    # CRITICAL: the success envelope (exit 0, action=accept) MUST NOT be emitted.
    assert '"action":"accept"' not in captured.out


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-042")
def test_remediate_action_resolves_exit_2(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Regression: a well-formed remediate decision still resolves to exit 2."""
    decision = {
        "gate_decision_id": "gd-rem",
        "action": "remediate",
        "round": 2,
        "failed_assertions": [{"id": "VAL-Y", "reason": "clock_skew"}],
    }
    _seed_draft_and_decision(
        monkeypatch, draft_id="draft-rem", decision_body=decision
    )
    with pytest.raises(typer.Exit) as exc:
        gate_mod.cmd_gate_evaluate(gate_id="g-rem")
    assert exc.value.exit_code == 2
    captured = capsys.readouterr()
    payload = json.loads(captured.out.strip().splitlines()[-1])
    assert payload["action"] == "remediate"


def _rly_env(tmp_path: Path, extra: dict[str, str]) -> dict[str, str]:
    env = os.environ.copy()
    env["RELAY_CLI_INVOCATIONS_DB_PATH"] = str(tmp_path / "inv.sqlite3")
    env["RELAY_HOME"] = str(tmp_path / "relay-home")
    env.pop("PYTEST_CURRENT_TEST", None)
    env.update(extra)
    return env


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-042")
@pytest.mark.parametrize("fixture_body", ["[]", "null", '"a-string"', "7"])
def test_fixture_path_non_dict_emits_structured_internal(
    tmp_path: Path, fixture_body: str
) -> None:
    """The env-gated fixture seam with a non-dict JSON body MUST emit the
    structured RELAY-GATE-INTERNAL envelope (exit 70), NOT an uncaught
    AttributeError.

    Runs as a subprocess (the fixture seam short-circuits before any HTTP)
    to exercise the full ``main.py`` dispatch + exit-code mapping.
    """
    env = _rly_env(tmp_path, {"RELAY_CLI_GATE_FIXTURE": fixture_body})
    result = subprocess.run(
        ["uv", "run", "rly", "gate", "evaluate", "--gate-id", "g-iso042-fx"],
        env=env,
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=60.0,
    )
    assert result.returncode == EXIT_UNCAUGHT_INTERNAL, (
        f"expected exit {EXIT_UNCAUGHT_INTERNAL}; got {result.returncode}\n"
        f"stdout={result.stdout}\nstderr={result.stderr}"
    )
    envelope = json.loads(result.stderr.strip().splitlines()[-1])
    assert envelope["code"] == "RELAY-GATE-INTERNAL", (
        f"expected RELAY-GATE-INTERNAL; got {envelope['code']}\n"
        f"stderr={result.stderr}"
    )
    assert envelope["blocked_surface"] == "rly gate evaluate"
    assert "Traceback (most recent call last):" not in result.stderr
    assert envelope["code"] != "RELAY-CLI-070"
