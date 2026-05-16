"""W12.6 first-tagged-release runbook gate plumbing tests (VAL-W12-047).

Tests the ``scripts/check-runbook-exists.py`` gate that CI invokes before
the first tagged release publishes. Verifies:

  * pass when the canonical runbook exists with all required sections
  * fail (exit 2) when the runbook file is absent
  * fail (exit 1) when a required section header is missing

Per CLAUDE.md TDD discipline: tests use ``@pytest.mark.fulfills`` to
bind to contract assertions. ASCII-only source per CLAUDE.md.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.plumbing

REPO_ROOT: Path = Path(__file__).resolve().parents[2]
GATE_SCRIPT: Path = REPO_ROOT / "scripts" / "check-runbook-exists.py"
CANONICAL_RUNBOOK: Path = REPO_ROOT / "docs" / "release" / "runbook.md"


def _run_gate(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(GATE_SCRIPT), *args],
        capture_output=True,
        text=True,
        check=False,
    )


REQUIRED_SECTIONS_TEXT = (
    "# Test Runbook\n"
    "\n"
    "## Compromised OIDC response\n"
    "Steps here.\n"
    "\n"
    "## No Destructive Rollback\n"
    "Policy here.\n"
    "\n"
    "## Sectigo TSA fallback\n"
    "Fallback here.\n"
    "\n"
    "## Trust-anchor governance cross-reference\n"
    "Reference here.\n"
)


# ---------------------------------------------------------------------------
# VAL-W12-047: gate behavior
# ---------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-W12-047")
def test_runbook_gate_passes_on_canonical_runbook() -> None:
    """The shipping runbook at docs/release/runbook.md MUST pass the gate."""
    result = _run_gate(["--runbook", str(CANONICAL_RUNBOOK), "--json"])
    assert result.returncode == 0, (
        f"canonical runbook failed gate: {result.stdout}\n{result.stderr}"
    )
    payload = json.loads(result.stdout)
    assert payload["status"] == "pass"
    assert payload["missing_sections"] == []
    assert "Compromised OIDC response" in payload["found_sections"]
    assert "No Destructive Rollback" in payload["found_sections"]
    assert "Sectigo TSA fallback" in payload["found_sections"]
    assert "Trust-anchor governance cross-reference" in payload["found_sections"]


@pytest.mark.fulfills("VAL-W12-047")
def test_runbook_gate_fails_when_runbook_absent(tmp_path: Path) -> None:
    """Missing runbook -> exit 2, RELAY-RELEASE-047, all sections missing."""
    absent = tmp_path / "nonexistent.md"
    result = _run_gate(["--runbook", str(absent), "--json"])
    assert result.returncode == 2
    payload = json.loads(result.stdout)
    assert payload["status"] == "fail"
    assert payload["error_code"] == "RELAY-RELEASE-047"
    assert payload["exists"] is False
    assert len(payload["missing_sections"]) == 4


@pytest.mark.fulfills("VAL-W12-047")
def test_runbook_gate_fails_when_section_missing(tmp_path: Path) -> None:
    """Runbook present but missing one section -> exit 1, RELAY-RELEASE-047."""
    partial = tmp_path / "runbook.md"
    # Drop the "Sectigo TSA fallback" section.
    partial.write_text(
        "# Partial Runbook\n"
        "\n"
        "## Compromised OIDC response\n"
        "Steps here.\n"
        "\n"
        "## No Destructive Rollback\n"
        "Policy here.\n"
        "\n"
        "## Trust-anchor governance cross-reference\n"
        "Reference here.\n"
    )
    result = _run_gate(["--runbook", str(partial), "--json"])
    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["status"] == "fail"
    assert payload["error_code"] == "RELAY-RELEASE-047"
    assert payload["missing_sections"] == ["Sectigo TSA fallback"]


@pytest.mark.fulfills("VAL-W12-047")
def test_runbook_gate_passes_synthetic_full_runbook(tmp_path: Path) -> None:
    """A minimal synthetic runbook with all four sections must pass."""
    full = tmp_path / "runbook.md"
    full.write_text(REQUIRED_SECTIONS_TEXT)
    result = _run_gate(["--runbook", str(full), "--json"])
    assert result.returncode == 0, result.stdout + "\n" + result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "pass"


@pytest.mark.fulfills("VAL-W12-047")
def test_runbook_gate_human_output_emits_ok_or_fail() -> None:
    """Human-readable output uses [OK] / [FAIL] (ASCII-safe per CLAUDE.md)."""
    result = _run_gate(["--runbook", str(CANONICAL_RUNBOOK)])
    assert result.returncode == 0
    assert "[OK]" in result.stdout
