"""VAL-V3M2-001/002/003 plumbing test.

Exercises ``scripts/check-openapi-route-coverage.py`` as a subprocess so
the same exit-code contract used by CI applies here. On a clean tree
the script must exit 0; any drift (missing/extra route, missing
summary/responses/requestBody, duplicate operationId) raises the script
exit code to 1 and this test fails.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[4]
_SCRIPT = _REPO_ROOT / "scripts" / "check-openapi-route-coverage.py"


@pytest.mark.plumbing
def test_openapi_route_coverage_script_exists() -> None:
    """The coverage script must exist on disk at the documented path."""
    assert _SCRIPT.is_file(), (
        f"VAL-V3M2-001: coverage script not found at "
        f"{_SCRIPT.relative_to(_REPO_ROOT)}"
    )


@pytest.mark.plumbing
def test_openapi_route_coverage_passes_on_current_tree() -> None:
    """The coverage script must exit 0 on HEAD.

    Covers VAL-V3M2-001 (route set equality), VAL-V3M2-002 (per-operation
    shape: summary + responses with 2xx and 4xx/5xx + requestBody for
    POST/PUT/PATCH), and VAL-V3M2-003 (operationId global uniqueness).
    """
    result = subprocess.run(
        [sys.executable, str(_SCRIPT)],
        capture_output=True,
        text=True,
        cwd=str(_REPO_ROOT),
        check=False,
    )
    assert result.returncode == 0, (
        "scripts/check-openapi-route-coverage.py exited "
        f"{result.returncode}\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )
    # The script's PASS line carries the route count -- assert it
    # references the FastAPI enumeration so a regression that silently
    # short-circuits (e.g. returns 0 with 0 routes) is caught.
    assert "FastAPI routes" in result.stdout, (
        "Coverage script PASS line did not include FastAPI route count; "
        f"stdout: {result.stdout!r}"
    )


@pytest.mark.plumbing
def test_openapi_route_coverage_detects_missing_route(tmp_path: Path) -> None:
    """Negative path: a doctored openapi.yaml omitting a route must fail.

    Constructs a minimal openapi.yaml with paths={} and runs the script
    against it via --openapi. The script must exit 1 with VAL-V3M2-001
    failures.
    """
    fake = tmp_path / "openapi.yaml"
    fake.write_text(
        "openapi: 3.1.0\n"
        "info:\n  title: t\n  version: 0.0.0\n"
        "paths: {}\n",
        encoding="utf-8",
    )
    result = subprocess.run(
        [sys.executable, str(_SCRIPT), "--openapi", str(fake)],
        capture_output=True,
        text=True,
        cwd=str(_REPO_ROOT),
        check=False,
    )
    assert result.returncode == 1, (
        "Empty-paths openapi.yaml should have failed coverage; "
        f"got returncode={result.returncode}\nSTDOUT:{result.stdout}\n"
        f"STDERR:{result.stderr}"
    )
    assert "VAL-V3M2-001" in result.stderr, (
        "Expected VAL-V3M2-001 in failure output; "
        f"stderr was:\n{result.stderr}"
    )
