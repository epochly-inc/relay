"""VAL-W2-021: AST lint -- no network awaits inside DB transactions.

Static analysis MUST find zero ``await httpx.*`` /
``await asyncio.open_connection`` / network primitive inside the body
of a DB transaction region in ``apps/local-sidecar/``. We exercise the
lint script in two modes:

  1. Run the lint against the actual sidecar source tree; expect 0
     violations (CI green).
  2. Run the lint against a synthesised offending file in a tmpdir;
     expect 1 violation (proves the lint actually detects the pattern,
     not just that the sidecar is currently clean).

ASCII-only per CLAUDE.md.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
LINT_SCRIPT = (
    REPO_ROOT
    / "apps"
    / "local-sidecar"
    / "scripts"
    / "lint_network_in_db_tx.py"
)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-021")
def test_lint_sidecar_source_zero_violations() -> None:
    """Running the lint against apps/local-sidecar/relay_sidecar/ -> exit 0."""
    assert LINT_SCRIPT.exists(), LINT_SCRIPT
    result = subprocess.run(
        [sys.executable, str(LINT_SCRIPT)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"VAL-W2-021 violations:\n"
        f"stdout={result.stdout!r}\nstderr={result.stderr!r}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-021")
def test_lint_detects_synthesised_violation(tmp_path) -> None:
    """An offending file (await httpx.get inside BEGIN..COMMIT) -> exit 1."""
    offending = tmp_path / "offender.py"
    offending.write_text(
        """
import asyncio
import httpx


async def offending_handler(conn):
    await conn.execute("BEGIN IMMEDIATE")
    await httpx.get("https://example.invalid/")
    await conn.execute("COMMIT")
""".strip()
        + "\n",
        encoding="utf-8",
    )
    result = subprocess.run(
        [sys.executable, str(LINT_SCRIPT), str(offending)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1, (
        f"expected exit 1 from lint on offending file, got "
        f"{result.returncode}; stdout={result.stdout!r} "
        f"stderr={result.stderr!r}"
    )
    assert "httpx.get" in result.stderr, result.stderr


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-021")
def test_lint_allows_sleep_outside_tx(tmp_path) -> None:
    """asyncio.sleep BETWEEN tx blocks must NOT be flagged."""
    clean = tmp_path / "clean.py"
    clean.write_text(
        """
import asyncio


async def clean_handler(conn):
    await conn.execute("BEGIN IMMEDIATE")
    await conn.execute("INSERT INTO t VALUES (1)")
    await conn.execute("COMMIT")
    await asyncio.sleep(0.01)
    await conn.execute("BEGIN IMMEDIATE")
    await conn.execute("INSERT INTO t VALUES (2)")
    await conn.execute("COMMIT")
""".strip()
        + "\n",
        encoding="utf-8",
    )
    result = subprocess.run(
        [sys.executable, str(LINT_SCRIPT), str(clean)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"expected exit 0; got {result.returncode}; "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )
