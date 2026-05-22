"""Plumbing-tier tests for ``scripts/docs/build-cli-reference.py``.

Binds VAL-DOCS-M1-008 (m1-f03-cli-reference-generator): the CLI-reference
generator walks every subcommand reachable via ``rly --json help`` and
writes a Markdown page per subcommand under ``docs/reference/cli/``. Each
page carries the banner "Generated from packages/cli/src/relay_cli/main.py.
Do not edit by hand." so machine consumers know to regenerate rather than
hand-edit.

Test coverage (per the feature dispatch directive):
- ``test_help_exits_zero`` -- ``--help`` exits 0
- ``test_generates_at_least_one_page`` -- generator writes >=1 page
- ``test_generated_pages_have_banner`` -- every page carries the banner
- ``test_idempotent`` -- two consecutive runs produce byte-identical output
- ``test_check_mode_exit_0_when_no_drift`` -- ``--check`` returns 0 when
  on-disk matches generated
- ``test_check_mode_exit_1_when_drift`` -- ``--check`` returns 1 when a
  page has drifted from the source CLI

ASCII-only source per CLAUDE.md "ASCII-Safe Source".

Spec citations:
- plan.md "Wave 1 deliverable 5" (CLI reference auto-generated)
- contract.md VAL-DOCS-M1-008.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "docs" / "build-cli-reference.py"

BANNER_FRAGMENT = (
    "Generated from packages/cli/src/relay_cli/main.py. Do not edit by hand."
)


def _run(args: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    """Invoke the generator script with the active interpreter."""
    env = dict(os.environ)
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        cwd=str(cwd or REPO_ROOT),
        env=env,
        timeout=120,
    )


@pytest.mark.plumbing
def test_help_exits_zero() -> None:
    """``--help`` exits 0 and prints a usage line mentioning --check + --out."""
    result = _run(["--help"])
    assert result.returncode == 0, (
        f"--help exit={result.returncode}; stderr={result.stderr!r}"
    )
    combined = result.stdout + result.stderr
    assert "--check" in combined, "help text must mention --check flag"
    assert "--out" in combined, "help text must mention --out flag"


@pytest.mark.plumbing
def test_generates_at_least_one_page(tmp_path: Path) -> None:
    """Running the generator against a fresh tmp dir emits at least one .md page."""
    out = tmp_path / "cli"
    result = _run(["--out", str(out)])
    assert result.returncode == 0, (
        f"generator exit={result.returncode}; "
        f"stderr={result.stderr!r}; stdout={result.stdout!r}"
    )
    pages = list(out.rglob("*.md"))
    assert len(pages) >= 1, (
        f"expected at least one generated page; found {len(pages)} under {out}"
    )


@pytest.mark.plumbing
def test_generated_pages_have_banner(tmp_path: Path) -> None:
    """Every emitted Markdown page carries the 'Generated from ... do not edit' banner."""
    out = tmp_path / "cli"
    result = _run(["--out", str(out)])
    assert result.returncode == 0, (
        f"generator failed; stderr={result.stderr!r}"
    )
    pages = list(out.rglob("*.md"))
    assert pages, "generator produced no pages"
    for p in pages:
        body = p.read_text(encoding="utf-8")
        assert BANNER_FRAGMENT in body, (
            f"page {p} missing banner fragment {BANNER_FRAGMENT!r}"
        )


@pytest.mark.plumbing
def test_idempotent(tmp_path: Path) -> None:
    """Running the generator twice produces byte-identical output."""
    out = tmp_path / "cli"
    r1 = _run(["--out", str(out)])
    assert r1.returncode == 0, f"first run failed; stderr={r1.stderr!r}"
    first_snapshot: dict[str, bytes] = {
        str(p.relative_to(out)): p.read_bytes() for p in sorted(out.rglob("*.md"))
    }
    r2 = _run(["--out", str(out)])
    assert r2.returncode == 0, f"second run failed; stderr={r2.stderr!r}"
    second_snapshot: dict[str, bytes] = {
        str(p.relative_to(out)): p.read_bytes() for p in sorted(out.rglob("*.md"))
    }
    assert first_snapshot.keys() == second_snapshot.keys(), (
        f"page set diverged: only-in-first={set(first_snapshot) - set(second_snapshot)};"
        f" only-in-second={set(second_snapshot) - set(first_snapshot)}"
    )
    for key in first_snapshot:
        assert first_snapshot[key] == second_snapshot[key], (
            f"page {key!r} not byte-identical between runs"
        )


@pytest.mark.plumbing
def test_check_mode_exit_0_when_no_drift(tmp_path: Path) -> None:
    """After a fresh generate, ``--check`` against the same dir exits 0."""
    out = tmp_path / "cli"
    gen = _run(["--out", str(out)])
    assert gen.returncode == 0, f"initial generate failed; stderr={gen.stderr!r}"
    check = _run(["--check", "--out", str(out)])
    assert check.returncode == 0, (
        f"--check should return 0 on clean tree; exit={check.returncode}; "
        f"stderr={check.stderr!r}; stdout={check.stdout!r}"
    )


@pytest.mark.plumbing
def test_check_mode_exit_1_when_drift(tmp_path: Path) -> None:
    """After mutating an emitted page, ``--check`` exits 1 and reports drift."""
    out = tmp_path / "cli"
    gen = _run(["--out", str(out)])
    assert gen.returncode == 0, f"initial generate failed; stderr={gen.stderr!r}"
    pages = list(out.rglob("*.md"))
    assert pages, "generator produced no pages; cannot test drift detection"
    target = pages[0]
    body = target.read_text(encoding="utf-8")
    target.write_text(body + "\n<!-- deliberate drift marker -->\n", encoding="utf-8")
    check = _run(["--check", "--out", str(out)])
    assert check.returncode == 1, (
        f"--check should return 1 on drift; exit={check.returncode}; "
        f"stderr={check.stderr!r}; stdout={check.stdout!r}"
    )
