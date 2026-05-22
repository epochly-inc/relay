"""Plumbing-tier tests for scripts/lint-banned-copy.py (VAL-DOCS-M1-014).

These tests lock in the docs/**/*.md scanning behavior added for the
relay-docs-v1 operation:

- docs/**/*.md is scanned for banned product copy per CLAUDE.md banned
  pattern #9 / spec section J.5.
- docs/internal/** is excluded (internal-only docs may quote tokens in
  meta-discussion of the lint policy itself).
- docs/release/** is excluded (operational runbooks may need to reference
  compliance language in incident-response narratives).
- Word-boundary policy on `compliant` / `certified`: STRICT. `\bcompliant\b`
  matches the bare token AND matches inside hyphenated compounds like
  `non-compliant` because `-` is a non-word character in Python regex.
  Decision rationale documented in scripts/lint-banned-copy.py.
- The pre-existing surfaces (cli-source-tree, cli-readme, etc.) continue
  to lint clean on the live repo.

The tests load the lint script as a module via importlib (the filename
contains a hyphen so a plain `import` does not work) and monkeypatch its
REPO_ROOT to point at a temp filesystem populated with fixtures. This
exercises the real `_scan_surface` / `main` codepaths without depending on
or mutating the live repo tree.

ASCII-only per CLAUDE.md.
"""

from __future__ import annotations

import importlib.util
import io
import json
import re
import sys
from contextlib import redirect_stdout
from pathlib import Path

import pytest

# Repo root: this test file lives at relay/tests/test_lint_banned_copy.py.
REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "lint-banned-copy.py"


def _load_lint_module():
    """Load scripts/lint-banned-copy.py as a module under a Python-safe name."""
    spec = importlib.util.spec_from_file_location(
        "lint_banned_copy_under_test", SCRIPT_PATH
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    # Register so dataclasses / annotations resolve normally.
    sys.modules["lint_banned_copy_under_test"] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def lint_module():
    """Fresh load per-test so REPO_ROOT monkeypatching is hermetic."""
    return _load_lint_module()


def _run_main_against_root(
    lint_mod, fake_root: Path, *, monkeypatch: pytest.MonkeyPatch
) -> tuple[int, str]:
    """Point the lint module at `fake_root` and invoke main with --json.

    Returns (exit_code, stdout). main() returns the exit code; we also
    capture the JSON payload printed to stdout so individual tests can
    assert on per-surface violation lists.
    """
    monkeypatch.setattr(lint_mod, "REPO_ROOT", fake_root)
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = lint_mod.main(["--json"])
    return rc, buf.getvalue()


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


@pytest.mark.plumbing
def test_docs_md_scanned(tmp_path: Path, lint_module, monkeypatch):
    """A banned token in docs/<page>.md MUST trigger a non-zero exit.

    Locks in VAL-DOCS-M1-014: the lint extension scans docs/**/*.md and
    surfaces banned-copy violations there.
    """
    _write(
        tmp_path / "docs" / "intro" / "page.md",
        "This product is compliant with everything.\n",
    )
    rc, stdout = _run_main_against_root(
        lint_module, tmp_path, monkeypatch=monkeypatch
    )
    assert rc != 0, f"expected non-zero exit, got {rc}; stdout={stdout!r}"
    report = json.loads(stdout)
    public_docs = next(
        s for s in report["surfaces"] if s["label"] == "public-docs"
    )
    assert public_docs["root_exists"] is True
    assert public_docs["files_scanned"] >= 1
    assert any(
        v["path"].endswith("docs/intro/page.md")
        and "compliant" in [m.lower() for m in v["matches"]]
        for v in public_docs["violations"]
    ), public_docs


@pytest.mark.plumbing
def test_docs_internal_excluded(tmp_path: Path, lint_module, monkeypatch):
    """A banned token under docs/internal/** MUST NOT trigger a failure.

    Internal docs may discuss the banned-copy policy itself or quote
    counsel-grade material that legitimately references compliance
    language; the lint policy explicitly excludes this subtree.
    """
    _write(
        tmp_path / "docs" / "internal" / "lint-policy.md",
        "The lint forbids 'compliant' and 'certified' in customer surfaces.\n",
    )
    rc, stdout = _run_main_against_root(
        lint_module, tmp_path, monkeypatch=monkeypatch
    )
    assert rc == 0, f"expected exit 0, got {rc}; stdout={stdout!r}"
    report = json.loads(stdout)
    public_docs = next(
        s for s in report["surfaces"] if s["label"] == "public-docs"
    )
    # The internal file must NOT be scanned by the public-docs surface.
    scanned_paths = [v["path"] for v in public_docs["violations"]]
    assert all("internal" not in p for p in scanned_paths)


@pytest.mark.plumbing
def test_docs_release_excluded(tmp_path: Path, lint_module, monkeypatch):
    """A banned token under docs/release/** MUST NOT trigger a failure.

    Release runbooks describe incident response and may need to reference
    compliance language in narrative; the lint policy excludes this subtree.
    """
    _write(
        tmp_path / "docs" / "release" / "runbook.md",
        "On a certified rollback, follow the playbook.\n",
    )
    rc, stdout = _run_main_against_root(
        lint_module, tmp_path, monkeypatch=monkeypatch
    )
    assert rc == 0, f"expected exit 0, got {rc}; stdout={stdout!r}"


@pytest.mark.plumbing
def test_permitted_alternatives_pass(
    tmp_path: Path, lint_module, monkeypatch
):
    """Pages using only the permitted alternative phrases lint clean."""
    _write(
        tmp_path / "docs" / "compliance" / "readiness.md",
        (
            "# AI Act readiness evidence\n\n"
            "Relay produces evidence coverage that surfaces gaps and "
            "leaves the bundle ready for auditor review.\n"
        ),
    )
    rc, stdout = _run_main_against_root(
        lint_module, tmp_path, monkeypatch=monkeypatch
    )
    assert rc == 0, f"expected exit 0, got {rc}; stdout={stdout!r}"
    report = json.loads(stdout)
    assert report["total_violations"] == 0


@pytest.mark.plumbing
def test_word_boundary_compliant(tmp_path: Path, lint_module, monkeypatch):
    """STRICT word-boundary policy: `\\bcompliant\\b` matches inside
    `non-compliant` because `-` is a non-word character.

    Documented decision: the strict path is the conservative one. If a
    page genuinely needs to say "non-compliant" it should be rephrased
    to "fails the compliance check" or moved to docs/internal/ which is
    excluded from this surface.
    """
    _write(
        tmp_path / "docs" / "page.md",
        "The output was non-compliant with the schema.\n",
    )
    rc, stdout = _run_main_against_root(
        lint_module, tmp_path, monkeypatch=monkeypatch
    )
    assert rc != 0, f"expected non-zero exit, got {rc}; stdout={stdout!r}"
    report = json.loads(stdout)
    public_docs = next(
        s for s in report["surfaces"] if s["label"] == "public-docs"
    )
    assert any(
        "compliant" in [m.lower() for m in v["matches"]]
        for v in public_docs["violations"]
    )


@pytest.mark.plumbing
def test_ai_act_approved_variants(tmp_path: Path, lint_module, monkeypatch):
    """Both `AI Act-approved` and `AI Act approved` (with space) flag.

    Regression for the variant-aware regex; ensures docs surface inherits
    the same variant coverage as the source-tree surface.
    """
    _write(
        tmp_path / "docs" / "marketing.md",
        "This module is AI Act-approved and AI Act approved.\n",
    )
    rc, stdout = _run_main_against_root(
        lint_module, tmp_path, monkeypatch=monkeypatch
    )
    assert rc != 0, f"expected non-zero exit, got {rc}; stdout={stdout!r}"


@pytest.mark.plumbing
def test_guaranteed_ai_act_compliance(
    tmp_path: Path, lint_module, monkeypatch
):
    _write(
        tmp_path / "docs" / "sales.md",
        "We offer guaranteed AI Act compliance.\n",
    )
    rc, _ = _run_main_against_root(
        lint_module, tmp_path, monkeypatch=monkeypatch
    )
    assert rc != 0


@pytest.mark.plumbing
def test_public_docs_surface_includes_exclusions_in_config(lint_module):
    """The SURFACES table for `public-docs` MUST declare the internal +
    release exclusions explicitly. Locks in the config so a later edit
    that drops the excludes is caught by this test rather than by a
    production incident.
    """
    public_docs = next(
        s for s in lint_module.SURFACES if s["label"] == "public-docs"
    )
    excludes = list(public_docs["excludes"])
    assert "internal/**" in excludes, excludes
    assert "release/**" in excludes, excludes
    # Includes must still target docs/**/*.md.
    assert "**/*.md" in list(public_docs["includes"])


@pytest.mark.plumbing
def test_public_docs_exclude_patterns_match_candidate_files(lint_module, tmp_path: Path):
    root = tmp_path / "docs"
    internal_file = root / "internal" / "lint-policy.md"
    nested_internal_file = root / "internal" / "nested" / "policy.md"
    release_file = root / "release" / "runbook.md"
    public_file = root / "public" / "page.md"
    patterns = ["internal/**", "release/**"]

    assert lint_module._is_excluded(internal_file, root, patterns) is True
    assert lint_module._is_excluded(nested_internal_file, root, patterns) is True
    assert lint_module._is_excluded(release_file, root, patterns) is True
    assert lint_module._is_excluded(public_file, root, patterns) is False


@pytest.mark.plumbing
def test_verify_self_banned_copy_regex_matches_lint_policy(lint_module):
    from relay_cli.invariants.banned_patterns import _BANNED_COPY_RE

    assert _BANNED_COPY_RE.pattern == lint_module.BANNED_REGEX.pattern
    assert _BANNED_COPY_RE.flags & re.IGNORECASE
    assert lint_module.BANNED_REGEX.flags & re.IGNORECASE
    assert _BANNED_COPY_RE.search("noncompliant") is None
    assert _BANNED_COPY_RE.search("certified_status") is None
    assert _BANNED_COPY_RE.search("non-compliant") is not None


@pytest.mark.plumbing
def test_real_docs_tree_clean(lint_module):
    """The live docs/ tree as it stands today MUST lint clean.

    This is the on-the-record proof for VAL-DOCS-M1-014: extending the
    lint to docs/**/*.md (with the internal/release exclusions) does not
    surface any pre-existing banned-copy in the published docs tree.

    If this assertion ever fails, do NOT relax the lint; surface the
    finding to the orchestrator as a docs-content bug.
    """
    # Use the live REPO_ROOT defined inside the module (no monkeypatch).
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = lint_module.main(["--json"])
    assert rc == 0, (
        "live banned-copy lint failed; stdout=" + buf.getvalue()
    )
    report = json.loads(buf.getvalue())
    public_docs = next(
        s for s in report["surfaces"] if s["label"] == "public-docs"
    )
    assert public_docs["root_exists"] is True
    assert public_docs["files_scanned"] >= 1
    assert public_docs["violations"] == []


@pytest.mark.plumbing
def test_existing_surfaces_still_present(lint_module):
    """Regression: the pre-existing surfaces (cli-source-tree, cli-readme,
    cli-pyproject, root-package-json, sdk-typescript-package-json,
    schemas-typescript-package-json, public-docs, github-release-notes,
    pyinstaller-spec) MUST all remain configured. Locks in
    VAL-W5-009 / VAL-W5-009b coverage so the m1-f02 extension does not
    accidentally drop a surface.
    """
    labels = {s["label"] for s in lint_module.SURFACES}
    required = {
        "cli-source-tree",
        "cli-readme",
        "cli-pyproject",
        "root-package-json",
        "sdk-typescript-package-json",
        "schemas-typescript-package-json",
        "public-docs",
        "github-release-notes",
        "pyinstaller-spec",
    }
    missing = required - labels
    assert not missing, "surfaces dropped from SURFACES: " + repr(missing)
