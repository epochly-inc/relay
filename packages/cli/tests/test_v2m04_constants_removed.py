"""V2 M04 w4-side-effects: legacy constant removal guard tests.

Covers VAL-V2M04-023 (SIDE_EFFECT_NONE removed), VAL-V2M04-024
(SIDE_EFFECT_REVERSIBLE removed), VAL-V2M04-025 (replay default is
'read_only'). Spec E.3 lines 3931-3936 lock the canonical four classes.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_THIS = Path(__file__).resolve()
# packages/cli/tests/test_v2m04_constants_removed.py
# parents[3] is the public relay repo root.
_REPO_ROOT = _THIS.parents[3]


def _scan_oss_sources_for_legacy_constant(name: str) -> list[tuple[Path, int, str]]:
    """Grep guard mirroring the VAL-V2M04-023/024 evidence requirement.

    Returns offender (path, line_number, line_text) tuples. The guard
    scans ``packages/`` and ``apps/`` and ``services/`` (when present)
    but excludes ``__pycache__``, ``.venv``, generated trees, and ``tests/``
    (tests are allowed to mention the constant names in assertions /
    docstrings demonstrating they were removed -- the prose IS the test).

    The contract also explicitly excludes ``contract-drafts/`` / ``golden``
    (per VAL-V2M04-023 "excluding .venv and tests/golden").
    """
    pattern = re.compile(rf"\b{name}\b")
    offenders: list[tuple[Path, int, str]] = []
    for top in ("packages", "apps", "services"):
        top_path = _REPO_ROOT / top
        if not top_path.is_dir():
            continue
        for py in top_path.rglob("*.py"):
            parts = set(py.parts)
            if "__pycache__" in parts or ".venv" in parts:
                continue
            if "_generated" in parts:
                continue
            if "tests" in parts:
                continue
            if "golden" in parts:
                continue
            try:
                text = py.read_text(encoding="utf-8")
            except OSError:
                continue
            for lineno, line in enumerate(text.splitlines(), start=1):
                # Allow the doc comment that documents the removal.
                if "removed alongside" in line or "removed from this module" in line:
                    continue
                if pattern.search(line):
                    offenders.append((py, lineno, line.strip()))
    return offenders


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-023")
def test_side_effect_none_removed_from_oss_sources() -> None:
    """grep -rn 'SIDE_EFFECT_NONE' relay/packages relay/apps relay/services
    must return zero matches outside tests/golden + doc comments
    documenting the removal."""
    offenders = _scan_oss_sources_for_legacy_constant("SIDE_EFFECT_NONE")
    assert offenders == [], (
        "SIDE_EFFECT_NONE was removed by M04 w4; offenders found:\n"
        + "\n".join(f"  {p}:{ln}: {src}" for p, ln, src in offenders)
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-024")
def test_side_effect_reversible_removed_from_oss_sources() -> None:
    """grep -rn 'SIDE_EFFECT_REVERSIBLE' relay/packages relay/apps relay/services
    must return zero matches outside tests/golden + doc comments
    documenting the removal."""
    offenders = _scan_oss_sources_for_legacy_constant("SIDE_EFFECT_REVERSIBLE")
    assert offenders == [], (
        "SIDE_EFFECT_REVERSIBLE was removed by M04 w4; offenders found:\n"
        + "\n".join(f"  {p}:{ln}: {src}" for p, ln, src in offenders)
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-025")
def test_replay_default_side_effect_class_is_read_only() -> None:
    """The replay.py default for an absent side_effect_class is the
    canonical 'read_only' string, not the legacy 'none'."""
    from relay_cli.commands.replay import SIDE_EFFECT_READ_ONLY

    assert SIDE_EFFECT_READ_ONLY == "read_only"

    # The source line at file:355 reads ``side_class = call.get(
    # "side_effect_class", SIDE_EFFECT_READ_ONLY)``. Confirm by reading
    # the file content.
    replay_path = (
        _REPO_ROOT / "packages" / "cli" / "src" / "relay_cli" / "commands" / "replay.py"
    )
    text = replay_path.read_text(encoding="utf-8")
    assert 'call.get("side_effect_class", SIDE_EFFECT_READ_ONLY)' in text, (
        "VAL-V2M04-025: replay default constant should be SIDE_EFFECT_READ_ONLY"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-025")
def test_replay_module_exports_canonical_four_classes() -> None:
    """The replay module's __all__ exposes all four canonical classes
    (read_only, mutating, external_irreversible, approval_required) and
    none of the legacy ones."""
    from relay_cli.commands import replay

    exported = set(replay.__all__)
    assert "SIDE_EFFECT_READ_ONLY" in exported
    assert "SIDE_EFFECT_MUTATING" in exported
    assert "SIDE_EFFECT_EXTERNAL_IRREVERSIBLE" in exported
    assert "SIDE_EFFECT_APPROVAL_REQUIRED" in exported
    assert "SIDE_EFFECT_NONE" not in exported
    assert "SIDE_EFFECT_REVERSIBLE" not in exported


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-025")
def test_approval_required_treated_as_dangerous_in_replay() -> None:
    """approval_required class is blocked alongside mutating and
    external_irreversible (the _DANGEROUS_SIDE_EFFECTS set)."""
    from relay_cli.commands.replay import _DANGEROUS_SIDE_EFFECTS

    assert "approval_required" in _DANGEROUS_SIDE_EFFECTS
    assert "mutating" in _DANGEROUS_SIDE_EFFECTS
    assert "external_irreversible" in _DANGEROUS_SIDE_EFFECTS
    assert "read_only" not in _DANGEROUS_SIDE_EFFECTS
