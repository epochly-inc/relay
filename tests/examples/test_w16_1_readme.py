"""README content assertions for the OpenAI tool-agent example.

Covers:
  VAL-W16-015: README documents five required sections (installation,
               running live mode, recording a cassette, replaying from
               cassette, expected output snippet).
  VAL-W16-016: no banned product copy in any example file.

Tier-1 plumbing: pure file reads + regex checks.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

# Required README section headings per VAL-W16-015. Matching is
# case-insensitive on a line starting with one or more '#' markers.
REQUIRED_SECTIONS: tuple[str, ...] = (
    "Installation",
    "Running live mode",
    "Recording a cassette",
    "Replaying from cassette",
    "Expected output",
)

# Banned product copy per spec section J.5 and CLAUDE.md banned #9.
# Case-insensitive substring match; READMEs that need to discuss "AI Act
# readiness" must use "readiness" / "evidence" / "gaps" language instead.
BANNED_PHRASES: tuple[str, ...] = (
    "compliant",
    "certified",
    "AI Act-approved",
    "guaranteed AI Act compliance",
)

SCANNED_SUFFIXES: frozenset[str] = frozenset(
    {".md", ".py", ".ts", ".tsx", ".json", ".yaml", ".yml", ".toml"}
)


def _section_present(text: str, heading: str) -> bool:
    """Return True if a markdown heading matching ``heading`` appears."""
    pattern = re.compile(
        r"^#{1,6}\s+.*" + re.escape(heading) + r".*$",
        re.IGNORECASE | re.MULTILINE,
    )
    return pattern.search(text) is not None


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-015")
def test_openai_root_readme_has_required_sections(example_root: Path) -> None:
    """The root example README documents all five required sections."""
    readme = example_root / "README.md"
    assert readme.is_file(), "examples/openai-tool-agent/README.md missing"
    text = readme.read_text(encoding="utf-8")
    missing = [s for s in REQUIRED_SECTIONS if not _section_present(text, s)]
    assert not missing, (
        f"README missing required section headings: {missing}. "
        f"Required: {list(REQUIRED_SECTIONS)} (VAL-W16-015)."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-015")
def test_openai_python_readme_has_required_sections(example_root: Path) -> None:
    """Per-language Python README also documents the five sections."""
    readme = example_root / "python" / "README.md"
    assert readme.is_file(), "examples/openai-tool-agent/python/README.md missing"
    text = readme.read_text(encoding="utf-8")
    missing = [s for s in REQUIRED_SECTIONS if not _section_present(text, s)]
    assert not missing, (
        f"python/README.md missing required section headings: {missing}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-015")
def test_openai_typescript_readme_has_required_sections(
    example_root: Path,
) -> None:
    """Per-language TypeScript README also documents the five sections."""
    readme = example_root / "typescript" / "README.md"
    assert readme.is_file(), (
        "examples/openai-tool-agent/typescript/README.md missing"
    )
    text = readme.read_text(encoding="utf-8")
    missing = [s for s in REQUIRED_SECTIONS if not _section_present(text, s)]
    assert not missing, (
        f"typescript/README.md missing required section headings: {missing}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-016")
def test_openai_example_contains_no_banned_product_copy(
    example_root: Path,
) -> None:
    """No file under examples/openai-tool-agent/ contains banned product copy."""
    offenders: list[str] = []
    for path in example_root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix not in SCANNED_SUFFIXES:
            continue
        rel = path.relative_to(example_root)
        if any(
            part in {"node_modules", "__pycache__", ".venv", "dist"}
            for part in rel.parts
        ):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        lowered = text.lower()
        for phrase in BANNED_PHRASES:
            if phrase.lower() in lowered:
                offenders.append(f"{rel}: {phrase!r}")
    assert not offenders, (
        "Banned product copy found in examples/openai-tool-agent/:\n"
        + "\n".join(offenders)
        + "\nUse 'AI Act readiness evidence', 'evidence coverage', 'gaps' "
        "instead (spec J.5, CLAUDE.md banned #9)."
    )
