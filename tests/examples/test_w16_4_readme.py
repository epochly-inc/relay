"""README content assertions for the MCP tool-agent example.

Covers:
  VAL-W16-015: README documents the five required sections
               (installation, running live mode, recording a cassette,
               replaying from cassette, expected output snippet).
  VAL-W16-016: no banned product copy in any example file.

Tier-1 plumbing: pure file reads + regex checks.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def mcp_example_root() -> Path:
    return REPO_ROOT / "examples" / "mcp-tool-agent"


# Required README section headings per VAL-W16-015.
REQUIRED_SECTIONS: tuple[str, ...] = (
    "Installation",
    "Running live mode",
    "Recording a cassette",
    "Replaying from cassette",
    "Expected output",
)

# Banned product copy per spec section J.5 and CLAUDE.md banned #9.
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
def test_mcp_root_readme_has_required_sections(
    mcp_example_root: Path,
) -> None:
    """The root example README documents all five required sections."""
    readme = mcp_example_root / "README.md"
    assert readme.is_file(), "examples/mcp-tool-agent/README.md missing"
    text = readme.read_text(encoding="utf-8")
    missing = [s for s in REQUIRED_SECTIONS if not _section_present(text, s)]
    assert not missing, (
        f"README missing required section headings: {missing}. "
        f"Required: {list(REQUIRED_SECTIONS)} (VAL-W16-015)."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-015")
def test_mcp_python_readme_has_required_sections(
    mcp_example_root: Path,
) -> None:
    """Per-language Python README also documents the five sections."""
    readme = mcp_example_root / "python" / "README.md"
    assert readme.is_file(), (
        "examples/mcp-tool-agent/python/README.md missing"
    )
    text = readme.read_text(encoding="utf-8")
    missing = [s for s in REQUIRED_SECTIONS if not _section_present(text, s)]
    assert not missing, (
        f"python/README.md missing required section headings: {missing}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-013")
def test_mcp_readme_documents_mcp_protocol(
    mcp_example_root: Path,
) -> None:
    """Per VAL-W16-013 the README MUST document that the example captures
    tool calls via the MCP (Model Context Protocol) surface. The README
    references the protocol by name and identifies the MCP server the
    example exercises (for reproducibility per contract gap #2).
    """
    readme = mcp_example_root / "README.md"
    text = readme.read_text(encoding="utf-8")
    lowered = text.lower()
    assert "model context protocol" in lowered or "mcp protocol" in lowered, (
        "README must document the Model Context Protocol (MCP) by name "
        "(VAL-W16-013)."
    )
    # The README MUST identify the MCP server the example uses so the
    # cassette is reproducible (contract gap #2). The pinned server is
    # referenced explicitly in the README and the cassette.
    assert "mcp server" in lowered, (
        "README must identify the MCP server the example exercises "
        "(contract gap #2 reproducibility)."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-014")
def test_mcp_readme_documents_cassette_replay_invariant(
    mcp_example_root: Path,
) -> None:
    """Per VAL-W16-014 the README MUST document that cassette replay (a)
    is offline (zero network egress), and (b) does NOT spawn an MCP
    server process during replay.
    """
    readme = mcp_example_root / "README.md"
    text = readme.read_text(encoding="utf-8")
    lowered = text.lower()
    assert "zero network egress" in lowered or "no network egress" in lowered, (
        "README must document the zero-network-egress invariant for "
        "cassette mode (VAL-W16-014)."
    )
    # Cassette replay MUST NOT spawn an MCP server child process.
    has_no_spawn_claim = (
        "no mcp server" in lowered
        or "without spawning" in lowered
        or "does not spawn" in lowered
        or "no child process" in lowered
    )
    assert has_no_spawn_claim, (
        "README must document that cassette replay does NOT spawn an MCP "
        "server child process (VAL-W16-014)."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-016")
def test_mcp_example_contains_no_banned_product_copy(
    mcp_example_root: Path,
) -> None:
    """No file under examples/mcp-tool-agent/ contains banned product copy."""
    offenders: list[str] = []
    for path in mcp_example_root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix not in SCANNED_SUFFIXES:
            continue
        rel = path.relative_to(mcp_example_root)
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
        "Banned product copy found in examples/mcp-tool-agent/:\n"
        + "\n".join(offenders)
        + "\nUse 'AI Act readiness evidence', 'evidence coverage', 'gaps' "
        "instead (spec J.5, CLAUDE.md banned #9)."
    )
