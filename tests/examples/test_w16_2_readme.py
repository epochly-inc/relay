"""README content assertions for the LangChain RAG example.

Covers:
  VAL-W16-007: README documents the "manual instrumentation" gap
               honestly via an "Adapter status" section that explicitly
               states the LangChain adapter is P1-deferred in v0.1 and
               that this example uses manual SDK calls.
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
def langchain_example_root() -> Path:
    return REPO_ROOT / "examples" / "langchain-rag-agent"


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

# Substrings that imply the LangChain adapter has shipped. The
# "Adapter status" section MUST NOT imply a shipped adapter; per
# VAL-W16-007 the example uses manual instrumentation only.
LANGCHAIN_SHIPPED_PHRASES: tuple[str, ...] = (
    "langchain adapter ships",
    "langchain adapter is shipped",
    "langchain adapter is available",
    "ships the langchain adapter",
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
def test_langchain_root_readme_has_required_sections(
    langchain_example_root: Path,
) -> None:
    """The root example README documents all five required sections."""
    readme = langchain_example_root / "README.md"
    assert readme.is_file(), "examples/langchain-rag-agent/README.md missing"
    text = readme.read_text(encoding="utf-8")
    missing = [s for s in REQUIRED_SECTIONS if not _section_present(text, s)]
    assert not missing, (
        f"README missing required section headings: {missing}. "
        f"Required: {list(REQUIRED_SECTIONS)} (VAL-W16-015)."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-015")
def test_langchain_python_readme_has_required_sections(
    langchain_example_root: Path,
) -> None:
    """Per-language Python README also documents the five sections."""
    readme = langchain_example_root / "python" / "README.md"
    assert readme.is_file(), (
        "examples/langchain-rag-agent/python/README.md missing"
    )
    text = readme.read_text(encoding="utf-8")
    missing = [s for s in REQUIRED_SECTIONS if not _section_present(text, s)]
    assert not missing, (
        f"python/README.md missing required section headings: {missing}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-007")
def test_langchain_readme_has_adapter_status_section(
    langchain_example_root: Path,
) -> None:
    """README MUST include an 'Adapter status' section per VAL-W16-007.

    The section explicitly states that the full LangChain adapter is
    P1-deferred in v0.1 and that the example uses manual SDK calls.
    """
    readme = langchain_example_root / "README.md"
    text = readme.read_text(encoding="utf-8")
    assert _section_present(text, "Adapter status"), (
        "README must include an 'Adapter status' section "
        "(VAL-W16-007 manual-instrumentation gap)."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-007")
def test_langchain_readme_adapter_status_documents_manual_instrumentation(
    langchain_example_root: Path,
) -> None:
    """Adapter status section MUST state P1-deferred + manual SDK calls."""
    readme = langchain_example_root / "README.md"
    text = readme.read_text(encoding="utf-8").lower()
    assert "p1-deferred" in text or "p1 deferred" in text, (
        "README must call out the LangChain adapter as P1-deferred "
        "(VAL-W16-007)."
    )
    assert "manual" in text and (
        "instrumentation" in text or "sdk call" in text or "sdk calls" in text
    ), (
        "README must document that the example uses manual instrumentation / "
        "manual SDK calls (VAL-W16-007)."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-007")
def test_langchain_readme_does_not_imply_shipped_langchain_adapter(
    langchain_example_root: Path,
) -> None:
    """Per VAL-W16-007 the README MUST NOT imply a shipped LangChain adapter."""
    readme = langchain_example_root / "README.md"
    text = readme.read_text(encoding="utf-8").lower()
    offenders = [p for p in LANGCHAIN_SHIPPED_PHRASES if p in text]
    assert not offenders, (
        "README contains substrings that imply a shipped LangChain adapter: "
        f"{offenders}. The adapter is P1-deferred; use manual-instrumentation "
        "language only (VAL-W16-007)."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-024")
def test_langchain_readme_documents_anthropic_backing_model(
    langchain_example_root: Path,
) -> None:
    """Per VAL-W16-024 the README MUST document Anthropic as the backing
    model and the ANTHROPIC_API_KEY requirement.
    """
    readme = langchain_example_root / "README.md"
    text = readme.read_text(encoding="utf-8")
    lowered = text.lower()
    assert "anthropic" in lowered, (
        "README must document Anthropic as the backing LLM "
        "(VAL-W16-024 / CW-002)."
    )
    assert "anthropic_api_key" in lowered or "ANTHROPIC_API_KEY" in text, (
        "README must document the ANTHROPIC_API_KEY requirement "
        "(VAL-W16-024 live-mode)."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-016")
def test_langchain_example_contains_no_banned_product_copy(
    langchain_example_root: Path,
) -> None:
    """No file under examples/langchain-rag-agent/ contains banned product copy."""
    offenders: list[str] = []
    for path in langchain_example_root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix not in SCANNED_SUFFIXES:
            continue
        rel = path.relative_to(langchain_example_root)
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
        "Banned product copy found in examples/langchain-rag-agent/:\n"
        + "\n".join(offenders)
        + "\nUse 'AI Act readiness evidence', 'evidence coverage', 'gaps' "
        "instead (spec J.5, CLAUDE.md banned #9)."
    )
