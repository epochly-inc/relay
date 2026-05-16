"""Structural / static-file assertions for the LangChain RAG example.

Covers (w16.2 cross-cutting share):
  VAL-W16-021: cassette-mode entry point is platform-agnostic (no
               POSIX-only primitives invoked unconditionally).
  VAL-W16-023: no TODO/FIXME/HACK and no debug-file artifacts; only the
               permitted root files are present at the example root.

Per the contract coverage map the LangChain example is Python-only (the
W3.5 Python Anthropic adapter underpins VAL-W16-024); there is no
TypeScript subdirectory. The root contains README.md, relay.manifest.yaml,
pyproject.toml, .gitignore, and the ``python/`` subdir only.

Tier-1 plumbing: inspects files on disk; no sidecar, no provider key.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def langchain_example_root() -> Path:
    """Return the langchain-rag-agent example root."""
    return REPO_ROOT / "examples" / "langchain-rag-agent"


# Files permitted at the example-app root per VAL-W16-023. The LangChain
# example is Python-only (per contract coverage map + VAL-W16-024 reasoning:
# the W3.5 Python Anthropic adapter underpins the canonical assertion);
# no package.json at the example root.
PERMITTED_ROOT_FILES: frozenset[str] = frozenset(
    {
        "README.md",
        "relay.manifest.yaml",
        "pyproject.toml",
        ".gitignore",
    }
)

PERMITTED_ROOT_SUBDIRS: frozenset[str] = frozenset({"python"})

# Anti-hack markers per CLAUDE.md anti-patterns and VAL-W16-023.
ANTI_HACK_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bTODO\b"),
    re.compile(r"\bFIXME\b"),
    re.compile(r"\bXXX\b"),
    re.compile(r"\bHACK\b"),
)

SCANNED_SUFFIXES: frozenset[str] = frozenset(
    {".py", ".ts", ".tsx", ".js", ".mjs", ".cjs", ".md", ".yaml", ".yml", ".json", ".toml"}
)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-023")
def test_langchain_example_root_exists(langchain_example_root: Path) -> None:
    """The example directory exists at examples/langchain-rag-agent/."""
    assert langchain_example_root.is_dir(), (
        f"examples/langchain-rag-agent/ must exist; got {langchain_example_root}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-023")
def test_langchain_example_has_required_top_level_files(
    langchain_example_root: Path,
) -> None:
    """README, relay.manifest.yaml, pyproject.toml exist at example root."""
    assert (langchain_example_root / "README.md").is_file(), (
        "examples/langchain-rag-agent/README.md missing"
    )
    assert (langchain_example_root / "relay.manifest.yaml").is_file(), (
        "examples/langchain-rag-agent/relay.manifest.yaml missing"
    )
    assert (langchain_example_root / "pyproject.toml").is_file(), (
        "examples/langchain-rag-agent/pyproject.toml missing"
    )
    py_main = langchain_example_root / "python" / "main.py"
    assert py_main.is_file(), "python/main.py entry point missing"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-023")
def test_langchain_example_root_contains_only_permitted_files(
    langchain_example_root: Path,
) -> None:
    """Per VAL-W16-023 root contains only README, relay.manifest.yaml,
    pyproject.toml, .gitignore, and the python/ subdir.
    """
    actual: set[str] = set()
    for child in langchain_example_root.iterdir():
        if child.name.startswith(".") and child.name != ".gitignore":
            continue
        if child.name in {"__pycache__", ".venv", "dist", "node_modules"}:
            continue
        actual.add(child.name)
    expected = PERMITTED_ROOT_FILES | PERMITTED_ROOT_SUBDIRS
    unexpected = actual - expected
    assert not unexpected, (
        f"Unexpected entries at examples/langchain-rag-agent/ root: "
        f"{sorted(unexpected)}. Only {sorted(expected)} are permitted "
        "per VAL-W16-023."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-023")
def test_langchain_example_has_no_todo_fixme_hack(
    langchain_example_root: Path,
) -> None:
    """Anti-hack grep: TODO/FIXME/XXX/HACK markers absent across the example."""
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
        for lineno, line in enumerate(text.splitlines(), start=1):
            for pattern in ANTI_HACK_PATTERNS:
                if pattern.search(line):
                    offenders.append(f"{rel}:{lineno}: {line.strip()}")
    assert not offenders, (
        "VAL-W16-023 anti-hack markers found in examples/langchain-rag-agent/:\n"
        + "\n".join(offenders)
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-021")
def test_langchain_example_is_platform_agnostic(
    langchain_example_root: Path,
) -> None:
    """The example MUST run on macOS, Linux, AND Windows. POSIX-only
    APIs (os.fork, signal.SIGUSR1, fcntl.flock on the example surface)
    are not invoked unconditionally; Windows path separators are not
    assumed.
    """
    python_main = (langchain_example_root / "python" / "main.py").read_text(
        encoding="utf-8"
    )
    forbidden_unconditional_posix = (
        "os.fork(",
        "signal.SIGUSR1",
        "signal.SIGUSR2",
        "fcntl.flock(",
        "fcntl.fcntl(",
    )
    for pattern in forbidden_unconditional_posix:
        assert pattern not in python_main, (
            f"main.py uses POSIX-only API {pattern!r}; this breaks Windows "
            "(VAL-W16-021 platform parity)."
        )
    assert "\\\\" not in python_main, (
        "main.py must not hard-code Windows backslashes; use pathlib "
        "(VAL-W16-021)"
    )
