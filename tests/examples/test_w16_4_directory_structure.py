"""Structural / static-file assertions for the MCP tool-agent example.

Covers (W16.4 cross-cutting share):
  VAL-W16-021: cassette-mode entry point is platform-agnostic (no
               POSIX-only primitives invoked unconditionally).
  VAL-W16-023: no TODO/FIXME/HACK and no debug-file artifacts; only the
               permitted root files are present at the example root.

Per the contract coverage map and the W16.4 feature definition the MCP
example is Python-only (the W3.5 Python adapter set anchors the
canonical assertion at the W16.4 worker scope; the spec's
``examples/mcp-tool-agent/`` placeholder originally cited a typescript/
subdir but the deliverable for v0.1 is the Python MCP client example).
The root contains README.md, relay.manifest.yaml, pyproject.toml,
.gitignore, and the ``python/`` subdir only.

Tier-1 plumbing: inspects files on disk; no sidecar, no provider key.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def mcp_example_root() -> Path:
    """Return the mcp-tool-agent example root."""
    return REPO_ROOT / "examples" / "mcp-tool-agent"


# Files permitted at the example-app root per VAL-W16-023. The MCP
# example is Python-only (per W16.4 feature definition: "Python MCP
# client example"); no package.json at the example root.
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
def test_mcp_example_root_exists(mcp_example_root: Path) -> None:
    """The example directory exists at examples/mcp-tool-agent/."""
    assert mcp_example_root.is_dir(), (
        f"examples/mcp-tool-agent/ must exist; got {mcp_example_root}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-023")
def test_mcp_example_has_required_top_level_files(
    mcp_example_root: Path,
) -> None:
    """README, relay.manifest.yaml, pyproject.toml exist at example root."""
    assert (mcp_example_root / "README.md").is_file(), (
        "examples/mcp-tool-agent/README.md missing"
    )
    assert (mcp_example_root / "relay.manifest.yaml").is_file(), (
        "examples/mcp-tool-agent/relay.manifest.yaml missing"
    )
    assert (mcp_example_root / "pyproject.toml").is_file(), (
        "examples/mcp-tool-agent/pyproject.toml missing"
    )
    py_main = mcp_example_root / "python" / "main.py"
    assert py_main.is_file(), "python/main.py entry point missing"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-023")
def test_mcp_example_root_contains_only_permitted_files(
    mcp_example_root: Path,
) -> None:
    """Per VAL-W16-023 root contains only README, relay.manifest.yaml,
    pyproject.toml, .gitignore, and the python/ subdir.
    """
    actual: set[str] = set()
    for child in mcp_example_root.iterdir():
        if child.name.startswith(".") and child.name != ".gitignore":
            continue
        if child.name in {"__pycache__", ".venv", "dist", "node_modules"}:
            continue
        actual.add(child.name)
    expected = PERMITTED_ROOT_FILES | PERMITTED_ROOT_SUBDIRS
    unexpected = actual - expected
    assert not unexpected, (
        f"Unexpected entries at examples/mcp-tool-agent/ root: "
        f"{sorted(unexpected)}. Only {sorted(expected)} are permitted "
        "per VAL-W16-023."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-023")
def test_mcp_example_has_no_todo_fixme_hack(
    mcp_example_root: Path,
) -> None:
    """Anti-hack grep: TODO/FIXME/XXX/HACK markers absent across the example."""
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
        for lineno, line in enumerate(text.splitlines(), start=1):
            for pattern in ANTI_HACK_PATTERNS:
                if pattern.search(line):
                    offenders.append(f"{rel}:{lineno}: {line.strip()}")
    assert not offenders, (
        "VAL-W16-023 anti-hack markers found in examples/mcp-tool-agent/:\n"
        + "\n".join(offenders)
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-021")
def test_mcp_example_is_platform_agnostic(
    mcp_example_root: Path,
) -> None:
    """The example MUST run on macOS, Linux, AND Windows. POSIX-only
    APIs (os.fork, signal.SIGUSR1, fcntl.flock on the example surface)
    are not invoked unconditionally; Windows path separators are not
    assumed.

    Per the contract notes gap #8 ("Windows MCP example viability"): if
    the example spawned a POSIX-only MCP server subprocess, Windows
    would fail silently. The cassette-mode entry point MUST NOT spawn
    any MCP server child process during replay (VAL-W16-014: "no MCP
    server process spawned during replay"); the static check here
    asserts that no POSIX-only subprocess primitives are invoked
    unconditionally from the example source.
    """
    python_main = (mcp_example_root / "python" / "main.py").read_text(
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
