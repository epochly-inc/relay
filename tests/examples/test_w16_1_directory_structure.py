"""Structural / static-file assertions for the OpenAI tool-agent example.

Covers:
  VAL-W16-003: ships in BOTH Python AND TypeScript (pyproject.toml +
               package.json at example root).
  VAL-W16-023: no TODO/FIXME/HACK and no debug-file artifacts; only the
               permitted root files are present.

These are tier-1 plumbing checks: they inspect files on disk, do not
require a sidecar, OpenAI key, or network. They run in <1s.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

# Files permitted at the example-app root per VAL-W16-023 and
# VAL-W16-003. The single-language sub-roots add their language
# manifest separately.
PERMITTED_ROOT_FILES: frozenset[str] = frozenset(
    {
        "README.md",
        "relay.manifest.yaml",
        "pyproject.toml",
        "package.json",
        ".gitignore",
    }
)

PERMITTED_ROOT_SUBDIRS: frozenset[str] = frozenset(
    {"python", "typescript", "cassettes"}
)

# Anti-hack markers per CLAUDE.md anti-patterns and VAL-W16-023.
# Word-boundaries avoid false matches inside identifiers like "xxxhash".
ANTI_HACK_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bTODO\b"),
    re.compile(r"\bFIXME\b"),
    re.compile(r"\bXXX\b"),
    re.compile(r"\bHACK\b"),
)

# Files we scan for banned markers. Cassette JSONL fixtures are
# user-data and excluded; everything else under examples/ is in scope.
SCANNED_SUFFIXES: frozenset[str] = frozenset(
    {".py", ".ts", ".tsx", ".js", ".mjs", ".cjs", ".md", ".yaml", ".yml", ".json", ".toml"}
)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-003")
def test_openai_example_root_exists(example_root: Path) -> None:
    """The example directory exists at examples/openai-tool-agent/."""
    assert example_root.is_dir(), (
        f"examples/openai-tool-agent/ must exist; got {example_root}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-003")
def test_openai_example_ships_pyproject_and_package_json(
    example_root: Path,
) -> None:
    """OpenAI example MUST ship BOTH pyproject.toml AND package.json at root.

    Per VAL-W16-003 and MI-B-07 reconciliation: language is inferred from
    the manifest files present at the example root. The OpenAI example
    (W3 Python + W4 TS parity) MUST ship both.
    """
    py_manifest = example_root / "pyproject.toml"
    ts_manifest = example_root / "package.json"
    assert py_manifest.is_file(), (
        "OpenAI example missing pyproject.toml at example root "
        "(VAL-W16-003: ships in Python AND TypeScript)."
    )
    assert ts_manifest.is_file(), (
        "OpenAI example missing package.json at example root "
        "(VAL-W16-003: ships in Python AND TypeScript)."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-003")
def test_openai_example_has_readme_and_manifest_and_entry_points(
    example_root: Path,
) -> None:
    """README, relay.manifest.yaml, and per-language entry points exist."""
    assert (example_root / "README.md").is_file(), "README.md missing"
    assert (example_root / "relay.manifest.yaml").is_file(), (
        "relay.manifest.yaml missing at example root"
    )
    # Per-language subdirs each ship a runnable entry point.
    py_main = example_root / "python" / "main.py"
    ts_main = example_root / "typescript" / "main.ts"
    assert py_main.is_file(), "python/main.py entry point missing"
    assert ts_main.is_file(), "typescript/main.ts entry point missing"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-023")
def test_openai_example_root_contains_only_permitted_files(
    example_root: Path,
) -> None:
    """Per VAL-W16-023 root contains only README, relay.manifest.yaml,
    pyproject.toml / package.json, .gitignore, and the language subdirs.
    """
    actual: set[str] = set()
    for child in example_root.iterdir():
        # Ignore dotfiles other than .gitignore; ignore pytest/build caches.
        if child.name.startswith(".") and child.name != ".gitignore":
            continue
        actual.add(child.name)
    expected = PERMITTED_ROOT_FILES | PERMITTED_ROOT_SUBDIRS
    unexpected = actual - expected
    assert not unexpected, (
        f"Unexpected entries at examples/openai-tool-agent/ root: "
        f"{sorted(unexpected)}. Only {sorted(expected)} are permitted "
        "per VAL-W16-023."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-023")
def test_openai_example_has_no_todo_fixme_hack(example_root: Path) -> None:
    """Anti-hack grep: TODO/FIXME/XXX/HACK markers absent across the example."""
    offenders: list[str] = []
    for path in example_root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix not in SCANNED_SUFFIXES:
            continue
        # Skip vendored / generated files if any (none expected at this
        # point but defensive).
        rel = path.relative_to(example_root)
        if any(part in {"node_modules", "__pycache__", ".venv", "dist"} for part in rel.parts):
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
        "VAL-W16-023 anti-hack markers found in examples/openai-tool-agent/:\n"
        + "\n".join(offenders)
    )
