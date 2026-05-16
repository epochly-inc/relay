"""Structural / static-file assertions for the Vercel AI tool-agent example.

Covers (W16.3 primary owner + cross-cutting share with W16.1):
  VAL-W16-009: Vercel AI SDK example is TypeScript only -- the directory
               examples/vercel-ai-tool-agent/ MUST contain a typescript/
               subdirectory and MUST NOT contain a python/ subdirectory.
  VAL-W16-023: no TODO/FIXME/HACK and no debug-file artifacts; only the
               permitted root files are present at the example root.

Per the contract coverage map the Vercel AI SDK example is TS-only (the
Vercel AI SDK is TS-native; Python has no equivalent, per W3 surfaced
asymmetry and spec section S P0 adapter placement); there is no
python/ subdirectory. The root contains README.md, relay.manifest.yaml,
package.json, .gitignore, and the typescript/ subdir only.

Tier-1 plumbing: inspects files on disk; no sidecar, no provider key.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def vercel_example_root() -> Path:
    """Return the vercel-ai-tool-agent example root."""
    return REPO_ROOT / "examples" / "vercel-ai-tool-agent"


# Files permitted at the example-app root per VAL-W16-023. The Vercel AI
# example is TS-only (per contract coverage map + VAL-W16-009 invariant);
# no pyproject.toml at the example root.
PERMITTED_ROOT_FILES: frozenset[str] = frozenset(
    {
        "README.md",
        "relay.manifest.yaml",
        "package.json",
        ".gitignore",
    }
)

PERMITTED_ROOT_SUBDIRS: frozenset[str] = frozenset({"typescript"})

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
@pytest.mark.fulfills("VAL-W16-009")
def test_vercel_example_root_exists(vercel_example_root: Path) -> None:
    """The example directory exists at examples/vercel-ai-tool-agent/."""
    assert vercel_example_root.is_dir(), (
        f"examples/vercel-ai-tool-agent/ must exist; got {vercel_example_root}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-009")
def test_vercel_example_has_typescript_subdir(vercel_example_root: Path) -> None:
    """Per VAL-W16-009 the example MUST ship a typescript/ subdirectory."""
    ts_dir = vercel_example_root / "typescript"
    assert ts_dir.is_dir(), (
        "examples/vercel-ai-tool-agent/typescript/ missing "
        "(VAL-W16-009: TypeScript-only example)."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-009")
def test_vercel_example_does_not_have_python_subdir(
    vercel_example_root: Path,
) -> None:
    """Per VAL-W16-009 the example MUST NOT contain a python/ subdirectory.

    This codifies the Python/TS asymmetry W3 surfaced: the Vercel AI SDK
    is TS-native and has no Python equivalent (the W3.5 Python adapter
    set does not include it). CI gate fails if a python/ subdirectory
    is added.
    """
    py_dir = vercel_example_root / "python"
    assert not py_dir.exists(), (
        "examples/vercel-ai-tool-agent/python/ MUST NOT exist "
        "(VAL-W16-009: TypeScript-only example; the Vercel AI SDK has "
        "no Python equivalent)."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-009")
def test_vercel_example_does_not_have_pyproject(
    vercel_example_root: Path,
) -> None:
    """Per VAL-W16-009 + VAL-W16-023 the TS-only example MUST NOT ship a
    pyproject.toml at the example root.
    """
    py_manifest = vercel_example_root / "pyproject.toml"
    assert not py_manifest.exists(), (
        "examples/vercel-ai-tool-agent/pyproject.toml MUST NOT exist "
        "(VAL-W16-009: TypeScript-only example)."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-009")
def test_vercel_example_ships_package_json(vercel_example_root: Path) -> None:
    """The TS example ships a package.json at the example root."""
    ts_manifest = vercel_example_root / "package.json"
    assert ts_manifest.is_file(), (
        "examples/vercel-ai-tool-agent/package.json missing "
        "(VAL-W16-009: TS-only example)."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-023")
def test_vercel_example_has_required_top_level_files(
    vercel_example_root: Path,
) -> None:
    """README, relay.manifest.yaml, package.json, and the typescript entry exist."""
    assert (vercel_example_root / "README.md").is_file(), (
        "examples/vercel-ai-tool-agent/README.md missing"
    )
    assert (vercel_example_root / "relay.manifest.yaml").is_file(), (
        "examples/vercel-ai-tool-agent/relay.manifest.yaml missing"
    )
    ts_main = vercel_example_root / "typescript" / "main.ts"
    assert ts_main.is_file(), "typescript/main.ts entry point missing"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-023")
def test_vercel_example_root_contains_only_permitted_files(
    vercel_example_root: Path,
) -> None:
    """Per VAL-W16-023 root contains only README, relay.manifest.yaml,
    package.json, .gitignore, and the typescript/ subdir.
    """
    actual: set[str] = set()
    for child in vercel_example_root.iterdir():
        if child.name.startswith(".") and child.name != ".gitignore":
            continue
        if child.name in {"__pycache__", ".venv", "dist", "node_modules"}:
            continue
        actual.add(child.name)
    expected = PERMITTED_ROOT_FILES | PERMITTED_ROOT_SUBDIRS
    unexpected = actual - expected
    assert not unexpected, (
        f"Unexpected entries at examples/vercel-ai-tool-agent/ root: "
        f"{sorted(unexpected)}. Only {sorted(expected)} are permitted "
        "per VAL-W16-023."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-023")
def test_vercel_example_has_no_todo_fixme_hack(
    vercel_example_root: Path,
) -> None:
    """Anti-hack grep: TODO/FIXME/XXX/HACK markers absent across the example."""
    offenders: list[str] = []
    for path in vercel_example_root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix not in SCANNED_SUFFIXES:
            continue
        rel = path.relative_to(vercel_example_root)
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
        "VAL-W16-023 anti-hack markers found in examples/vercel-ai-tool-agent/:\n"
        + "\n".join(offenders)
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-021")
def test_vercel_example_is_platform_agnostic(
    vercel_example_root: Path,
) -> None:
    """The example MUST run on macOS, Linux, AND Windows. Node-specific
    APIs that are POSIX-only are not invoked unconditionally; Windows
    path separators are not hard-coded.
    """
    ts_main = (vercel_example_root / "typescript" / "main.ts").read_text(
        encoding="utf-8"
    )
    # Node forbids no-op for these on Windows, but examples must use
    # node:path / node:url for portability. Hard-coded posix separators
    # in literal paths break Windows.
    assert "\\\\" not in ts_main, (
        "main.ts must not hard-code Windows backslashes; use node:path "
        "(VAL-W16-021)"
    )
    # Use of node:path or path is the portable form; node:fs and node:url
    # also acceptable. Forbid direct child_process.spawn on POSIX-only
    # binaries unconditionally.
    forbidden_unconditional_posix = (
        "/bin/sh",
        "/usr/bin/env",
    )
    for pattern in forbidden_unconditional_posix:
        # Allowed inside comments/markdown; for source we strip nothing
        # because comments in main.ts may legitimately mention paths.
        # We use a stricter check: literal use as a string argument to
        # child_process.* would be unsafe. A loose grep on the string
        # is sufficient because the example is small.
        if pattern in ts_main:
            # Only fail if the pattern is in a code path, not a comment.
            # Conservative heuristic: a line containing the pattern AND
            # any of ('spawn', 'exec', 'execFile') is suspect.
            for line in ts_main.splitlines():
                if pattern in line and any(
                    proc in line for proc in ("spawn(", "exec(", "execFile(")
                ):
                    raise AssertionError(
                        f"main.ts invokes POSIX-only binary path "
                        f"{pattern!r} via child_process; breaks Windows "
                        "(VAL-W16-021 platform parity)."
                    )
