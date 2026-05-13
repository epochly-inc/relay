"""VAL-W2-005: ``local_atomic_file_write`` is the only writer of ``sidecar.lock``.

Grep guard:

  rg "open\\(.*sidecar\\.lock.*['\"]w['\"]" apps/local-sidecar/ packages/cli/

MUST return empty. Direct ``Path.write_text``, ``Path.write_bytes``, and
``shutil.copy`` against the lockfile path are also banned.

This test runs a Python implementation of the grep so it works on the
macOS / Linux / Windows test matrix without depending on a ripgrep
binary.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

# Repo root: apps/local-sidecar/tests/test_atomic_primitive_guard.py
# -> parents[3]
REPO_ROOT = Path(__file__).resolve().parents[3]


SCANNED_DIRS = (
    REPO_ROOT / "apps" / "local-sidecar",
    REPO_ROOT / "packages" / "cli",
)


# Patterns that would indicate a bypass of local_atomic_file_write.
BANNED_PATTERNS = (
    re.compile(r"open\([^)]*sidecar\.lock[^)]*['\"]w['\"]"),
    re.compile(r"\.write_text\([^)]*\)\s*$"),
    re.compile(r"\.write_bytes\([^)]*\)\s*$"),
)


# Allow-list: files where mentioning the patterns is part of the test or
# primitive itself. The primitive's own source MAY include the temp-file
# fdopen path (which is NOT direct-write to ``sidecar.lock`` but to a
# sibling tempfile). The grep guard explicitly excludes these.
ALLOWLIST = (
    "apps/local-sidecar/tests/test_atomic_primitive_guard.py",
    "apps/local-sidecar/relay_sidecar/primitives/local_atomic_file_write.py",
)


def _is_allowlisted(path: Path) -> bool:
    rel = str(path.relative_to(REPO_ROOT))
    return rel in ALLOWLIST


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-005")
def test_no_direct_open_write_on_sidecar_lock() -> None:
    """Grep guard: ``open(<path>, 'w')`` against ``sidecar.lock`` is banned."""
    pattern = re.compile(r"open\([^)]*sidecar\.lock[^)]*['\"]w['\"]")
    offenders: list[str] = []
    for root in SCANNED_DIRS:
        if not root.exists():
            continue
        for py in root.rglob("*.py"):
            if _is_allowlisted(py):
                continue
            try:
                text = py.read_text(encoding="utf-8")
            except OSError:
                continue
            for lineno, line in enumerate(text.splitlines(), start=1):
                if pattern.search(line):
                    offenders.append(f"{py}:{lineno}: {line.strip()}")
    assert not offenders, "VAL-W2-005 violations:\n" + "\n".join(offenders)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-005")
def test_no_write_text_or_write_bytes_on_lockfile_path() -> None:
    """No ``Path.write_text``/``Path.write_bytes`` lines that mention sidecar.lock."""
    pattern = re.compile(
        r"\.write_(text|bytes)\([^)]*\)"
    )
    sidecar_lock_pattern = re.compile(r"sidecar\.lock")
    offenders: list[str] = []
    for root in SCANNED_DIRS:
        if not root.exists():
            continue
        for py in root.rglob("*.py"):
            if _is_allowlisted(py):
                continue
            try:
                text = py.read_text(encoding="utf-8")
            except OSError:
                continue
            for lineno, line in enumerate(text.splitlines(), start=1):
                if sidecar_lock_pattern.search(line) and pattern.search(line):
                    offenders.append(f"{py}:{lineno}: {line.strip()}")
    assert not offenders, "VAL-W2-005 violations:\n" + "\n".join(offenders)
