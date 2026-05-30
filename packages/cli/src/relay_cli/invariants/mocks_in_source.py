"""Mocks-in-non-test-source checker (VAL-W5-033).

Per CLAUDE.md banned pattern #4 + boundaries.md sec 6 (B4): mocks live
ONLY in test paths. Production source under ``packages/`` / ``services/``
/ ``apps/`` MUST NOT import a mock primitive.

The check matches the same regex specified by contract VAL-W5-033:
``from unittest.mock|MagicMock\\(|@patch\\(|@mock\\.``. Test paths are
filtered by :func:`relay_cli.invariants.util.iter_source_files` which
already excludes the canonical ``tests/`` subtrees and
``packages/sdk-typescript/test/``. We additionally exclude
``test_*.py``, ``*.test.ts``, and ``conftest.py`` files at the per-file
layer because they may live outside an excluded ``tests/`` prefix.
Project-specific test-helper basenames (e.g. ``_w25_helpers.py``) are
exempted ONLY when they actually live under a ``tests/`` directory; the
exemption is NOT applied globally by basename, so a production source
file sharing the name cannot smuggle a mock import past the check
(VAL-ISO-037).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final

from verify_self.finding_codes import RELAY_VERIFY_SELF_MOCK_IN_SOURCE

from .util import (
    Finding,
    iter_source_files,
    suggested_fix_for,
)

CHECK_NAME: Final[str] = "no-mocks-in-prod"

# Mock-import regex (VAL-W5-033 verbatim). The pattern recognises:
#   * Python ``from unittest.mock import ...``
#   * Python ``MagicMock(`` instantiation
#   * Python ``@patch(`` decorator
#   * Python ``@mock.<member>`` decorator
# A future feature can extend the regex to TS (``vi.mock``, ``sinon``) when
# the TS source tree grows beyond fixtures. The current regex is the
# contract-specified shape.
_MOCK_RE: Final[re.Pattern[str]] = re.compile(
    r"from\s+unittest\.mock|MagicMock\(|@patch\(|@mock\."
)

# Unconditional per-file exclusions: filenames that are test-only by
# convention REGARDLESS of directory. ``conftest.py`` is the pytest
# fixture-collection file and is test-only everywhere by definition.
_PER_FILE_EXCLUDES: Final[tuple[str, ...]] = ("conftest.py",)

# Test-tree-scoped per-file exclusions: project-specific test helper
# basenames that are ONLY test-only when they actually live under a
# ``tests/`` directory. ``_w25_helpers.py`` is a shared helper module
# imported by the W2.5 sidecar tests; it legitimately uses mocks, but
# the exemption MUST be scoped to ``tests/`` so a production source file
# that happens to share the basename cannot smuggle a mock import into
# shipping code (VAL-ISO-037 -- the basename allowlist was previously
# applied across the whole tree, exempting any non-test file with this
# name).
_TEST_SCOPED_PER_FILE_EXCLUDES: Final[tuple[str, ...]] = ("_w25_helpers.py",)


def _under_tests_dir(path: Path) -> bool:
    """Return True iff ``path`` has a ``tests`` directory segment.

    Matches both ``.../tests/...`` (Python) and ``.../test/...``
    (vitest) path segments, case-sensitively, so the test-scoped
    exemptions only apply inside genuine test trees.
    """
    return "tests" in path.parts or "test" in path.parts


def _is_test_filename(path: Path) -> bool:
    """Return True for files that are test-only by convention.

    Unconditional test filenames (``test_*.py``, ``*.test.ts``,
    ``conftest.py`` ...) are test-only regardless of location. The
    project-specific helper basenames in
    :data:`_TEST_SCOPED_PER_FILE_EXCLUDES` are test-only ONLY when they
    live under a ``tests/`` directory (VAL-ISO-037).
    """
    name = path.name
    if name.startswith("test_") and (name.endswith(".py") or name.endswith(".pyi")):
        return True
    if name.endswith(".test.ts") or name.endswith(".test.tsx"):
        return True
    if name.endswith(".test.js") or name.endswith(".test.jsx"):
        return True
    if name.endswith(".spec.ts") or name.endswith(".spec.tsx"):
        return True
    if name.endswith(".spec.js") or name.endswith(".spec.jsx"):
        return True
    if name in _PER_FILE_EXCLUDES:
        return True
    return name in _TEST_SCOPED_PER_FILE_EXCLUDES and _under_tests_dir(path)


def run(repo_root: Path) -> tuple[str, list[Finding]]:
    """Run the no-mocks-in-prod check against ``repo_root``.

    Returns ``(check_name, findings)`` sorted by ``(file, line, code)``
    for reproducible output (VAL-W5-038).
    """
    findings: list[Finding] = []
    for path in iter_source_files(repo_root):
        if _is_test_filename(path):
            continue
        # Only Python sources can import unittest.mock; .py / .pyi only.
        if path.suffix not in (".py", ".pyi"):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(path.relative_to(repo_root))
        for line_no_minus_one, line in enumerate(text.split("\n")):
            m = _MOCK_RE.search(line)
            if m is None:
                continue
            findings.append(
                Finding(
                    file=rel,
                    line=line_no_minus_one + 1,
                    code=RELAY_VERIFY_SELF_MOCK_IN_SOURCE,
                    suggested_fix=suggested_fix_for(
                        RELAY_VERIFY_SELF_MOCK_IN_SOURCE
                    ),
                    pattern=m.group(0),
                )
            )
    findings.sort(key=lambda f: (f.file, f.line, f.code))
    return CHECK_NAME, findings


__all__ = ["CHECK_NAME", "run"]
