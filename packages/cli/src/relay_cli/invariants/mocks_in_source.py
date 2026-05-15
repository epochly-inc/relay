"""Mocks-in-non-test-source checker (VAL-W5-033).

Per CLAUDE.md banned pattern #4 + boundaries.md sec 6 (B4): mocks live
ONLY in test paths. Production source under ``packages/`` / ``services/``
/ ``apps/`` MUST NOT import a mock primitive.

The check matches the same regex specified by contract VAL-W5-033:
``from unittest.mock|MagicMock\\(|@patch\\(|@mock\\.``. Test paths are
filtered by :func:`relay_cli.invariants.util.iter_source_files` which
already excludes ``**/tests/`` and ``packages/sdk-typescript/test/``.
We additionally exclude ``test_*.py`` and ``conftest.py`` files at the
per-file layer because they may live outside a ``tests/`` directory in
TS package roots.

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

# Per-file exclusions. Test files often live alongside non-test source
# in TS workspaces; ``test_*.py`` and ``conftest.py`` are unconditionally
# test-only across both Python and TS conventions.
_PER_FILE_EXCLUDES: Final[tuple[str, ...]] = (
    "conftest.py",
    "_w25_helpers.py",
)


def _is_test_filename(path: Path) -> bool:
    """Return True for filenames that are test-only by convention."""
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
    return name in _PER_FILE_EXCLUDES


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
