"""ISO-037 regression: _w25_helpers.py exemption must be scoped to tests/.

Reproduces VAL-ISO-037. The mocks-in-source checker
(``relay_cli.invariants.mocks_in_source.run``) exempts any file whose
basename is ``_w25_helpers.py`` via the ``_PER_FILE_EXCLUDES`` allowlist
and ``_is_test_filename``. The exemption is applied by basename ACROSS
THE WHOLE TREE -- it is not scoped to ``tests/`` directories. So a
production source file named ``_w25_helpers.py`` placed outside any
``tests/`` directory can import ``unittest.mock`` and be silently
exempted (CLAUDE.md banned pattern #4 bypass).

RED at base commit (the non-test helper is exempted -> no finding);
GREEN after the exemption is scoped to ``tests/`` paths.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from pathlib import Path

import pytest
from relay_cli.invariants import mocks_in_source
from verify_self.finding_codes import RELAY_VERIFY_SELF_MOCK_IN_SOURCE

_MOCK_SRC = (
    '"""helper with a banned mock import."""\n'
    "from unittest.mock import MagicMock\n"
    "\n"
    "def helper():\n"
    "    return MagicMock()\n"
)


def _make_clean_tree(root: Path) -> None:
    src = root / "packages" / "okpkg" / "src"
    src.mkdir(parents=True)
    (src / "module.py").write_text(
        '"""Clean module."""\n\n\ndef helper() -> int:\n    return 42\n',
        encoding="utf-8",
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-037")
def test_w25_helper_outside_tests_is_detected(tmp_path: Path) -> None:
    """A _w25_helpers.py OUTSIDE a tests/ dir importing a mock is detected.

    This is the load-bearing regression: prior to the fix the basename
    allowlist exempts the file globally, so the banned mock import in
    production source is silently passed.
    """
    _make_clean_tree(tmp_path)
    # Production source path -- NOT under any tests/ directory.
    prod = tmp_path / "packages" / "okpkg" / "src" / "_w25_helpers.py"
    prod.write_text(_MOCK_SRC, encoding="utf-8")

    _name, findings = mocks_in_source.run(tmp_path)

    assert any(
        f.file.endswith("_w25_helpers.py")
        and f.code == RELAY_VERIFY_SELF_MOCK_IN_SOURCE
        for f in findings
    ), (
        "expected a mock-in-source finding on the non-test "
        "_w25_helpers.py; got " + repr(findings)
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-037")
def test_w25_helper_inside_tests_is_exempt(tmp_path: Path) -> None:
    """A genuine _w25_helpers.py UNDER a tests/ dir stays exempt.

    Guards against the fix becoming over-broad: legitimate test helpers
    that live under a tests/ tree may import mocks.
    """
    _make_clean_tree(tmp_path)
    test_dir = tmp_path / "packages" / "okpkg" / "tests"
    test_dir.mkdir(parents=True)
    (test_dir / "_w25_helpers.py").write_text(_MOCK_SRC, encoding="utf-8")

    _name, findings = mocks_in_source.run(tmp_path)

    assert not any(
        f.file.endswith("_w25_helpers.py") for f in findings
    ), (
        "a _w25_helpers.py under tests/ must remain exempt; got "
        + repr(findings)
    )
