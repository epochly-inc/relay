"""Guard registry index test (VAL-V3M5-024, spec section U).

Asserts that ``docs/guards/INDEX.md`` is a complete, current, and
machine-checkable index for the ten guards enumerated in CLAUDE.md
"REQUIRED GUARD TESTS".

Concretely the test asserts three properties:

  1. **Completeness.** Every canonical guard name in
     :data:`REQUIRED_GUARD_NAMES` (derived verbatim from the CLAUDE.md
     "REQUIRED GUARD TESTS" table) appears as a row in the index table.

  2. **Path existence.** Every ``Test file path`` cell in the index
     resolves to a real file on disk at the repository root. Paths are
     repository-relative (e.g. ``apps/local-sidecar/tests/foo.py``).

  3. **Function existence.** Every ``Test function`` cell resolves to a
     top-level ``def test_<name>`` or ``async def test_<name>``
     declaration in the file named on the same row.

CLAUDE.md is also parsed directly so a future addition / rename in the
spec's REQUIRED GUARD TESTS table cannot drift away from this index
without triggering a test failure here.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Repository root resolution
# ---------------------------------------------------------------------------
#
# This file lives at ``tests/guards/test_guard_registry_index.py`` relative
# to the public ``relay/`` repository root. ``parents[2]`` is therefore the
# ``relay/`` directory itself.
REPO_ROOT = Path(__file__).resolve().parents[2]
INDEX_PATH = REPO_ROOT / "docs" / "guards" / "INDEX.md"


# ---------------------------------------------------------------------------
# Canonical guard names (CLAUDE.md "REQUIRED GUARD TESTS" table)
# ---------------------------------------------------------------------------
#
# These strings MUST match the "Guard" column of the table in CLAUDE.md
# byte-for-byte modulo trailing whitespace. The test also re-parses
# CLAUDE.md and asserts that the names below remain a complete reflection
# of the upstream table, so an out-of-band rename in CLAUDE.md is caught
# here rather than silently leaving the index stale.
REQUIRED_GUARD_NAMES: tuple[str, ...] = (
    "RunResult ownership guard",
    "Coverage invariant guard",
    "Gate restart guard",
    "Stale handoff guard",
    "Evidence pairing guard",
    "Manifest source-of-truth guard",
    "Side-effect idempotency guard",
    "Atomic write guard",
    "Anti-bypass guard",
    "Context reinjection guard",
)


# ---------------------------------------------------------------------------
# Markdown table parser
# ---------------------------------------------------------------------------

_TABLE_HEADER_RE = re.compile(
    r"^\s*\|\s*Guard name\s*\|\s*Asserts\s*\|\s*Test file path\s*\|\s*Test function\s*\|\s*$"
)
_TABLE_SEPARATOR_RE = re.compile(r"^\s*\|\s*-+\s*\|.*\|\s*$")
_TABLE_ROW_RE = re.compile(r"^\s*\|(.+)\|\s*$")


def _parse_index_rows(text: str) -> list[dict[str, str]]:
    """Parse the four-column guard registry table out of INDEX.md.

    Returns a list of {guard_name, asserts, test_file_path, test_function}
    dicts (in declaration order). Cells are stripped of leading/trailing
    whitespace. The parser is deliberately strict: it requires the exact
    four-column header and is anchored on the first such header that
    appears in the document, so accidental nested tables elsewhere in
    the doc cannot pollute the result.
    """
    lines = text.splitlines()
    rows: list[dict[str, str]] = []
    in_table = False
    saw_separator = False
    for line in lines:
        if not in_table:
            if _TABLE_HEADER_RE.match(line):
                in_table = True
                saw_separator = False
            continue
        # We are inside the table.
        if not saw_separator:
            if _TABLE_SEPARATOR_RE.match(line):
                saw_separator = True
                continue
            # The line right after the header must be the separator;
            # anything else means the table was malformed.
            pytest.fail(
                f"Malformed guard index table: expected separator row after header, got: {line!r}"
            )
        row_match = _TABLE_ROW_RE.match(line)
        if row_match is None:
            # First non-row line terminates the table.
            break
        cells = [cell.strip() for cell in row_match.group(1).split("|")]
        if len(cells) != 4:
            pytest.fail(
                "Malformed guard index row: expected 4 cells, "
                f"got {len(cells)}: {line!r}"
            )
        rows.append(
            {
                "guard_name": cells[0],
                "asserts": cells[1],
                "test_file_path": cells[2],
                "test_function": cells[3],
            }
        )
    return rows


# ---------------------------------------------------------------------------
# CLAUDE.md REQUIRED GUARD TESTS parser
# ---------------------------------------------------------------------------
#
# CLAUDE.md is checked into the repository root. The table appears under
# the "REQUIRED GUARD TESTS" subsection. We parse the table's first column
# and assert REQUIRED_GUARD_NAMES is the exact set of guard names there.


def _parse_claude_md_required_guards() -> set[str]:
    claude_md = REPO_ROOT.parent / "CLAUDE.md"
    if not claude_md.exists():
        pytest.skip(
            "Workspace CLAUDE.md not found relative to relay/ -- "
            "test runs only inside the epochly-relay workspace layout."
        )
    text = claude_md.read_text(encoding="utf-8")
    # Find the heading "REQUIRED GUARD TESTS" (case-insensitive ok), then
    # parse the next markdown table whose header starts with "Guard".
    heading_idx = text.upper().find("REQUIRED GUARD TESTS")
    if heading_idx < 0:
        pytest.fail(
            "CLAUDE.md does not contain the 'REQUIRED GUARD TESTS' heading; "
            "the guard registry index has lost its upstream reference."
        )
    sub = text[heading_idx:]
    lines = sub.splitlines()
    guards: set[str] = set()
    in_table = False
    saw_separator = False
    for line in lines:
        stripped = line.strip()
        if not in_table:
            if (
                stripped.startswith("|")
                and "guard" in stripped.lower()
                and "asserts" in stripped.lower()
            ):
                in_table = True
                saw_separator = False
            continue
        if not saw_separator:
            if stripped.startswith("|") and set(stripped.replace("|", "").strip()) <= {
                "-",
                " ",
            }:
                saw_separator = True
                continue
            # Header without separator -- malformed.
            break
        if not stripped.startswith("|"):
            break
        cells = [c.strip() for c in stripped.strip("|").split("|")]
        if not cells or not cells[0]:
            break
        # Normalize: CLAUDE.md formats some guard names with inline-code
        # backticks for the identifier (e.g. "`RunResult` ownership guard").
        # The INDEX.md table uses plain prose ("RunResult ownership guard").
        # Strip backticks for comparison so the two surfaces can use the
        # presentation they prefer without drifting semantically.
        normalized = cells[0].replace("`", "")
        guards.add(normalized)
    return guards


# ---------------------------------------------------------------------------
# Test function discovery helpers
# ---------------------------------------------------------------------------

_TEST_FN_RE_TEMPLATE = (
    r"^\s*(?:async\s+)?def\s+{name}\s*\("
)


def _file_contains_test_function(file_path: Path, function_name: str) -> bool:
    """True if ``def <function_name>(`` (optionally ``async``) appears at
    the start of any line in ``file_path``.

    We deliberately do NOT import the test module: importing forces a full
    package-resolution pass that pulls in optional dependencies and is
    far slower than a regex scan. The regex anchors on line start so
    accidental references inside docstrings or comments are not matched.
    """
    pattern = re.compile(_TEST_FN_RE_TEMPLATE.format(name=re.escape(function_name)), re.M)
    text = file_path.read_text(encoding="utf-8")
    return bool(pattern.search(text))


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def index_rows() -> list[dict[str, str]]:
    assert INDEX_PATH.exists(), (
        f"docs/guards/INDEX.md is missing at {INDEX_PATH}; the guard registry "
        "doc is required by VAL-V3M5-024."
    )
    rows = _parse_index_rows(INDEX_PATH.read_text(encoding="utf-8"))
    assert rows, "Guard registry index parsed zero rows."
    return rows


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M5-024")
def test_index_has_row_for_every_required_guard(index_rows: list[dict[str, str]]) -> None:
    """Completeness: every CLAUDE.md guard name has a row in INDEX.md."""
    listed = {row["guard_name"] for row in index_rows}
    missing = sorted(set(REQUIRED_GUARD_NAMES) - listed)
    assert not missing, (
        "docs/guards/INDEX.md is missing rows for the following CLAUDE.md "
        f"REQUIRED GUARD TESTS guards: {missing}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M5-024")
def test_index_does_not_introduce_unknown_guards(
    index_rows: list[dict[str, str]],
) -> None:
    """Inverse coverage: every row in INDEX.md is a recognised CLAUDE.md
    guard. Prevents drift in the opposite direction (someone adds a row
    here that does not correspond to a CLAUDE.md entry)."""
    listed = {row["guard_name"] for row in index_rows}
    extra = sorted(listed - set(REQUIRED_GUARD_NAMES))
    assert not extra, (
        "docs/guards/INDEX.md lists guards not present in CLAUDE.md "
        f"REQUIRED GUARD TESTS: {extra}. Update REQUIRED_GUARD_NAMES "
        "or remove the extra row."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M5-024")
def test_required_guard_names_match_claude_md(
    index_rows: list[dict[str, str]],
) -> None:
    """REQUIRED_GUARD_NAMES is in sync with CLAUDE.md's table.

    This guards against an out-of-band rename in CLAUDE.md that the
    constant here did not pick up. If this fails, update both
    REQUIRED_GUARD_NAMES and the index's first column.
    """
    upstream = _parse_claude_md_required_guards()
    assert upstream == set(REQUIRED_GUARD_NAMES), (
        "REQUIRED_GUARD_NAMES has drifted from CLAUDE.md REQUIRED GUARD TESTS. "
        f"In CLAUDE.md only: {sorted(upstream - set(REQUIRED_GUARD_NAMES))}. "
        f"In REQUIRED_GUARD_NAMES only: {sorted(set(REQUIRED_GUARD_NAMES) - upstream)}."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M5-024")
@pytest.mark.parametrize(
    "guard_name",
    REQUIRED_GUARD_NAMES,
    ids=lambda name: name.replace(" ", "_").replace("-", "_"),
)
def test_referenced_test_file_exists(
    index_rows: list[dict[str, str]],
    guard_name: str,
) -> None:
    """Path existence: each guard's referenced test file is a real file."""
    matching = [row for row in index_rows if row["guard_name"] == guard_name]
    assert matching, f"No row for guard {guard_name!r} in docs/guards/INDEX.md"
    row = matching[0]
    rel_path = row["test_file_path"]
    abs_path = REPO_ROOT / rel_path
    assert abs_path.exists(), (
        f"Guard {guard_name!r} references {rel_path} but that file does not "
        f"exist at {abs_path}. Either the path is stale (re-point the row) "
        "or the test file was removed (restore it)."
    )
    assert abs_path.is_file(), (
        f"Guard {guard_name!r} references {rel_path} but the path is not a file."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M5-024")
@pytest.mark.parametrize(
    "guard_name",
    REQUIRED_GUARD_NAMES,
    ids=lambda name: name.replace(" ", "_").replace("-", "_"),
)
def test_referenced_test_function_exists(
    index_rows: list[dict[str, str]],
    guard_name: str,
) -> None:
    """Function existence: the named test function lives in the named file."""
    matching = [row for row in index_rows if row["guard_name"] == guard_name]
    assert matching, f"No row for guard {guard_name!r} in docs/guards/INDEX.md"
    row = matching[0]
    rel_path = row["test_file_path"]
    function_name = row["test_function"]
    abs_path = REPO_ROOT / rel_path
    assert abs_path.exists(), (
        f"Pre-condition failed: {rel_path} must exist before function check."
    )
    found = _file_contains_test_function(abs_path, function_name)
    assert found, (
        f"Guard {guard_name!r}: test function {function_name!r} not found in "
        f"{rel_path}. Either the function was renamed (update the row) or "
        "the row points at the wrong file."
    )
