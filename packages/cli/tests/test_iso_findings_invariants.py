"""Regression tests for isolated bug-hunt findings VAL-ISO-005 and VAL-ISO-014.

VAL-ISO-005: The Sigstore/Rekor/TSA ``*-verifier-implemented`` checks must
read the ``*_CRYPTO_IMPLEMENTED`` flag from the SOURCE FILE under the
operator-supplied ``repo_root``, not from the installed package on
``sys.path``. Otherwise ``rly verify-self --repo-root <other-tree>``
validates the wrong tree: it reports the installed wheel's flag (True)
instead of the source flag under the tree being checked (potentially
False).

VAL-ISO-014: The atomic-primitives documentation classifier (heuristic 2)
must correctly handle runs of backslashes preceding a quote. A line whose
preceding string literal ends in an escaped backslash (``"\\\\"``) must not
have its closing quote treated as escaped -- otherwise quote parity
inverts and a real atomic-primitive bypass after a closed string is
mis-classified as documentation and silently passes the verifier.

Per CLAUDE.md TDD discipline both tests reproduce the finding's trigger:
RED at the defect, GREEN after the fix.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest
from relay_cli.invariants import (
    atomic_primitives,
    rekor_verifier,
    sigstore_verifier,
    tsa_verifier,
)

pytestmark = pytest.mark.plumbing


# ---------------------------------------------------------------------------
# VAL-ISO-005: crypto-implemented flag read from --repo-root source file.
# ---------------------------------------------------------------------------


def _write_flag_source(
    repo_root: Path, rel_source: str, flag_name: str, value: bool
) -> None:
    """Materialize a source file under ``repo_root`` declaring ``flag_name``.

    The declaration mirrors the canonical shape the production source uses
    (``<NAME>: Final[bool] = <value>``) so the source-reading parser the
    fix introduces matches the real declaration form.
    """
    src = repo_root / rel_source
    src.parent.mkdir(parents=True, exist_ok=True)
    src.write_text(
        textwrap.dedent(
            f"""\
            from typing import Final

            {flag_name}: Final[bool] = {value!r}
            """
        ),
        encoding="utf-8",
    )


_VERIFIER_CASES = (
    pytest.param(
        sigstore_verifier,
        "packages/cli/src/relay_cli/bundle.py",
        "VERIFIER_SIGSTORE_CRYPTO_IMPLEMENTED",
        id="sigstore",
    ),
    pytest.param(
        rekor_verifier,
        "packages/cli/src/relay_cli/commands/verify_install.py",
        "REKOR_CRYPTO_IMPLEMENTED",
        id="rekor",
    ),
    pytest.param(
        tsa_verifier,
        "packages/verifier/src/relay_verifier/tsa.py",
        "TSA_CRYPTO_IMPLEMENTED",
        id="tsa",
    ),
)


@pytest.mark.fulfills("VAL-ISO-005")
@pytest.mark.parametrize("module, rel_source, flag_name", _VERIFIER_CASES)
def test_implemented_check_reads_flag_from_repo_root_false(
    module: object, rel_source: str, flag_name: str, tmp_path: Path
) -> None:
    """A repo_root tree whose flag is False reports NOT-implemented.

    The installed package on sys.path has the flag True (M09 flipped it).
    Pointing the check at a synthetic tree where the source flag is False
    must produce exactly one finding -- the check must read the operator's
    tree, not the installed wheel.
    """
    _write_flag_source(tmp_path, rel_source, flag_name, value=False)
    check_name, findings = module.run(tmp_path)  # type: ignore[attr-defined]
    assert len(findings) == 1, (
        f"{check_name}: expected one not-implemented finding when the "
        f"source flag under repo_root is False, got {findings!r}"
    )
    finding = findings[0]
    assert finding.file == rel_source
    # The finding's line points at the flag declaration in the source tree.
    declared_line = (
        (tmp_path / rel_source)
        .read_text(encoding="utf-8")
        .splitlines()
        .index(f"{flag_name}: Final[bool] = False")
        + 1
    )
    assert finding.line == declared_line, (
        f"{check_name}: finding line {finding.line} should point at the "
        f"flag declaration at line {declared_line}"
    )


@pytest.mark.fulfills("VAL-ISO-005")
@pytest.mark.parametrize("module, rel_source, flag_name", _VERIFIER_CASES)
def test_implemented_check_reads_flag_from_repo_root_true(
    module: object, rel_source: str, flag_name: str, tmp_path: Path
) -> None:
    """A repo_root tree whose flag is True reports implemented (zero findings)."""
    _write_flag_source(tmp_path, rel_source, flag_name, value=True)
    check_name, findings = module.run(tmp_path)  # type: ignore[attr-defined]
    assert findings == [], (
        f"{check_name}: expected zero findings when the source flag under "
        f"repo_root is True, got {findings!r}"
    )


@pytest.mark.fulfills("VAL-ISO-005")
@pytest.mark.parametrize("module, rel_source, flag_name", _VERIFIER_CASES)
def test_implemented_check_reports_missing_source_file(
    module: object, rel_source: str, flag_name: str, tmp_path: Path
) -> None:
    """An empty repo_root (no source file at all) reports NOT-implemented.

    Absence of the flag declaration is itself a regression of the canonical
    surface and must fail closed.
    """
    check_name, findings = module.run(tmp_path)  # type: ignore[attr-defined]
    assert len(findings) == 1, (
        f"{check_name}: expected one finding when the flag source file is "
        f"absent under repo_root, got {findings!r}"
    )
    assert findings[0].file == rel_source


# ---------------------------------------------------------------------------
# VAL-ISO-014: heuristic-2 backslash-escaped-quote handling.
# ---------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-ISO-014")
def test_escaped_backslash_does_not_hide_real_bypass() -> None:
    r"""A real bypass hidden behind an escaped-backslash quote run is detected.

    Source line (real backslashes/quotes):

        a = "p\\" + "//q" db.execute("DELETE")

    Trace of the defect:

      * ``"p\\"`` is a string whose content is ``p\`` -- the closing quote is
        preceded by a run of TWO backslashes (even), so the quote is NOT
        escaped and the string IS closed.
      * The naive single-char escape check (``line[idx-1] == "\"``) sees the
        one immediately-preceding backslash and wrongly SKIPS the closing
        quote, leaving quote parity at 1.
      * The next string ``"//q"`` opens at parity 2 (buggy) -- even.
      * The ``//`` inside ``"//q"`` is then read at even buggy parity and the
        classifier returns documentation=True, HIDING the live
        ``db.execute(`` bypass that follows.

    After the fix the backslash RUN is counted: the run before the closing
    quote of ``"p\\"`` is even, so that quote is recognized (parity 2), the
    second string opens at parity 3 (odd), the ``//`` is correctly seen as
    INSIDE the open string (not a comment), and the bypass is DETECTED.
    """
    # The Python literal below encodes the source line: each ``\\\\`` is two
    # literal backslashes in the source.
    line = 'a = "p\\\\" + "//q" db.execute("DELETE")'
    assert line == 'a = "p\\\\" + "//q" db.execute("DELETE")'  # documents intent
    match_start = line.index("db.execute(")
    is_doc = atomic_primitives._match_is_documentation(line, match_start)
    assert is_doc is False, (
        "a real db.execute( bypass following a string literal that ends in "
        "an escaped backslash (even backslash run) must NOT be classified as "
        f"documentation; line={line!r}"
    )


@pytest.mark.fulfills("VAL-ISO-014")
def test_escaped_backslash_hash_variant_does_not_hide_bypass() -> None:
    r"""Same defect, ``#`` comment marker variant: bypass is detected.

    Source line:

        a = "\\" "#q" db.execute("DELETE")

    ``"\\"`` is a single-char string holding a backslash (closing quote
    preceded by an even run of two backslashes -> closed). The buggy escape
    check skips that closing quote, mis-parities the following ``"#q"``
    string so the in-string ``#`` is read at even parity and the line is
    wrongly called documentation. The fix counts the backslash run and the
    ``#`` is correctly seen inside the open second string -> bypass detected.
    """
    line = 'a = "\\\\" "#q" db.execute("DELETE")'
    match_start = line.index("db.execute(")
    is_doc = atomic_primitives._match_is_documentation(line, match_start)
    assert is_doc is False, (
        "an in-string '#' mis-parityed by an escaped-backslash quote run "
        f"must not hide a real bypass; line={line!r}"
    )


@pytest.mark.fulfills("VAL-ISO-014")
def test_trailing_comment_after_closed_string_is_documentation() -> None:
    """A genuine trailing comment after a properly closed string is doc.

    Sanity floor: the fix must not break the legitimate trailing-comment
    case. ``y = "ok"  # db.execute(...)`` is documentation because the
    string is closed (even quote parity) and the ``#`` is a real comment.
    """
    line = 'y = "ok"  # db.execute("DELETE FROM gate_decisions")'
    match_start = line.index("db.execute(")
    is_doc = atomic_primitives._match_is_documentation(line, match_start)
    assert is_doc is True, (
        "a db.execute( mention inside a real trailing comment after a "
        f"closed string must remain documentation; line={line!r}"
    )


@pytest.mark.fulfills("VAL-ISO-014")
def test_trailing_comment_after_escaped_backslash_string_is_documentation() -> None:
    """A real trailing comment after a string ending in an escaped backslash.

    Source line:

        p = "a\\" + foo  # db.execute("x")

    The string ``"a\\"`` is closed (even backslash run); the ``#`` after it
    is a genuine trailing comment, so the ``db.execute(`` mention is
    documentation. The fix must classify this as documentation (correct
    parity is even at the ``#``). The pre-fix code happened to return False
    here (its own inverse mis-parity), so this case also moves from a wrong
    answer to the right one.
    """
    line = 'p = "a\\\\" + foo  # db.execute("x")'
    match_start = line.index("db.execute(")
    is_doc = atomic_primitives._match_is_documentation(line, match_start)
    assert is_doc is True, (
        "a real trailing comment after a closed escaped-backslash string "
        f"must be documentation; line={line!r}"
    )


# ---------------------------------------------------------------------------
# Guard-vacuity P2 (structural-review): the ``//`` line-comment heuristic
# must apply ONLY to languages where ``//`` is a comment (TS/JS), NOT to
# Python, where ``//`` is the floor-division operator. A Python production
# line containing floor division to the LEFT of a banned primitive call on
# the same physical line must be FLAGGED, not suppressed as documentation.
# The default caller (atomic_primitives.run for .py/.ts) invokes the
# matcher without sql=, so before the fix the ``//`` arm fired on Python
# source and the keystone-#8 guard went vacuous for that line.
# ---------------------------------------------------------------------------


def test_python_floor_division_before_bypass_is_flagged() -> None:
    """Python floor division left of a banned call must NOT be suppressed.

    ``chunk = size // 2; db.execute(q)`` is real Python production code:
    ``//`` is the floor-division OPERATOR, the statement separator ``;``
    runs ``db.execute(q)`` as a live call. The matcher must NOT treat the
    ``//`` as a comment start for Python -> the bypass is DETECTED.

    RED on current code: the default (TS/JS-style) ``//`` arm fires and
    classifies the line as documentation, suppressing the violation.
    GREEN after the fix: Python is told ``//`` is not a comment.
    """
    line = "chunk = size // 2; db.execute(q)"
    match_start = line.index("db.execute(")
    is_doc = atomic_primitives._match_is_documentation(
        line, match_start, slash_comment=False
    )
    assert is_doc is False, (
        "Python floor division ('//') left of a live db.execute( call must "
        f"NOT be classified as documentation; line={line!r}"
    )


def test_python_floor_division_open_write_is_flagged() -> None:
    """Floor division before a write-mode open() is flagged for Python.

    ``n = total // shards; open(path, 'w').write(b)`` -- the ``//`` is
    floor division, the ``open(..., 'w')`` is a real banned write. The
    matcher must not suppress it as a comment for Python.
    """
    line = "n = total // shards; open(path, 'w').write(b)"
    # The primitive regex matches the open(...,'w') arm; locate it.
    match_start = line.index("open(")
    is_doc = atomic_primitives._match_is_documentation(
        line, match_start, slash_comment=False
    )
    assert is_doc is False, (
        "Python floor division left of a write-mode open() must NOT be "
        f"classified as documentation; line={line!r}"
    )


def test_python_hash_comment_mentioning_bypass_is_documentation() -> None:
    """A genuine Python ``#`` comment mentioning a banned call stays doc.

    Disabling the ``//``-comment arm for Python must NOT disturb the real
    ``#`` Python comment heuristic. ``# do not call db.execute here`` is a
    full-line comment and remains documentation.
    """
    line = "    # do not call db.execute here"
    match_start = line.index("db.execute")
    is_doc = atomic_primitives._match_is_documentation(
        line, match_start, slash_comment=False
    )
    assert is_doc is True, (
        "a real Python '#' comment mentioning a banned call must remain "
        f"documentation; line={line!r}"
    )


def test_python_trailing_hash_comment_mentioning_bypass_is_documentation() -> None:
    """A genuine Python trailing ``#`` comment stays documentation.

    ``x = 1  # db.execute(q) is banned`` -- a real trailing comment. With
    ``//`` disabled for Python the ``#`` heuristic must still fire.
    """
    line = "x = 1  # db.execute(q) is banned"
    match_start = line.index("db.execute(")
    is_doc = atomic_primitives._match_is_documentation(
        line, match_start, slash_comment=False
    )
    assert is_doc is True, (
        "a real Python trailing '#' comment must remain documentation; "
        f"line={line!r}"
    )


def test_ts_full_line_slash_comment_mentioning_bypass_is_documentation() -> None:
    """A real TS/JS ``//`` full-line comment stays documentation.

    The ``//``-comment behavior MUST be preserved for TS/JS. A line like
    ``// db.execute(q)`` in a .ts file is a comment -> documentation.
    """
    line = "  // db.execute(q)"
    match_start = line.index("db.execute(")
    is_doc = atomic_primitives._match_is_documentation(
        line, match_start, slash_comment=True
    )
    assert is_doc is True, (
        "a real TS/JS '//' full-line comment mentioning a banned call must "
        f"remain documentation; line={line!r}"
    )


def test_ts_trailing_slash_comment_mentioning_bypass_is_documentation() -> None:
    """A real TS/JS trailing ``//`` comment stays documentation.

    ``const x = 1; // db.execute(q)`` -- the banned call lives in a real
    trailing ``//`` comment. Preserved for TS/JS.
    """
    line = "const x = 1; // db.execute(q)"
    match_start = line.index("db.execute(")
    is_doc = atomic_primitives._match_is_documentation(
        line, match_start, slash_comment=True
    )
    assert is_doc is True, (
        "a real TS/JS trailing '//' comment must remain documentation; "
        f"line={line!r}"
    )


def test_ts_real_bypass_with_trailing_comment_is_flagged() -> None:
    """A genuine TS/JS bypass with a trailing comment must be flagged.

    ``db.execute(q) // comment`` -- the ``db.execute(`` is a LIVE call;
    the ``//`` comment sits to the RIGHT of the match. The matcher must
    NOT suppress it (heuristic 2 only fires when the comment marker is to
    the LEFT of the match).
    """
    line = "db.execute(q) // run the query"
    match_start = line.index("db.execute(")
    is_doc = atomic_primitives._match_is_documentation(
        line, match_start, slash_comment=True
    )
    assert is_doc is False, (
        "a live TS/JS db.execute( call followed by a trailing '//' comment "
        f"must be flagged, not suppressed; line={line!r}"
    )


def test_default_slash_comment_preserves_ts_behavior() -> None:
    """The matcher default keeps ``//``-as-comment (TS/JS) semantics.

    Back-compat floor: callers that do not pass ``slash_comment`` retain
    the historical TS/JS behavior so existing call sites and the SQL
    caller's documented contract are unchanged.
    """
    line = "  // db.execute(q)"
    match_start = line.index("db.execute(")
    assert atomic_primitives._match_is_documentation(line, match_start) is True


def test_run_flags_python_floor_division_bypass(tmp_path: Path) -> None:
    """End-to-end: atomic_primitives.run flags a Python floor-div bypass.

    Proves the language signal is threaded from the scan loop: a .py file
    with ``size // 2`` left of a live ``db.execute(`` on one physical line
    is reported as a finding (not suppressed). This is the real guard-
    vacuity the fix closes.
    """
    src = tmp_path / "packages" / "demo" / "writer.py"
    src.parent.mkdir(parents=True, exist_ok=True)
    src.write_text(
        "def go(db, q, size):\n"
        "    chunk = size // 2; db.execute(q)\n"
        "    return chunk\n",
        encoding="utf-8",
    )
    _name, findings = atomic_primitives.run(tmp_path)
    assert any(
        f.file.endswith("writer.py") and f.line == 2 for f in findings
    ), (
        "atomic_primitives.run must flag the Python floor-division bypass on "
        f"line 2; findings={findings!r}"
    )


def test_run_preserves_ts_slash_comment_suppression(tmp_path: Path) -> None:
    """End-to-end: a real ``//`` comment in a .ts file is still suppressed.

    The ``//``-comment behavior must be preserved for TS/JS through the
    scan loop. A .ts file whose only banned-literal mention is inside a
    ``//`` comment produces no finding.
    """
    src = tmp_path / "packages" / "demo" / "writer.ts"
    src.parent.mkdir(parents=True, exist_ok=True)
    src.write_text(
        "function go(db: any, q: string) {\n"
        "  // db.execute(q) is banned here\n"
        "  return 0;\n"
        "}\n",
        encoding="utf-8",
    )
    _name, findings = atomic_primitives.run(tmp_path)
    assert not any(f.file.endswith("writer.ts") for f in findings), (
        "a real '//' comment in a .ts file must remain suppressed; "
        f"findings={findings!r}"
    )


def test_run_flags_real_ts_bypass(tmp_path: Path) -> None:
    """End-to-end: a real TS bypass (live call) is still flagged.

    Disabling ``//`` for Python must not weaken detection of a genuine TS
    bypass. ``db.execute(q); // note`` in a .ts file is a live call and
    must be reported.
    """
    src = tmp_path / "packages" / "demo" / "live.ts"
    src.parent.mkdir(parents=True, exist_ok=True)
    src.write_text(
        "function go(db: any, q: string) {\n"
        "  db.execute(q); // run it\n"
        "  return 0;\n"
        "}\n",
        encoding="utf-8",
    )
    _name, findings = atomic_primitives.run(tmp_path)
    assert any(
        f.file.endswith("live.ts") and f.line == 2 for f in findings
    ), (
        "a live TS db.execute( call must be flagged even with a trailing "
        f"'//' comment; findings={findings!r}"
    )
