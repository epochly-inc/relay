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
