"""Atomic-primitives invariant checker (VAL-W5-034).

Per CLAUDE.md keystone invariant #8 + spec section H + boundaries.md
sec 3: business logic NEVER calls ``db.execute(...)``,
``s3.put_object(...)``, ``queue.send(...)``, or ``open(..., 'w')``
directly. Only the four atomic-persistence primitives are sanctioned.

The check matches the contract VAL-W5-034 regex:
``db\\.execute\\(|s3\\.put_object\\(|queue\\.send\\(|open\\([^)]*['"]w['"]``
filtered to exclude ``primitives/`` and ``tests/`` directories.

For each match the finding includes ``raw_call`` (the matched literal,
populated into ``pattern``) and ``suggested_primitive`` (the canonical
remediation string carried in ``suggested_fix``).

Per VAL-W5-034 zero matches = pass; any match fails the check.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import ast
import re
from pathlib import Path, PurePosixPath
from typing import Final

from verify_self.finding_codes import RELAY_VERIFY_SELF_PRIMITIVE_BYPASS

from .util import (
    Finding,
    iter_source_files,
    suggested_fix_for,
)

CHECK_NAME: Final[str] = "atomic-primitives-only"

# VAL-W5-034 regex (contract shape; we precompile for speed). Note: the
# ``open(..., 'w')`` arm uses a non-greedy ``[^)]*`` so the match stops at
# the closing paren of the open() call; this matches both ``open("x", "w")``
# and ``open("x","w","utf-8")`` invocations. We anchor the ``open(`` token
# at a word boundary (``\b``) so common safe wrappers like
# ``os.fdopen(fd, "w")`` (used inside primitives only) and
# ``codecs.open(p, "w")`` are not false-positives. The bare ``open(``
# call in business logic still matches because Python identifiers are
# word characters and the preceding ``.`` (in ``foo.open(``) is treated
# as a non-word character so ``\b`` does not fire AT the ``open``
# position -- it matches after the dot, which is the desired behavior:
# only bare ``open(`` triggers.
_PRIMITIVE_BYPASS_RE: Final[re.Pattern[str]] = re.compile(
    r"db\.execute\(|s3\.put_object\(|queue\.send\(|\bopen\([^)]*['\"]w['\"]"
)

# A line that looks like documentation (Python docstring indent line,
# Markdown bullet quote, comment, or backtick-wrapped reference) is
# excluded -- the verifier targets executable callsites, not prose
# mentions of the banned literal. The exclusion fires when the matched
# token is preceded by ``#`` (Python or shell comment), ``//`` (TS/JS
# comment), or appears inside double-backticks (RST inline code) or
# single-backticks (Markdown inline code) on the same line.
#
# We test the substring left of the match: if the last unquoted
# ``#``/``//`` is to the left of the match, OR a backtick pair surrounds
# the match span, the line is treated as documentation and skipped.
#
# The regex prefers double-backtick (RST) pairs first (longest match)
# and falls back to single-backtick (Markdown) pairs.
_BACKTICK_RE: Final[re.Pattern[str]] = re.compile(r"``[^`]+``|`[^`]+`")

# Path-prefix exclusions specific to this check (in addition to
# iter_source_files's base exclusions which already filter tests).
# Per VAL-W5-034 ``primitives/`` directories are exempt because that's
# where the atomic primitives THEMSELVES live; they internally call the
# raw operations the rest of the tree may not.
_PRIMITIVE_DIR_TOKEN: Final[str] = "primitives"


def _is_in_primitive_dir(rel_posix: str) -> bool:
    """Return True iff ``rel_posix`` lives under any ``primitives/`` dir.

    Matches any path component named ``primitives`` so both
    ``apps/local-sidecar/relay_sidecar/primitives/`` and any future
    ``packages/sdk-python/relay/persistence/primitives/`` tree are
    exempt.
    """
    return _PRIMITIVE_DIR_TOKEN in PurePosixPath(rel_posix).parts


def multiline_string_line_numbers(text: str, *, is_python: bool) -> frozenset[int]:
    """Return the 1-based line numbers covered by a STANDALONE string-expression
    statement (a docstring or a bare string-literal "comment") in a Python source.

    A pattern match (a banned ``db.execute(``, a canonical-row write, ...) on
    such a line is documentation/prose, not an executable callsite -- e.g. a
    module docstring that documents a grep guard across several lines.

    CRITICAL: this targets ONLY bare string-expression STATEMENTS
    (``ast.Expr`` whose value is a string constant). A string passed to
    ``execute(...)`` is a Call ARGUMENT, and a string assigned to a variable is
    an assignment value -- NEITHER is an ``ast.Expr`` statement, so a
    triple-quoted canonical-table SQL write passed to ``execute(...)`` is NOT
    suppressed and stays flagged (roborev a2adc74). A naive "every multi-line
    string token" suppression would mask exactly that executable write.

    Non-Python sources (and any source ``ast.parse`` cannot handle) return the
    empty set -- the per-line comment/backtick heuristics still apply there.
    """
    if not is_python:
        return frozenset()
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        # Unparseable / partial source: fall back to the per-line heuristics.
        return frozenset()
    doc_lines: set[int] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            const = node.value
            start = const.lineno
            end = getattr(const, "end_lineno", start) or start
            doc_lines.update(range(start, end + 1))
    return frozenset(doc_lines)


def _match_is_documentation(
    line: str,
    match_start: int,
    *,
    sql: bool = False,
    slash_comment: bool = True,
    hash_comment: bool = True,
    in_docstring: bool = False,
) -> bool:
    """Return True iff the match position appears inside a documentation context.

    Heuristics (each conservative; only fires when the match lives in
    explicit documentation syntax):

      1. The leftmost non-whitespace character on the line is ``#`` (when
         ``hash_comment=True``) or ``//`` (when ``slash_comment=True``) (or
         ``--`` when ``sql=True``) -> entire line is a comment ->
         documentation.
      2. A standalone ``#`` (Python/shell comment, only when
         ``hash_comment=True``), ``//`` (TS/JS comment, only when
         ``slash_comment=True``), or SQL ``--`` (when ``sql=True``) appears
         in the line BEFORE the match position, NOT inside a string literal
         -> the match is inside a trailing comment.
      3. The match span is wholly enclosed by a backtick pair on the
         line -> the match is a backtick-quoted reference.
      4. (``sql=True`` only) The match is enclosed in a quoted string
         literal -> it is a string payload (e.g. a ``RAISE(ABORT, '...')``
         error message), not an executable SQL statement.

    Heuristic 2's "not inside a string literal" check is approximated by
    counting unescaped quote characters to the left of the candidate
    ``#`` -- an even count means we are outside any string, an odd
    count means we are inside one. This is not a full Python lexer but
    catches the vast majority of trailing-comment cases without
    misidentifying an in-string ``#``.

    A quote is "unescaped" iff the run of consecutive backslashes
    immediately preceding it is even-length (VAL-ISO-014). A naive check
    of only the single preceding character wrongly treats the closing
    quote of a string ending in an escaped backslash (``"a\\"`` -- two
    source backslashes, one literal backslash, string CLOSED) as escaped,
    inverting quote parity and allowing a crafted line to hide a real
    atomic-primitive bypass behind an in-string ``#``/``//`` that is
    mis-read as a comment. Counting the backslash run fixes both the
    even case (escaped backslash, quote NOT escaped) and the odd case
    (escaped quote, string stays open).

    Heuristic 3 walks the line for ``backtick ... backtick`` pairs and
    returns True iff the match is fully bounded by one of them.

    ``sql=True`` is set by the control-plane-write check when scanning
    ``.sql`` migration files (VAL-ISO-035): SQL line comments start with
    ``--`` (not ``#``/``//``), and a canonical-table name mentioned
    inside a string literal (an error message) is not an executable
    write.

    ``slash_comment`` selects whether ``//`` is a line-comment marker for
    the scanned language. It MUST be ``True`` only for languages where
    ``//`` actually begins a comment -- TS/JS/JSX/MJS/CJS. For PYTHON
    (``.py``/``.pyi``) it MUST be ``False``: in Python ``//`` is the
    FLOOR-DIVISION operator, not a comment. Treating ``//`` as a comment
    on Python source makes a real bypass invisible -- a production line
    such as ``chunk = size // 2; db.execute(q)`` would be falsely
    classified as documentation and the keystone-#8 violation SKIPPED,
    going vacuous for that line. ``.sql`` files also pass
    ``slash_comment=False`` (SQL uses ``--``, not ``//``). The default
    ``slash_comment=True`` preserves the historical TS/JS behavior for any
    caller that does not specify a language.

    ``hash_comment`` selects whether ``#`` is a line-comment marker for the
    scanned language. It MUST be ``True`` only for languages where ``#``
    actually begins a comment -- Python (``.py``/``.pyi``), shell, and SQL.
    For TS/JS (``.ts``/``.tsx``/``.js``/``.jsx``/``.mjs``/``.cjs``) it MUST
    be ``False``: in those languages ``#`` is a PRIVATE-FIELD sigil (e.g.
    ``class C { #n = 1 }``) or a shebang, NOT a comment. Treating ``#`` as a
    comment on TS/JS source makes a real bypass invisible -- a production
    line such as ``class C { #n = 1; m(){ db.execute(q); } }`` would be
    falsely classified as documentation and the keystone-#8 violation
    SKIPPED, going vacuous for that line. The default ``hash_comment=True``
    preserves the historical Python/shell/SQL behavior for any caller that
    does not specify a language (including the control-plane-write SQL/Python
    caller).
    """
    # Heuristic 0: the line lies INSIDE a multi-line string literal (module /
    # function docstring or block string). A pattern match there is PROSE, not
    # executable code -- e.g. a module docstring that documents a grep guard with
    # a multi-line ``...`` RST span mentioning a canonical-row write pattern. This
    # is computed once per file with a real tokenizer (see
    # multiline_string_line_numbers) and is the correct replacement for the
    # removed backtick-token-counting heuristic, which both produced false
    # negatives (a "``" inside an executable string literal) and could not see
    # cross-line spans (re-hunt cli-inv-1 follow-up: the heuristic-4 removal
    # regressed the legitimate multi-line-docstring exclusion).
    if in_docstring:
        return True
    # Heuristic 1: full-line comment.
    stripped = line.lstrip()
    if hash_comment and stripped.startswith("#"):
        return True
    if slash_comment and stripped.startswith("//"):
        return True
    if sql and stripped.startswith("--"):
        return True
    # Heuristic 2: trailing comment.
    quote_count = 0
    for idx in range(match_start):
        ch = line[idx]
        if ch in ("'", '"'):
            # A quote is escaped iff the run of consecutive backslashes
            # immediately to its left is ODD. An even run (including a
            # lone escaped-backslash sequence ``\\``) leaves the quote
            # itself unescaped, so it opens/closes a string literal.
            backslashes = 0
            j = idx - 1
            while j >= 0 and line[j] == "\\":
                backslashes += 1
                j -= 1
            if backslashes % 2 == 1:
                continue
            quote_count += 1
        elif (hash_comment and ch == "#" and quote_count % 2 == 0) or (
            slash_comment
            and ch == "/"
            and quote_count % 2 == 0
            and idx + 1 < len(line)
            and line[idx + 1] == "/"
        ):
            return True
        elif (
            sql
            and ch == "-"
            and quote_count % 2 == 0
            and idx + 1 < len(line)
            and line[idx + 1] == "-"
        ):
            # SQL ``--`` line comment outside any string literal.
            return True
    # Heuristic 4 (SQL only): the match sits inside a string literal.
    # An odd number of unescaped quotes to the left of the match means
    # the match position is inside an open string literal.
    if sql and quote_count % 2 == 1:
        return True
    # Heuristic 3: backtick-bounded (closed pair on the same line).
    for m in _BACKTICK_RE.finditer(line):
        if m.start() < match_start < m.end():
            return True
    # NOTE: a prior "Heuristic 4" treated an ODD count of ``"``"`` tokens to the
    # LEFT of the match as an unclosed RST inline-code span -> documentation. But
    # a ``"``"`` inside an ordinary string literal (e.g. ``marker = "``"; ...``)
    # is not RST, so a banned db.execute( / cur.execute( on the same physical
    # line was masked vacuously (re-hunt cli-inv-1). A whole-tree scan found no
    # source line that relied on it -- legitimate RST inline code is already
    # suppressed by heuristic 3's closed-backtick-pair check above. Genuine
    # multi-line RST docstring continuation, if ever needed, must be handled with
    # real cross-line triple-quote/comment-region tracking in run(), never by
    # counting backtick tokens on a single executable line. The function
    # therefore falls through to a definite NOT-documentation verdict.
    return False


def run(repo_root: Path) -> tuple[str, list[Finding]]:
    """Run the atomic-primitives-only check against ``repo_root``.

    Returns ``(check_name, findings)`` sorted by ``(file, line, code)``.
    """
    findings: list[Finding] = []
    for path in iter_source_files(repo_root):
        rel = str(PurePosixPath(path.relative_to(repo_root)))
        if _is_in_primitive_dir(rel):
            continue
        # The check targets Python and TS source. Schemas and config
        # files (.json/.yaml) cannot contain function calls so skipping
        # them avoids spurious matches on string literals embedded in
        # fixture data.
        if path.suffix not in (".py", ".pyi", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        # ``//`` is a line comment ONLY in TS/JS family languages. In
        # Python (``.py``/``.pyi``) ``//`` is the floor-division operator,
        # so we must NOT treat it as a comment -- otherwise a production
        # line like ``chunk = size // 2; db.execute(q)`` would be falsely
        # classified as documentation and the keystone-#8 violation would
        # be skipped, making this guard vacuous for that line.
        slash_is_comment = path.suffix not in (".py", ".pyi")
        # ``#`` is a line comment ONLY in Python (and shell/SQL); in the
        # TS/JS family (``.ts``/``.tsx``/``.js``/``.jsx``/``.mjs``/``.cjs``)
        # ``#`` is a private-field sigil / shebang, NOT a comment. We must
        # NOT treat it as a comment for those sources -- otherwise a
        # production line like ``class C { #n = 1; m(){ db.execute(q); } }``
        # would be falsely classified as documentation and the keystone-#8
        # violation would be skipped, making this guard vacuous for that line.
        hash_is_comment = path.suffix in (".py", ".pyi")
        # Lines inside a multi-line string literal (docstring / block string) are
        # prose, not executable callsites -- computed once per file via the real
        # tokenizer so a banned token mentioned in a multi-line docstring is not
        # flagged (the correct replacement for the removed backtick-counting).
        doc_lines = multiline_string_line_numbers(
            text, is_python=path.suffix in (".py", ".pyi")
        )
        for line_no_minus_one, line in enumerate(text.split("\n")):
            m = _PRIMITIVE_BYPASS_RE.search(line)
            if m is None:
                continue
            if _match_is_documentation(
                line,
                m.start(),
                slash_comment=slash_is_comment,
                hash_comment=hash_is_comment,
                in_docstring=(line_no_minus_one + 1) in doc_lines,
            ):
                continue
            findings.append(
                Finding(
                    file=rel,
                    line=line_no_minus_one + 1,
                    code=RELAY_VERIFY_SELF_PRIMITIVE_BYPASS,
                    suggested_fix=suggested_fix_for(
                        RELAY_VERIFY_SELF_PRIMITIVE_BYPASS
                    ),
                    pattern=m.group(0),
                )
            )
    findings.sort(key=lambda f: (f.file, f.line, f.code))
    return CHECK_NAME, findings


__all__ = ["CHECK_NAME", "run"]
