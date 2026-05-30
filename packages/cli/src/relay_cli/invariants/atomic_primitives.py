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


def _match_is_documentation(
    line: str, match_start: int, *, sql: bool = False
) -> bool:
    """Return True iff the match position appears inside a documentation context.

    Heuristics (each conservative; only fires when the match lives in
    explicit documentation syntax):

      1. The leftmost non-whitespace character on the line is ``#`` or
         ``//`` (or ``--`` when ``sql=True``) -> entire line is a comment
         -> documentation.
      2. A standalone ``#`` (Python/shell comment, or SQL ``--`` when
         ``sql=True``) appears in the line BEFORE the match position, NOT
         inside a string literal -> the match is inside a trailing
         comment.
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
    write. The default (``sql=False``) preserves the exact Python/TS
    behavior for every other caller.
    """
    # Heuristic 1: full-line comment.
    stripped = line.lstrip()
    if stripped.startswith("#") or stripped.startswith("//"):
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
        elif ch == "#" and quote_count % 2 == 0 or (
            ch == "/"
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
    # Heuristic 4: unclosed double-backtick to the left of the match
    # (RST inline-code spanning a multi-line docstring continuation
    # line). The ``...`` opener may live on this line with no closer
    # before line-end; the closer typically appears on the next physical
    # line. If we see ``...``  with content but the match position is
    # AFTER the opener and BEFORE any matching closer on this line, the
    # match is inside the inline-code span and is documentation.
    left = line[:match_start]
    return "``" in left and left.count("``") % 2 == 1


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
        for line_no_minus_one, line in enumerate(text.split("\n")):
            m = _PRIMITIVE_BYPASS_RE.search(line)
            if m is None:
                continue
            if _match_is_documentation(line, m.start()):
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
