#!/usr/bin/env python3
"""ASCII-Safe Source lint (manifest command ``lint-ascii-source``).

CLAUDE.md "ASCII-Safe Source" forbids emoji and unicode glyphs in source
code, scripts, and CLI output. The stated rationale is encoding
portability: evidence bundles and CLI output are consumed by CI runners,
auditors, and verifiers whose encodings Relay does not control, so a
stray smart-quote or em-dash in a code token (an identifier, operator,
or an emitted runtime string) can corrupt a pipeline that re-encodes the
byte stream. The same rule explicitly permits unicode in Markdown docs
"where it aids readability".

Scope (manifest ``environment.ascii_only_paths``): ``packages/``,
``apps/``, ``scripts/``, ``tests/``.

What is scanned
---------------
Only executable source files where a non-ASCII byte in a *code* token is
a genuine portability hazard:

    .py .pyi .ts .tsx .js .jsx .mjs .cjs

What is NOT scanned (obvious non-source / explicitly-permitted unicode):

  * Markdown (``.md``)         -- CLAUDE.md permits unicode in docs.
  * Data / schema / config     -- ``.json .yaml .yml .toml .sql .csv``
                                  carry unicode test vectors and prose
                                  by design (RFC 8785 JCS corpora, spec
                                  section markers); they are data, not
                                  code tokens.
  * Binary / non-text          -- ``.DS_Store``, images, archives,
                                  certificates, lockfiles.
  * Vendored / generated trees -- ``packages/acef/upstream`` (byte-
                                  immutable vendor drop, VAL-W11-001/004),
                                  the W1.5 codegen output trees, and
                                  ``node_modules`` / ``dist`` / build
                                  artifacts.

What counts as a violation
--------------------------
A non-ASCII byte that appears in a *code* token: an identifier, keyword,
operator, or numeric literal. Non-ASCII inside a comment, a string
literal, a docstring, or an f-string text segment is NOT a violation:

  * Comments and docstrings are prose, governed by the same readability
    carve-out as Markdown.
  * String / data literals legitimately hold unicode in this codebase --
    e.g. ``apps/local-sidecar/relay_sidecar/runtime.py`` carries a
    denylist of U+202E / U+200B / U+FEFF code points precisely so the
    HTTP boundary can REJECT them (a byte-blind lint would flag the very
    security control that defends against the hazard), and the JCS /
    Relay-CEL corpus generators under ``scripts/`` emit unicode test
    vectors as their entire purpose.

Detecting non-ASCII in code tokens catches the real failure mode --
homoglyph or smart-quote characters smuggled into an identifier or
operator -- without raising false positives on deliberate unicode prose
or data. The classification is exact for Python (via the stdlib
``tokenize`` lexer) and conservative for TS/JS (a single-pass lexer that
removes comments and string/template literals, then flags any residual
non-ASCII).

Output is ASCII-only (``[OK]`` / ``[PASS]`` / ``[FAIL]``) per the rule
this script enforces. The sole side effect is the exit code: 0 = clean,
1 = at least one violation.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import io
import json
import sys
import tokenize
from pathlib import Path, PurePosixPath
from typing import Final

# Repo root -- this script lives at <repo>/scripts/.
REPO_ROOT: Final[Path] = Path(__file__).resolve().parent.parent

# Manifest environment.ascii_only_paths.
SCAN_ROOTS: Final[tuple[str, ...]] = ("packages", "apps", "scripts", "tests")

# Executable source extensions (the surface where a non-ASCII code token
# is a portability hazard). Python and the JS/TS family.
PY_EXTS: Final[frozenset[str]] = frozenset({".py", ".pyi"})
JS_EXTS: Final[frozenset[str]] = frozenset(
    {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}
)
SOURCE_EXTS: Final[frozenset[str]] = PY_EXTS | JS_EXTS

# Excluded subtrees (POSIX-form relative-path prefix match). These are
# vendored, generated, or build-output trees. Test SOURCE under tests/
# and packages/*/tests/ IS scanned (test code is still code); only
# vendored/generated/build trees are skipped.
EXCLUDED_PREFIXES: Final[tuple[str, ...]] = (
    # W11.1 vendored ACEF tree -- byte-immutable outside the vendor-update
    # workflow (VAL-W11-001, VAL-W11-004). Must never be mutated, and it
    # ships unicode test vectors upstream.
    "packages/acef/upstream",
    # W1.5 codegen output trees (drift-checked, never hand-edited).
    "packages/sdk-python/relay/_generated",
    "packages/schemas/python/relay_schemas/_generated",
    "packages/sdk-typescript/src/_generated",
    "packages/schemas/typescript",
)

# Directory components pruned at descent time (anywhere in the tree).
EXCLUDED_DIR_PARTS: Final[frozenset[str]] = frozenset(
    {"__pycache__", "node_modules", "dist", "build", ".venv", ".git"}
)


def _to_posix(path: Path) -> str:
    """POSIX-form relative path of ``path`` under :data:`REPO_ROOT`."""
    return str(PurePosixPath(path.relative_to(REPO_ROOT)))


def _is_excluded(rel_posix: str) -> bool:
    """Whether ``rel_posix`` lives under an excluded subtree prefix."""
    for prefix in EXCLUDED_PREFIXES:
        if rel_posix == prefix or rel_posix.startswith(prefix + "/"):
            return True
    return False


def _iter_source_files() -> list[Path]:
    """Deterministically enumerate scannable source files.

    Sorted by POSIX relative path so the report ordering is identical on
    every platform. Prunes ``__pycache__`` / ``node_modules`` / build
    dirs and the vendored/generated subtrees; keeps only files whose
    suffix is in :data:`SOURCE_EXTS`.
    """
    out: list[Path] = []
    for root_name in SCAN_ROOTS:
        root = REPO_ROOT / root_name
        if not root.exists():
            continue
        for p in root.rglob("*"):
            if not p.is_file():
                continue
            if p.suffix not in SOURCE_EXTS:
                continue
            if any(part in EXCLUDED_DIR_PARTS for part in p.parts):
                continue
            rel = _to_posix(p)
            if _is_excluded(rel):
                continue
            out.append(p)
    out.sort(key=_to_posix)
    return out


def _first_nonascii_col(text: str) -> int:
    """Return the 0-based column of the first non-ASCII char, or -1."""
    for idx, ch in enumerate(text):
        if ord(ch) > 0x7F:
            return idx
    return -1


def scan_python(path: Path) -> list[dict[str, object]]:
    """Scan a Python file; return violations for non-ASCII *code* tokens.

    Uses the stdlib :mod:`tokenize` lexer so the classification is exact.
    Tokens that are prose or data -- ``COMMENT``, ``STRING``,
    ``FSTRING_START`` / ``FSTRING_MIDDLE`` / ``FSTRING_END`` (the literal
    text segments of an f-string) -- are exempt. Any other token type
    (``NAME`` identifiers, ``OP`` operators, ``NUMBER`` literals,
    keywords) carrying a non-ASCII byte is a violation.

    On a tokenizer error (malformed source) the file is reported as a
    single violation so it cannot silently slip past the lint.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        # A file that is not valid UTF-8 still has non-ASCII bytes; flag it.
        return [
            {
                "line": 1,
                "col": 1,
                "context": "non-utf8-bytes",
                "detail": f"unreadable as utf-8: {exc.__class__.__name__}",
            }
        ]

    exempt_types = {
        tokenize.COMMENT,
        tokenize.STRING,
    }
    # f-string component token types exist from Python 3.12; guard with
    # getattr so the script also imports cleanly on older interpreters
    # (the project floor is 3.12, where these are present).
    for name in ("FSTRING_START", "FSTRING_MIDDLE", "FSTRING_END"):
        tok_type = getattr(tokenize, name, None)
        if tok_type is not None:
            exempt_types.add(tok_type)

    violations: list[dict[str, object]] = []
    try:
        tokens = tokenize.generate_tokens(io.StringIO(text).readline)
        for tok in tokens:
            if tok.type in exempt_types:
                continue
            col = _first_nonascii_col(tok.string)
            if col < 0:
                continue
            bad = tok.string[col]
            violations.append(
                {
                    "line": tok.start[0],
                    "col": tok.start[1] + col + 1,
                    "context": tokenize.tok_name.get(tok.type, str(tok.type)),
                    "detail": f"U+{ord(bad):04X} in code token",
                }
            )
    except (tokenize.TokenError, IndentationError, SyntaxError) as exc:
        # Malformed source: fall back to a whole-file flag rather than
        # passing silently. Do NOT mask the failure.
        col = _first_nonascii_col(text)
        line = text[: max(col, 0)].count("\n") + 1 if col >= 0 else 1
        violations.append(
            {
                "line": line,
                "col": 1,
                "context": "tokenizer-error",
                "detail": f"{exc.__class__.__name__}: cannot classify tokens",
            }
        )
    return violations


def _regex_allowed_after(prev_significant: str) -> bool:
    """Whether a ``/`` after ``prev_significant`` begins a regex literal.

    JS/TS overloads ``/`` as both the division operator and the start of a
    regex literal. The standard disambiguation is positional: a regex is
    valid wherever an *expression* may begin, i.e. when the previous
    significant (non-whitespace, non-comment) character does NOT close a
    value. After a value-producing token -- an identifier or number
    character, or a closing ``)`` / ``]`` / ``}`` -- a ``/`` is division;
    everywhere else (after ``=``, ``(``, ``,``, ``;``, ``:``, an operator,
    ``return``/``typeof``-style keywords, or at the very start of input)
    it begins a regex.

    ``prev_significant`` is the empty string at start-of-input, where a
    regex is allowed. We classify on the single previous significant
    character; this is the same conservative heuristic shipped by mature
    JS tokenizers (e.g. the esprima/acorn "regex allowed" rule reduced to
    its character-level core) and is sufficient here because the only
    consequence of a misclassification is whether a ``/...//`` span is
    treated as an exempt literal or as code -- and we additionally guard
    the false-positive direction by never flagging inside a regex body.

    ``}`` is treated as value-closing (block/object close). A regex
    immediately after ``}`` (e.g. ``if (c) {} /re/.test(x)``) is vanishingly
    rare in real source and erring toward "division" here only risks
    treating a would-be regex as code, which the regex-body exemption and
    the live-tree clean check both bound.

    Pure: no clock / network / randomness. Deterministic.
    """
    if prev_significant == "":
        return True
    if prev_significant in (")", "]", "}"):
        return False
    # Identifier or numeric continuation closes a value -> division.
    return not (prev_significant.isalnum() or prev_significant in ("_", "$"))


def _strip_js_comments_and_strings(text: str) -> str:
    """Replace JS/TS comments, string/template, and regex literals.

    Single-pass lexer. Newlines are preserved so line numbers in the
    residual line up with the source. Handles:

      * line comments  ``// ...``
      * block comments ``/* ... */``
      * single-quoted, double-quoted, and backtick template literals (with
        backslash escapes). A template literal is part string and part code:
        the literal TEXT spans are exempt, but each ``${...}`` interpolation
        is a real JS expression and is RE-ENTERED as code so a non-ASCII
        token smuggled into an interpolation identifier/operator is still
        flagged (codex P3). An escaped ``\\${`` is literal text, not an
        interpolation. Nested braces (object literals, nested template
        literals) inside an interpolation are balanced via a brace-depth
        stack so the interpolation does not close early.
      * regex literals ``/.../flags`` -- disambiguated from the division
        operator by :func:`_regex_allowed_after` (a ``/`` begins a regex
        only where an expression may begin). The regex body honors
        backslash escapes and character classes ``[...]`` (inside which an
        unescaped ``/`` is a literal slash, not the terminator, and a
        quote does NOT start a string). Treating the whole regex as one
        exempt literal is what stops a quote inside it from desyncing
        string state and silently swallowing later code tokens.

    The residual string contains only code tokens (and whitespace);
    any non-ASCII byte remaining in it is a code-token violation.

    A regex DSL is deliberately avoided: comment/string/regex boundaries
    do not nest regularly, and a hand-written state machine is the correct
    tool. This is pure (no clock / network / randomness), satisfying the
    determinism requirement for lint tooling.
    """
    out: list[str] = []
    i = 0
    n = len(text)
    # State: 'code', 'line', 'block', 'sq' (single), 'dq' (double),
    # 'tpl' (template/backtick), 'regex'.
    state = "code"
    # Last significant (non-whitespace, non-comment) source character seen
    # while in 'code' state. Drives regex-vs-division disambiguation.
    prev_significant = ""
    # Whether the regex lexer is currently inside a ``[...]`` char class
    # (where ``/`` is literal). Reset on each regex entry.
    in_char_class = False
    # Template-literal ${...} interpolation handling (codex P3). A template
    # literal `text${EXPR}text` is part string (the TEXT spans, exempt) and
    # part CODE (each EXPR inside ${...}). When we enter an interpolation from
    # 'tpl' state we switch to 'code' and push the brace depth at which the
    # interpolation closes (its matching `}` returns to 'tpl'). The stack
    # supports nested templates and object/block braces inside interpolations.
    #   brace_depth: current { } nesting in 'code' state.
    #   interp_return_depth: stack of brace depths; a `}` that drops the depth
    #     to a stacked value closes that interpolation and pops back to 'tpl'.
    brace_depth = 0
    interp_return_depth: list[int] = []
    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if state == "code":
            if ch == "/" and nxt == "/":
                out.append("  ")
                i += 2
                state = "line"
                continue
            if ch == "/" and nxt == "*":
                out.append("  ")
                i += 2
                state = "block"
                continue
            if ch == "/" and _regex_allowed_after(prev_significant):
                # Regex literal start. Blank the opening delimiter; the
                # body is consumed in the 'regex' state below.
                out.append(" ")
                i += 1
                state = "regex"
                in_char_class = False
                # A regex literal is itself a value: a following ``/`` is
                # division. Record that now so state restoration is correct.
                prev_significant = "/"
                continue
            if ch == "'":
                out.append(" ")
                i += 1
                state = "sq"
                continue
            if ch == '"':
                out.append(" ")
                i += 1
                state = "dq"
                continue
            if ch == "`":
                out.append(" ")
                i += 1
                state = "tpl"
                continue
            if ch == "{":
                brace_depth += 1
                prev_significant = ch
                out.append(ch)
                i += 1
                continue
            if ch == "}":
                # Does this `}` close an active template interpolation? An
                # interpolation entered at brace_depth d closes when a `}`
                # would drop the depth below d (i.e. it is the `}` matching
                # the `${`). Otherwise it is an ordinary closing brace.
                if interp_return_depth and brace_depth == interp_return_depth[-1]:
                    interp_return_depth.pop()
                    out.append(" ")  # the `}` is template syntax, not a token
                    i += 1
                    state = "tpl"
                    continue
                brace_depth -= 1
                prev_significant = ch
                out.append(ch)
                i += 1
                continue
            if not ch.isspace():
                prev_significant = ch
            out.append(ch)
            i += 1
            continue
        if state == "regex":
            if ch == "\\":
                # Escape: blank the backslash and the escaped char. Inside
                # or outside a char class, ``\/`` / ``\]`` / etc. are
                # literal and never terminate the regex or the class.
                out.append(" ")
                if nxt:
                    out.append("\n" if nxt == "\n" else " ")
                    i += 2
                else:
                    i += 1
                continue
            if ch == "[":
                in_char_class = True
                out.append(" ")
                i += 1
                continue
            if ch == "]" and in_char_class:
                in_char_class = False
                out.append(" ")
                i += 1
                continue
            if ch == "/" and not in_char_class:
                # Regex terminator. Following identifier chars are flags;
                # let the 'code' state consume them normally (flags are
                # ASCII per the grammar, and a homoglyph there would be a
                # genuine code-token violation worth flagging).
                out.append(" ")
                i += 1
                state = "code"
                continue
            # Any other char (including quotes, which must NOT start a
            # string here) is exempt regex-body content.
            out.append("\n" if ch == "\n" else " ")
            i += 1
            continue
        if state == "line":
            if ch == "\n":
                out.append("\n")
                i += 1
                state = "code"
                continue
            out.append(" " if ch != "\t" else "\t")
            i += 1
            continue
        if state == "block":
            if ch == "*" and nxt == "/":
                out.append("  ")
                i += 2
                state = "code"
                continue
            out.append("\n" if ch == "\n" else " ")
            i += 1
            continue
        # Template literal: literal TEXT spans are exempt (string content),
        # but ${...} interpolation expressions are CODE and must be scanned
        # (codex P3). Escapes (\`, \$, \\) are honored FIRST so an escaped
        # dollar (\${) is literal text, not an interpolation start.
        if state == "tpl":
            if ch == "\\":
                out.append(" ")
                if nxt:
                    out.append("\n" if nxt == "\n" else " ")
                    i += 2
                else:
                    i += 1
                continue
            if ch == "$" and nxt == "{":
                # Enter the interpolation as code. The matching `}` closes it
                # when brace_depth returns to its current value (recorded on
                # the stack). Blank the `${` -- it is template syntax, and the
                # `{` must NOT be counted as an ordinary code brace.
                interp_return_depth.append(brace_depth)
                out.append("  ")
                i += 2
                state = "code"
                # Fresh expression context: a leading `/` in `${/re/...}` is a
                # regex, not division.
                prev_significant = ""
                continue
            if ch == "`":
                out.append(" ")
                i += 1
                state = "code"
                continue
            out.append("\n" if ch == "\n" else " ")
            i += 1
            continue
        # single / double quoted string states: consume until the matching
        # delimiter, honoring backslash escapes. Preserve newlines.
        if state in ("sq", "dq"):
            if ch == "\\":
                # Escape: blank out the backslash and the escaped char.
                out.append(" ")
                if nxt:
                    out.append("\n" if nxt == "\n" else " ")
                    i += 2
                else:
                    i += 1
                continue
            close = {"sq": "'", "dq": '"'}[state]
            if ch == close:
                out.append(" ")
                i += 1
                state = "code"
                continue
            out.append("\n" if ch == "\n" else " ")
            i += 1
            continue
        # Unreachable; defensive.
        out.append(ch)  # pragma: no cover
        i += 1
    return "".join(out)


def scan_js(path: Path) -> list[dict[str, object]]:
    """Scan a TS/JS file; return violations for non-ASCII *code* tokens.

    Comments and string/template literals are removed first (replaced
    with whitespace, line numbers preserved); any non-ASCII byte
    remaining in the residual is a code-token violation.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return [
            {
                "line": 1,
                "col": 1,
                "context": "non-utf8-bytes",
                "detail": f"unreadable as utf-8: {exc.__class__.__name__}",
            }
        ]
    residual = _strip_js_comments_and_strings(text)
    violations: list[dict[str, object]] = []
    for line_idx, line in enumerate(residual.split("\n"), start=1):
        col = _first_nonascii_col(line)
        if col < 0:
            continue
        bad = line[col]
        violations.append(
            {
                "line": line_idx,
                "col": col + 1,
                "context": "code",
                "detail": f"U+{ord(bad):04X} in code token",
            }
        )
    return violations


def scan_file(path: Path) -> list[dict[str, object]]:
    """Dispatch to the Python or JS/TS scanner by extension."""
    if path.suffix in PY_EXTS:
        return scan_python(path)
    return scan_js(path)


def main(argv: list[str]) -> int:
    """Entry point. Returns 0 on clean lint, 1 on any violation."""
    json_output = "--json" in argv
    files = _iter_source_files()
    file_violations: list[dict[str, object]] = []
    for p in files:
        vios = scan_file(p)
        if vios:
            file_violations.append(
                {"path": _to_posix(p), "violations": vios}
            )
    total = sum(len(fv["violations"]) for fv in file_violations)  # type: ignore[arg-type]

    if json_output:
        report = {
            "schema_version": "relay.lint.ascii_source.v1",
            "exit_code": 0 if total == 0 else 1,
            "files_scanned": len(files),
            "total_violations": total,
            "files": file_violations,
        }
        print(json.dumps(report, separators=(",", ":"), ensure_ascii=True))
    else:
        if total == 0:
            print(
                "[OK] ascii-source lint: 0 violations across "
                f"{len(files)} source files"
            )
        else:
            for fv in file_violations:
                print("[FAIL] {path}".format(path=fv["path"]))
                for v in fv["violations"]:  # type: ignore[union-attr]
                    print(
                        "       L{line}:C{col} ({ctx}) {detail}".format(
                            line=v["line"],
                            col=v["col"],
                            ctx=v["context"],
                            detail=v["detail"],
                        )
                    )
            print(
                f"[FAIL] ascii-source lint: {total} non-ASCII code-token "
                f"violations across {len(file_violations)} files"
            )
    return 0 if total == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
