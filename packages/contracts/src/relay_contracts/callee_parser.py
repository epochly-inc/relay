"""Minimal host-side standalone CEL callee parser (M6 WS-I).

Extracts identifiers in BARE function-call position (``name(...)``) from CEL
source text. This is the sanctioned replacement (ADR cel-wasm-cutover
workstreams, Revisions section 3) for the legacy AST walk that derived the
publish-time callee set: with the single wasm engine as the only CEL backend
there is no host-side AST to walk, and the frozen crate does not emit a
statically-referenced-names field, so the host keeps this MINIMAL standalone
parser instead.

Scope (deliberately narrow -- the wasm engine remains the AUTHORITATIVE
compiler; this tokenizer only feeds two host screens):

  - the publish-time unregistered-UDF check in ``pipeline.publish_contract``
    (a bare callee that is neither a registered UDF nor a CEL builtin is
    rejected with RELAY-CONTRACT-004); and
  - the compile-time Relay-profile screen in the wasm-backed evaluator (a
    bare ``dyn`` / ``timestamp`` / ``duration`` call is rejected with
    RELAY-CEL-002 BEFORE any evaluation, including short-circuited branches).

Semantics match the legacy bare-call walk it replaces:

  - only BARE calls are yielded; member calls (``x.method(...)``, including
    the dotted ``relay.coverage(...)`` form) are NOT;
  - string literals (single / double / triple-quoted, with ``r`` / ``b``
    prefixes; raw strings do not honor backslash escapes) and ``//`` line
    comments never produce callees;
  - CEL reserved words are excluded (``a in (1, 2)`` must not yield ``in``);
  - extraction is total: malformed source yields a best-effort (possibly
    empty) callee set and NEVER raises -- the wasm compiler rejects malformed
    source with its own structured error at publish/eval.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import string

__all__ = ["extract_bare_callees"]

# CEL reserved words (cel-spec "Syntax" section): the boolean / null literals,
# the `in` operator (the load-bearing exclusion: `a in (1, 2)` puts `in`
# directly before `(`), and the reserved-for-future identifiers.
_RESERVED_WORDS: frozenset[str] = frozenset(
    {
        "true",
        "false",
        "null",
        "in",
        "as",
        "break",
        "const",
        "continue",
        "else",
        "for",
        "function",
        "if",
        "import",
        "let",
        "loop",
        "package",
        "namespace",
        "return",
        "var",
        "void",
        "while",
    }
)

# CEL string-literal prefixes: raw (r/R), bytes (b/B), and their combinations.
_STRING_PREFIXES: frozenset[str] = frozenset({"r", "b", "rb", "br"})

_IDENT_START: frozenset[str] = frozenset(string.ascii_letters + "_")
_IDENT_CONT: frozenset[str] = frozenset(string.ascii_letters + string.digits + "_")
_QUOTES: frozenset[str] = frozenset({"'", '"'})


def _skip_string(source: str, start: int, *, raw: bool) -> int:
    """Return the index just past the string literal opening at ``start``.

    ``source[start]`` MUST be a quote character. Handles single- and
    triple-quoted forms. In a non-raw literal a backslash escapes the next
    character (so an escaped quote does not terminate); in a raw literal the
    backslash is an ordinary character and any quote terminates (CEL raw
    strings do not interpret escape sequences). An unterminated literal
    consumes the rest of the source (fail-safe: no callee can be fabricated
    from a malformed tail; the wasm compiler rejects the source).
    """
    quote = source[start]
    n = len(source)
    if source[start : start + 3] == quote * 3:
        i = start + 3
        closer = quote * 3
        while i < n:
            if not raw and source[i] == "\\":
                i += 2
                continue
            if source[i : i + 3] == closer:
                return i + 3
            i += 1
        return n
    i = start + 1
    while i < n:
        c = source[i]
        if not raw and c == "\\":
            i += 2
            continue
        if c == quote:
            return i + 1
        i += 1
    return n


def _next_significant(source: str, start: int) -> int:
    """Index of the next non-whitespace, non-comment character at/after
    ``start`` (``len(source)`` when none remains)."""
    i = start
    n = len(source)
    while i < n:
        c = source[i]
        if c.isspace():
            i += 1
            continue
        if c == "/" and source[i + 1 : i + 2] == "/":
            newline = source.find("\n", i)
            if newline == -1:
                return n
            i = newline + 1
            continue
        return i
    return n


def extract_bare_callees(expression: str) -> tuple[str, ...]:
    """Identifiers in BARE function-call position, source order, deduplicated.

    A bare callee is an identifier that (a) is not part of a larger token,
    (b) is not preceded -- ignoring whitespace and comments -- by ``.``
    (member access), (c) is followed -- ignoring whitespace and comments --
    by ``(``, and (d) is not a CEL reserved word. String-literal bodies and
    ``//`` comments are skipped entirely. Total: never raises on malformed
    source.
    """
    callees: list[str] = []
    seen: set[str] = set()
    n = len(expression)
    i = 0
    # The last significant (non-whitespace, non-comment, non-literal-body)
    # character seen BEFORE the current scan position; "" at start of input.
    prev_significant = ""
    while i < n:
        c = expression[i]
        # Line comment: skip to end of line (or input).
        if c == "/" and expression[i + 1 : i + 2] == "/":
            newline = expression.find("\n", i)
            if newline == -1:
                break
            i = newline + 1
            continue
        # String literal (no prefix).
        if c in _QUOTES:
            i = _skip_string(expression, i, raw=False)
            # A literal is an operand; mark with the closing quote so a
            # following identifier is not treated as member access.
            prev_significant = c
            continue
        # Identifier (or a string-literal prefix like r"..." / b"...").
        if c in _IDENT_START:
            j = i + 1
            while j < n and expression[j] in _IDENT_CONT:
                j += 1
            name = expression[i:j]
            if (
                j < n
                and expression[j] in _QUOTES
                and name.lower() in _STRING_PREFIXES
            ):
                # r/b/rb prefix directly attached to a quote: a string
                # literal, not an identifier. Raw iff the prefix contains r.
                i = _skip_string(expression, j, raw="r" in name.lower())
                prev_significant = expression[j]
                continue
            is_member_access = prev_significant == "."
            k = _next_significant(expression, j)
            if (
                not is_member_access
                and k < n
                and expression[k] == "("
                and name not in _RESERVED_WORDS
                and name not in seen
            ):
                seen.add(name)
                callees.append(name)
            prev_significant = name[-1]
            i = j
            continue
        # Digits glue alphanumeric runs together (e.g. the `x1f` inside
        # `0x1f` is not an identifier): consume the full alnum run so its
        # alpha tail is never re-scanned as an identifier start.
        if c.isdigit():
            j = i + 1
            while j < n and expression[j] in _IDENT_CONT:
                j += 1
            prev_significant = expression[j - 1]
            i = j
            continue
        if not c.isspace():
            prev_significant = c
        i += 1
    return tuple(callees)
