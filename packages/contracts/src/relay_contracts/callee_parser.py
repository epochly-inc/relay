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

Semantics match the legacy bare-call walk it replaces, PLUS the two
ROBOREV M6 hardening fixes (findings B + C):

  - only BARE calls are yielded; member calls WITH A RECEIVER
    (``x.method(...)``, including the dotted ``relay.coverage(...)`` form)
    are NOT -- but a LEADING-DOT root-qualified call (``.dyn(...)``, the CEL
    absolute-reference form, where the ``.`` has NO receiver) IS a bare
    call whose callee is the identifier normalized WITHOUT the dot
    (finding B: the pinned engine compiles ``.dyn(1)`` and fails only at
    exec, which probe_compile defers, so the publish screens must see it);
  - string literals (single / double / triple-quoted, with ``r`` / ``b``
    prefixes; raw strings do not honor backslash escapes) and ``//`` line
    comments never produce callees;
  - ONLY the engine-compile-rejected words are excluded (``true`` /
    ``false`` / ``null`` / ``in`` -- ``a in (1, 2)`` must not yield ``in``);
    the cel-spec future-reserved words (``if``, ``for``, ...) tokenize as
    ordinary identifiers in the pinned engine and DO surface as callees
    (finding C: hiding them bypassed the unregistered-UDF screen);
  - extraction is total: malformed source yields a best-effort (possibly
    empty) callee set and NEVER raises -- the wasm compiler rejects malformed
    source with its own structured error at publish/eval.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import string

__all__ = ["extract_bare_callees"]

# Tokens excluded from the callee set: ONLY the words the PINNED wasm engine
# itself refuses to parse as call identifiers (ROBOREV M6 finding C). Probed
# empirically against the pinned engine: `true(1)` / `false(1)` / `null(1)` /
# `in(1)` are COMPILE-rejected by the engine grammar (RELAY-CEL-001 parse
# error), so publish already rejects them via probe_compile and excluding
# them here loses nothing (`in` is the load-bearing exclusion: `a in (1, 2)`
# puts `in` directly before `(`). The cel-spec FUTURE-reserved words (`if`,
# `for`, `while`, ...) are NOT excluded: the engine tokenizes them as
# ORDINARY identifiers (`if(1)` compiles and fails only at exec with
# UndeclaredReference("if"), an exec-cause envelope probe_compile defers), so
# hiding them from the callee set would bypass the publish-time
# unregistered-UDF screen. The division of labor is engine-matched: the
# parser excludes EXACTLY what the engine compile-rejects; everything else
# surfaces for the host screens.
_RESERVED_WORDS: frozenset[str] = frozenset(
    {
        "true",
        "false",
        "null",
        "in",
    }
)

# CEL string-literal prefixes: raw (r/R), bytes (b/B), and their combinations.
_STRING_PREFIXES: frozenset[str] = frozenset({"r", "b", "rb", "br"})

_IDENT_START: frozenset[str] = frozenset(string.ascii_letters + "_")
_IDENT_CONT: frozenset[str] = frozenset(string.ascii_letters + string.digits + "_")
_QUOTES: frozenset[str] = frozenset({"'", '"'})

# Characters that END a receiver expression (ROBOREV M6 finding B): a `.`
# whose previous significant character is one of these is MEMBER ACCESS
# (`x.method(...)`, `f(1).g(2)`, `"a".matches(...)`, `[x][0].f(...)`,
# `{...}.size()`); a `.` preceded by anything else (start of expression, an
# operator, `(`, `[`, `{`, `,`, `:`, `&`, `|`, `!`, ...) is a ROOT-QUALIFIED
# (absolute) reference -- CEL permits `.ident(...)` -- whose callee is the
# identifier normalized WITHOUT the leading dot. Identifier and number runs
# record their last character (always in _IDENT_CONT); string literals
# record their closing quote.
_RECEIVER_END_CHARS: frozenset[str] = _IDENT_CONT | {")", "]", "}"} | _QUOTES


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
    (b) is not preceded -- ignoring whitespace and comments -- by a ``.``
    THAT HAS A RECEIVER (member access; a receiver ends with an identifier /
    number character, ``)``, ``]``, ``}``, or a string literal -- a dot
    WITHOUT one is the CEL root-qualified ``.ident(...)`` form and the
    identifier IS a bare callee, normalized without the dot), (c) is
    followed -- ignoring whitespace and comments -- by ``(``, and (d) is not
    one of the engine-compile-rejected words (``true`` / ``false`` /
    ``null`` / ``in``). String-literal bodies and ``//`` comments are
    skipped entirely. Total: never raises on malformed source.
    """
    callees: list[str] = []
    seen: set[str] = set()
    n = len(expression)
    i = 0
    # The last significant (non-whitespace, non-comment, non-literal-body)
    # character seen BEFORE the current scan position; "" at start of input.
    prev_significant = ""
    # Whether the most recently seen "." had a RECEIVER before it (member
    # access) or was a leading/root qualifier (ROBOREV M6 finding B: CEL
    # permits `.ident(...)` absolute references; the pinned engine compiles
    # them and fails only at exec, which probe_compile defers, so the host
    # screens must see the normalized callee). Only meaningful while
    # prev_significant == ".".
    dot_had_receiver = False
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
        # Dot: classify member access vs root qualifier BEFORE overwriting
        # prev_significant (the receiver evidence lives in the character
        # that precedes the dot).
        if c == ".":
            dot_had_receiver = prev_significant in _RECEIVER_END_CHARS
            prev_significant = c
            i += 1
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
            # Member access ONLY when the dot had a receiver; a leading /
            # root-qualified dot (start of expression or after an operator,
            # `(`, `[`, `{`, `,`, ...) makes this a BARE call whose callee
            # is the identifier WITHOUT the dot.
            is_member_access = prev_significant == "." and dot_had_receiver
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
