"""M6 WS-I: minimal host-side standalone CEL callee parser.

After WS-I removes cel-python, ``pipeline.publish_contract`` can no longer
derive the statically-referenced callee set from a celpy AST walk
(`evaluator._env.compile`). Per ADR cel-wasm-cutover-workstreams Revisions
section 3, the sanctioned replacement (with the crate frozen until M7) is a
MINIMAL host-side standalone callee parser: a tokenizer that extracts
identifiers in BARE function-call position from the CEL source text. It is
NOT a full CEL parser -- the wasm engine remains the authoritative compiler;
the parser only needs to:

  - find bare-call identifiers (``name(``), matching the celpy
    ``ident_arg`` walk it replaces (member calls ``x.name(...)`` were never
    yielded by that walk and are not yielded here);
  - skip string literals (single/double/triple-quoted, r/b prefixes) so
    quoted text never produces a false callee;
  - skip ``//`` line comments;
  - exclude CEL reserved words (``in`` is the load-bearing one:
    ``a in (1, 2)`` must not yield a callee ``in``).

VAL-CWC-P6REMOVE-003 (the ``udfs_invoked`` / publish-time callee set is
derived WITHOUT the celpy AST walk).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import pytest
from relay_contracts.callee_parser import extract_bare_callees

pytestmark = pytest.mark.plumbing


# ---------------------------------------------------------------------------
# bare-call extraction
# ---------------------------------------------------------------------------


def test_simple_bare_call() -> None:
    assert extract_bare_callees("my_check(1)") == ("my_check",)


def test_multiple_bare_calls_in_source_order_deduped() -> None:
    assert extract_bare_callees('f(1) && g("x") || f(2)') == ("f", "g")


def test_nested_calls_all_extracted() -> None:
    assert extract_bare_callees("outer(inner(1), other(2))") == (
        "outer",
        "inner",
        "other",
    )


def test_bare_reference_without_call_not_extracted() -> None:
    # A variable lookup is not a UDF call (matches the celpy ident_arg walk).
    assert extract_bare_callees("dyn") == ()
    assert extract_bare_callees("x + y") == ()


def test_whitespace_between_ident_and_paren_still_a_call() -> None:
    assert extract_bare_callees("size (x)") == ("size",)


# ---------------------------------------------------------------------------
# member calls are NOT bare callees
# ---------------------------------------------------------------------------


def test_member_call_not_extracted() -> None:
    # x.method(...) is a member call; the celpy walk never yielded it.
    assert extract_bare_callees('"a".matches("b")') == ()
    assert extract_bare_callees("trace.size()") == ()


def test_dotted_udf_call_not_extracted_as_bare() -> None:
    # relay.coverage(...) parses as a member call on `relay`; the bare-callee
    # parser (like the celpy ident_arg walk it replaces) does not yield it.
    assert extract_bare_callees('relay.coverage(trace, "s")') == ()


def test_member_call_with_spaces_around_dot_not_extracted() -> None:
    assert extract_bare_callees("a . method (1)") == ()


def test_argument_of_member_call_still_extracted() -> None:
    assert extract_bare_callees("x.filter(f(1))") == ("f",)


# ---------------------------------------------------------------------------
# string literals never produce callees
# ---------------------------------------------------------------------------


def test_call_inside_double_quoted_string_ignored() -> None:
    assert extract_bare_callees('"dyn(1)" == s') == ()


def test_call_inside_single_quoted_string_ignored() -> None:
    assert extract_bare_callees("'foo(1)' == s") == ()


def test_escaped_quote_does_not_terminate_string() -> None:
    # The escaped quote keeps the literal open; bar( is inside the literal.
    assert extract_bare_callees('"a\\"bar(" == s && f(1)') == ("f",)


def test_raw_string_backslash_does_not_escape_quote() -> None:
    # In a CEL raw string a backslash is literal; the second quote CLOSES the
    # string, so g( after it is a real call.
    assert extract_bare_callees('r"\\" == x && g(1)') == ("g",)


def test_bytes_and_raw_prefixes_skip_literal_body() -> None:
    assert extract_bare_callees('b"f(1)" == x') == ()
    assert extract_bare_callees('rb"g(2)" == x') == ()
    assert extract_bare_callees('R"h(3)" == x') == ()


def test_triple_quoted_string_body_ignored() -> None:
    assert extract_bare_callees('"""dyn(1) " inner """ == s && f(2)') == ("f",)


def test_unterminated_string_consumes_rest_fail_safe() -> None:
    # Malformed source: the unterminated literal swallows the tail. No false
    # callee is produced; the wasm compiler rejects the source at publish.
    assert extract_bare_callees('"never closed f(1)') == ()


# ---------------------------------------------------------------------------
# comments never produce callees
# ---------------------------------------------------------------------------


def test_line_comment_ignored() -> None:
    assert extract_bare_callees("1 + 1 // dyn(1)\n== 2") == ()


def test_comment_then_call_on_next_line() -> None:
    assert extract_bare_callees("// leading comment f(0)\ng(1)") == ("g",)


def test_division_is_not_a_comment() -> None:
    assert extract_bare_callees("size(x) / size(y) == 1") == ("size",)


# ---------------------------------------------------------------------------
# reserved words are never callees -- ONLY the tokens the wasm engine itself
# refuses to parse as call identifiers (ROBOREV M6 finding C)
# ---------------------------------------------------------------------------


def test_in_operator_before_paren_is_not_a_callee() -> None:
    # `a in (...)` -- the parenthesized RHS must not turn `in` into a callee.
    assert extract_bare_callees("a in (1, 2, 3)") == ()


@pytest.mark.parametrize("word", ["true", "false", "null", "in"])
def test_engine_compile_rejected_words_excluded(word: str) -> None:
    # Empirically probed against the PINNED wasm engine: `true(1)`,
    # `false(1)`, `null(1)`, and `in(1)` are COMPILE-rejected by the engine
    # grammar (RELAY-CEL-001 parse error), so publish already rejects them
    # via probe_compile; the parser may exclude exactly these.
    assert extract_bare_callees(f"{word} (x)") == ()


@pytest.mark.parametrize(
    "word",
    [
        "as", "break", "const", "continue", "else", "for", "function", "if",
        "import", "let", "loop", "namespace", "package", "return", "var",
        "void", "while",
    ],
)
def test_future_reserved_words_surface_as_callees(word: str) -> None:
    # ROBOREV M6 finding C: empirically probed against the PINNED wasm
    # engine, every future-reserved word tokenizes as an ORDINARY identifier
    # (`if(1)` compiles and fails only at exec with
    # UndeclaredReference("if"), which probe_compile defers) -- so the parser
    # MUST surface it as a callee or the publish-time unregistered-UDF
    # screen is bypassed.
    assert extract_bare_callees(f"{word}(x)") == (word,)


# ---------------------------------------------------------------------------
# leading-dot ROOT-QUALIFIED calls are bare callees (ROBOREV M6 finding B):
# CEL permits `.ident(...)` (absolute / root-namespace reference). The
# pinned engine compiles it and fails only at exec
# (UndeclaredReference(".dyn")), which probe_compile defers -- so the parser
# must normalize `.dyn` -> `dyn` or the publish-time profile and
# unregistered-UDF screens are bypassed.
# ---------------------------------------------------------------------------


def test_leading_dot_dyn_at_start_of_expression_is_a_callee() -> None:
    assert extract_bare_callees(".dyn(1)") == ("dyn",)


def test_leading_dot_after_short_circuit_operator_is_a_callee() -> None:
    assert extract_bare_callees("false && .dyn(1)") == ("dyn",)
    assert extract_bare_callees("true || .timestamp('x')") == ("timestamp",)


def test_leading_dot_unknown_udf_is_a_callee() -> None:
    assert extract_bare_callees(".unknown(2)") == ("unknown",)


@pytest.mark.parametrize(
    "expression,expected",
    [
        ("( .dyn(1) )", ("dyn",)),
        ("[.dyn(1)]", ("dyn",)),
        ("f(.dyn(1))", ("f", "dyn")),
        ("1 + .dyn(2)", ("dyn",)),
        ("x == .dyn(2)", ("dyn",)),
        ("a ? .dyn(1) : .unknown(2)", ("dyn", "unknown")),
        ("!.dyn(1)", ("dyn",)),
        ("{1: .dyn(2)}", ("dyn",)),
        (", .dyn(1)", ("dyn",)),
    ],
)
def test_leading_dot_after_operators_is_root_qualified(
    expression: str, expected: tuple[str, ...]
) -> None:
    # After an operator / opening bracket / comma the `.` has NO receiver:
    # the call is root-qualified and its callee must surface (normalized
    # WITHOUT the dot).
    assert extract_bare_callees(expression) == expected


def test_root_qualified_member_chain_is_still_a_member_call() -> None:
    # `.a.b(1)`: `b` is a member call on the root-qualified `.a` receiver --
    # the engine validates member calls at eval; not a bare callee.
    assert extract_bare_callees(".a.b(1)") == ()


def test_root_qualified_dedupes_with_bare_form() -> None:
    assert extract_bare_callees(".dyn(1) && dyn(2)") == ("dyn",)


@pytest.mark.parametrize(
    "expression",
    [
        "a.b(1)",
        '"a".matches("b")',
        'relay.coverage(trace, "s")',
        "x[0].f(1)",
        "f(1).g(2)",
        "(a).m(2)",
        "{'k': 1}.size()",
        "1.5.f(1)",
        "a . method (1)",
    ],
)
def test_member_access_with_receiver_does_not_regress(expression: str) -> None:
    # The receiver-tracking fix must NOT turn genuine member access into a
    # bare callee: previous significant token is an identifier / `)` / `]` /
    # `}` / string literal / number -> the `.` is member access.
    callees = extract_bare_callees(expression)
    for name in ("b", "matches", "coverage", "m", "size", "method"):
        assert name not in callees, (
            f"member callee {name!r} falsely extracted from {expression!r}"
        )


def test_member_access_argument_callee_still_extracted_with_receiver() -> None:
    assert extract_bare_callees("x[0].f(g(1))") == ("g",)


# ---------------------------------------------------------------------------
# profile-relevant builtins surface as bare callees (the compile-time
# profile screen intersects the callee set with the disabled builtins)
# ---------------------------------------------------------------------------


def test_disabled_builtin_calls_are_extracted() -> None:
    assert extract_bare_callees("dyn(1)") == ("dyn",)
    assert extract_bare_callees('timestamp("2020-01-01T00:00:00Z")') == (
        "timestamp",
    )
    assert extract_bare_callees('duration("1s")') == ("duration",)


def test_short_circuited_call_still_statically_extracted() -> None:
    # Static extraction is the point: a short-circuited branch never RUNS,
    # but the callee is still statically referenced (celpy _check_profile
    # rejected it at compile; the parser preserves that).
    assert extract_bare_callees("false && dyn(1)") == ("dyn",)


def test_identifier_adjacent_to_number_is_not_a_callee() -> None:
    # `0x1f` style adjacency: the alpha run inside a larger token is not an
    # identifier in call position.
    assert extract_bare_callees("0x1f (x)") == ()


def test_underscore_identifiers_extracted() -> None:
    assert extract_bare_callees("_private(1) && my_check2(2)") == (
        "_private",
        "my_check2",
    )


def test_empty_and_garbage_input_total() -> None:
    assert extract_bare_callees("") == ()
    assert extract_bare_callees("(((") == ()
    assert extract_bare_callees("&& || !") == ()
