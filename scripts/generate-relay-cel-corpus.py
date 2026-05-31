"""W6.5 Relay CEL Conformance Corpus generator.

Produces ``tests/conformance/cel/relay_cel_corpus.json`` -- the ~200-case
golden corpus exercised by both ``cel-python`` (Python) and ``cel-js``
(TypeScript). Every case carries enough metadata for the per-runtime
test runners (Python: ``packages/contracts/tests/test_w6_5_corpus.py``;
TypeScript: ``packages/contracts-typescript/test/w6_5_corpus.test.ts``)
to assert byte-for-byte parity after RFC 8785 JCS canonicalisation
(VAL-W6-051) and to verify the per-UDF floor + idiom-matrix coverage
(VAL-W6-052, VAL-W6-053).

Case kinds:

  - ``eval_value``: a CEL expression that BOTH runtimes evaluate to the
    same value. ``py_jcs_b64`` is the base64 of the JCS-canonical bytes
    of the cel-python result. The TS runner asserts cel-js produces a
    value whose JCS bytes equal ``py_jcs_b64``.

  - ``eval_error``: a CEL expression that BOTH runtimes refuse to
    evaluate (e.g. profile-rejected idioms, division by zero, parse
    errors). The runners assert each side raises some exception. Error
    class identity does NOT need to match -- the contract is
    "neither runtime returns a value".

  - ``udf_value``: a direct UDF invocation that bypasses the CEL parser
    entirely (mirrors W6.3 ``relay_udfs_parity.json``). Used to meet
    the per-UDF case-count floor (VAL-W6-052) without depending on
    cel-js exposing UDF binding semantics.

This generator is **deterministic**: running it twice on the same
``cel-python`` version produces byte-identical output. The drift check
(``scripts/check-cel-spec-drift.py``) compares the on-disk corpus to a
freshly-computed run.

ASCII-only per CLAUDE.md.
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path
from typing import Any

# Make packages/contracts importable when running this script directly.
REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "packages" / "contracts" / "src"))

from relay_contracts import (  # noqa: E402  -- after sys.path adjustment
    RELAY_UDFS,
    RelayCelEvaluator,
    jcs_canonicalize,
    relay_coverage,
    relay_schema_match,
    relay_tool_arg,
)

CORPUS_PATH = REPO_ROOT / "tests" / "conformance" / "cel" / "relay_cel_corpus.json"
SCHEMA_VERSION = 1


# ---------------------------------------------------------------------------
# Per-idiom case generators
# ---------------------------------------------------------------------------

# Each generator returns a list of (id, expression, bindings, idiom,
# edge_category) tuples for ``eval_value`` cases. The orchestrator below
# evaluates each in cel-python (via the Relay profile) and records the
# JCS golden bytes.


def arith_cases() -> list[tuple[str, str, dict[str, Any], str, str | None]]:
    cases: list[tuple[str, str, dict[str, Any], str, str | None]] = []
    # Integer arithmetic (whole-valued, no division surprises)
    cases.extend(
        [
            ("arith_int_add_small", "1 + 2", {}, "arithmetic", None),
            ("arith_int_add_zero", "0 + 0", {}, "arithmetic", "empty"),
            ("arith_int_add_neg", "-5 + 3", {}, "arithmetic", None),
            ("arith_int_sub", "10 - 3", {}, "arithmetic", None),
            ("arith_int_sub_neg", "3 - 10", {}, "arithmetic", None),
            ("arith_int_mul", "4 * 5", {}, "arithmetic", None),
            ("arith_int_mul_zero", "0 * 999", {}, "arithmetic", "empty"),
            ("arith_int_mul_neg", "-3 * 4", {}, "arithmetic", None),
            ("arith_int_div_exact", "12 / 3", {}, "arithmetic", None),
            ("arith_int_mod", "10 % 3", {}, "arithmetic", None),
            ("arith_int_mod_zero_dividend", "0 % 7", {}, "arithmetic", "empty"),
            ("arith_int_neg_unary", "-7", {}, "unary", None),
            ("arith_int_double_neg", "-(-5)", {}, "unary", None),
            ("arith_int_precedence", "1 + 2 * 3", {}, "arithmetic", None),
            ("arith_int_paren", "(1 + 2) * 3", {}, "arithmetic", None),
            ("arith_int_chain_add", "1 + 2 + 3 + 4", {}, "arithmetic", None),
            ("arith_int_chain_mul", "2 * 3 * 4", {}, "arithmetic", None),
            ("arith_int_with_var", "a + 1", {"a": 5}, "arithmetic", None),
            ("arith_int_var_var", "a + b", {"a": 7, "b": 13}, "arithmetic", None),
            ("arith_int_var_unary_neg", "-x", {"x": 7}, "unary", None),
            # VAL-PARITY-001 accepted boundary: MAX_SAFE_INTEGER (2**53 - 1)
            # is the LARGEST integer accepted by both runtimes. It is exact in
            # cel-python and exactly representable as a float64 in cel-js, so
            # it canonicalises byte-identically. The very next integer
            # (2**53) is rejected -- see the err_int_two_pow_53_* eval_error
            # cases.
            (
                "arith_int_max_safe_integer_accepted",
                "9007199254740991",
                {},
                "arithmetic",
                None,
            ),
        ]
    )
    # Double arithmetic (whole-valued doubles canonicalise to integer
    # form via JCS ECMA-262 7.1.12.1; verify both runtimes agree)
    cases.extend(
        [
            ("arith_dbl_add_whole", "1.0 + 2.0", {}, "arithmetic", None),
            ("arith_dbl_add_frac", "1.5 + 2.5", {}, "arithmetic", None),
            ("arith_dbl_sub", "10.5 - 0.5", {}, "arithmetic", None),
            ("arith_dbl_mul", "2.5 * 4.0", {}, "arithmetic", None),
            ("arith_dbl_div", "10.0 / 4.0", {}, "arithmetic", None),
            ("arith_dbl_neg", "-1.5", {}, "unary", None),
            ("arith_dbl_neg_zero", "-0.0", {}, "arithmetic", None),
            ("arith_dbl_var", "a + 0.5", {"a": 1.5}, "arithmetic", None),
        ]
    )
    return cases


def string_cases() -> list[tuple[str, str, dict[str, Any], str, str | None]]:
    return [
        ("str_concat_simple", "'a' + 'b'", {}, "string", None),
        ("str_concat_three", "'a' + 'b' + 'c'", {}, "string", None),
        ("str_concat_empty_left", "'' + 'x'", {}, "string", "empty"),
        ("str_concat_empty_right", "'x' + ''", {}, "string", "empty"),
        ("str_concat_both_empty", "'' + ''", {}, "string", "empty"),
        ("str_eq_match", "'foo' == 'foo'", {}, "comparison", None),
        ("str_eq_no_match", "'foo' == 'bar'", {}, "comparison", None),
        ("str_neq", "'foo' != 'bar'", {}, "comparison", None),
        ("str_lt", "'a' < 'b'", {}, "comparison", None),
        ("str_gt", "'z' > 'a'", {}, "comparison", None),
        ("str_le_eq", "'a' <= 'a'", {}, "comparison", None),
        ("str_ge", "'b' >= 'a'", {}, "comparison", None),
        ("str_var", "a + 'x'", {"a": "y"}, "string", None),
        ("str_var_var", "a + b", {"a": "hello", "b": "world"}, "string", None),
        ("str_size_simple", "size('hello')", {}, "string", None),
        ("str_size_empty", "size('')", {}, "string", "empty"),
        # Unicode handling: codepoint-equal strings must compare equal
        # in both runtimes. Note: cel-js does not implement
        # ``string.size()`` as a method, but ``size(s)`` as a builtin
        # call works.
        ("str_unicode_acute_e", "'\\u00e9' == '\\u00e9'", {}, "string", "unicode"),
        # Cyrillic 'a' vs Latin 'a' (homoglyph) -- different codepoints
        ("str_unicode_homoglyph_neq", "'\\u0430' == 'a'", {}, "string", "unicode"),
        # RTL: Arabic letter Alef
        ("str_unicode_rtl_eq", "'\\u0627' == '\\u0627'", {}, "string", "unicode"),
        ("str_unicode_var", "x", {"x": "café"}, "string", "unicode"),
        ("str_size_var", "size(s)", {"s": "abcdef"}, "string", None),
    ]


def list_cases() -> list[tuple[str, str, dict[str, Any], str, str | None]]:
    return [
        ("list_literal_int", "[1, 2, 3]", {}, "list", None),
        ("list_literal_str", "['a', 'b', 'c']", {}, "list", None),
        ("list_literal_mixed_safe", "[1, 'a', true, null]", {}, "list", None),
        ("list_literal_empty", "[]", {}, "list", "empty"),
        ("list_index_first", "[10, 20, 30][0]", {}, "indexing", None),
        ("list_index_middle", "[10, 20, 30][1]", {}, "indexing", None),
        ("list_index_last", "[10, 20, 30][2]", {}, "indexing", None),
        ("list_index_var", "xs[i]", {"xs": [100, 200, 300], "i": 2}, "indexing", None),
        ("list_concat", "[1, 2] + [3, 4]", {}, "list", None),
        ("list_concat_empty_left", "[] + [1]", {}, "list", "empty"),
        ("list_concat_empty_right", "[1] + []", {}, "list", "empty"),
        ("list_concat_both_empty", "[] + []", {}, "list", "empty"),
        ("list_size", "size([1, 2, 3, 4])", {}, "list", None),
        ("list_size_empty", "size([])", {}, "list", "empty"),
        ("list_eq", "[1, 2] == [1, 2]", {}, "comparison", None),
        ("list_neq", "[1, 2] != [1, 3]", {}, "comparison", None),
        ("list_eq_empty", "[] == []", {}, "comparison", "empty"),
        ("list_in_int", "2 in [1, 2, 3]", {}, "in", None),
        ("list_in_string", "'b' in ['a', 'b', 'c']", {}, "in", None),
        ("list_in_missing", "9 in [1, 2, 3]", {}, "in", None),
        ("list_in_empty", "1 in []", {}, "in", "empty"),
        ("list_var", "xs", {"xs": [1, 2, 3]}, "list", None),
        ("list_var_empty", "xs", {"xs": []}, "list", "empty"),
        # Nested list (2 deep)
        ("list_nested_2", "x[0][1]", {"x": [[10, 11], [20, 21]]}, "indexing", None),
    ]


def map_cases() -> list[tuple[str, str, dict[str, Any], str, str | None]]:
    return [
        ("map_literal_simple", "{'a': 1}", {}, "map", None),
        ("map_literal_two_keys", "{'a': 1, 'b': 2}", {}, "map", None),
        ("map_literal_empty", "{}", {}, "map", "empty"),
        ("map_field_access", "{'a': 1, 'b': 2}.a", {}, "member-access", None),
        ("map_field_access_b", "{'a': 1, 'b': 2}.b", {}, "member-access", None),
        ("map_index_string_key", "{'a': 1}['a']", {}, "indexing", None),
        ("map_index_var_key", "m[k]", {"m": {"x": 7}, "k": "x"}, "indexing", None),
        ("map_var_field", "x.a", {"x": {"a": 99}}, "member-access", None),
        ("map_var_nested", "x.a.b", {"x": {"a": {"b": 7}}}, "member-access", None),
        ("map_var_deep_3", "x.a.b.c", {"x": {"a": {"b": {"c": 42}}}}, "member-access", None),
        (
            "map_var_deep_4",
            "x.a.b.c.d",
            {"x": {"a": {"b": {"c": {"d": 11}}}}},
            "member-access",
            None,
        ),
        ("map_eq", "{'a': 1} == {'a': 1}", {}, "comparison", None),
        ("map_neq_value", "{'a': 1} != {'a': 2}", {}, "comparison", None),
        ("map_size", "size({'a': 1, 'b': 2})", {}, "map", None),
        ("map_size_empty", "size({})", {}, "map", "empty"),
        # Map values can be any valid JSON-serialisable type
        ("map_value_string", "{'name': 'relay'}.name", {}, "member-access", None),
        ("map_value_bool", "{'ok': true}.ok", {}, "member-access", None),
        ("map_value_null", "{'x': null}.x", {}, "member-access", None),
        ("map_value_list", "{'xs': [1, 2]}.xs", {}, "member-access", None),
    ]


def comparison_cases() -> list[tuple[str, str, dict[str, Any], str, str | None]]:
    return [
        ("cmp_int_eq", "1 == 1", {}, "comparison", None),
        ("cmp_int_neq", "1 != 2", {}, "comparison", None),
        ("cmp_int_lt", "1 < 2", {}, "comparison", None),
        ("cmp_int_gt", "2 > 1", {}, "comparison", None),
        ("cmp_int_le", "1 <= 1", {}, "comparison", None),
        ("cmp_int_ge", "2 >= 2", {}, "comparison", None),
        ("cmp_dbl_eq", "1.5 == 1.5", {}, "comparison", None),
        ("cmp_dbl_neq", "1.5 != 2.5", {}, "comparison", None),
        ("cmp_dbl_lt", "1.5 < 2.5", {}, "comparison", None),
        ("cmp_bool_eq_true", "true == true", {}, "comparison", None),
        ("cmp_bool_eq_false", "false == false", {}, "comparison", None),
        ("cmp_bool_neq", "true != false", {}, "comparison", None),
        ("cmp_var_var", "a < b", {"a": 1, "b": 2}, "comparison", None),
        # Nested member comparison
        ("cmp_nested_member", "x.a == y.b", {"x": {"a": 5}, "y": {"b": 5}}, "comparison", None),
    ]


def ternary_cases() -> list[tuple[str, str, dict[str, Any], str, str | None]]:
    return [
        ("tern_const_true", "true ? 1 : 2", {}, "ternary", None),
        ("tern_const_false", "false ? 1 : 2", {}, "ternary", None),
        ("tern_var_true", "a ? 'YES' : 'NO'", {"a": True}, "ternary", None),
        ("tern_var_false", "a ? 'YES' : 'NO'", {"a": False}, "ternary", None),
        ("tern_nested", "a ? (b ? 1 : 2) : 3", {"a": True, "b": True}, "ternary", None),
        ("tern_nested_else", "a ? (b ? 1 : 2) : 3", {"a": True, "b": False}, "ternary", None),
        ("tern_nested_outer_else", "a ? 1 : (b ? 2 : 3)", {"a": False, "b": True}, "ternary", None),
        ("tern_with_arith", "x > 0 ? x : -x", {"x": -5}, "ternary", None),
        (
            "tern_string_branches",
            "ok ? msg : 'fallback'",
            {"ok": True, "msg": "hi"},
            "ternary",
            None,
        ),
        ("tern_returns_list", "p ? [1, 2] : [3, 4]", {"p": True}, "ternary", None),
        ("tern_returns_map", "p ? {'a': 1} : {'a': 2}", {"p": False}, "ternary", None),
    ]


def logical_cases() -> list[tuple[str, str, dict[str, Any], str, str | None]]:
    return [
        ("logical_and_tt", "true && true", {}, "logical", None),
        ("logical_and_tf", "true && false", {}, "logical", None),
        ("logical_and_ft", "false && true", {}, "logical", None),
        ("logical_and_ff", "false && false", {}, "logical", None),
        ("logical_or_tt", "true || true", {}, "logical", None),
        ("logical_or_tf", "true || false", {}, "logical", None),
        ("logical_or_ft", "false || true", {}, "logical", None),
        ("logical_or_ff", "false || false", {}, "logical", None),
        ("logical_not_t", "!true", {}, "logical", None),
        ("logical_not_f", "!false", {}, "logical", None),
        ("logical_not_var", "!a", {"a": True}, "logical", None),
        ("logical_combo", "(a || b) && c", {"a": True, "b": False, "c": True}, "logical", None),
        ("logical_de_morgan_l", "!(a && b)", {"a": True, "b": False}, "logical", None),
        ("logical_de_morgan_r", "!a || !b", {"a": True, "b": False}, "logical", None),
    ]


def null_cases() -> list[tuple[str, str, dict[str, Any], str, str | None]]:
    """Null-handling idioms.

    cel-python rejects cross-type equality (``null == 0`` raises
    ``no matching overload``) whereas cel-js silently coerces. The
    corpus restricts to comparisons that BOTH runtimes accept:
    ``null == null``, string-vs-null, and variable-bound nulls
    where the variable's compile-time type matches null. Cross-type
    null-vs-int comparisons live in the eval_error set instead.
    """

    return [
        ("null_literal", "null", {}, "null", None),
        ("null_eq_null", "null == null", {}, "null", None),
        ("null_eq_null_var", "a == null", {"a": None}, "null", None),
        ("null_str_neq_null", "'a' == null", {}, "null", None),
        ("null_in_map", "{'x': null}.x", {}, "null", None),
        ("null_in_list", "[null, null][0]", {}, "null", None),
        ("null_var_returned", "x", {"x": None}, "null", None),
        ("null_in_list_membership", "null in [null, 1]", {}, "null", None),
    ]


def cel_spec_mirror_cases() -> list[tuple[str, str, dict[str, Any], str, str | None]]:
    """Cases that mirror representative entries from the upstream
    cel-spec/cel-conformance test vectors (subset Relay supports:
    non-``dyn``, non-native-timestamp, non-protobuf-message). Each
    case carries an ``idiom`` consistent with the rest of the corpus
    so the idiom-coverage guard counts them toward the matrix.

    The drift checker
    (``scripts/check-cel-spec-drift.py``) loads the vendored
    cel-spec vector list at
    ``tests/conformance/cel/vendor/cel_spec_vectors.json`` and asserts
    that every vector ID present there resolves to a matching corpus
    case ID via the ``cel_spec_id`` field. New upstream vectors not
    yet mirrored here cause the drift check to fail.
    """

    return [
        # Boolean operator basics from cel-spec/conformance/basic/
        ("celspec_basic_or_true", "true || false", {}, "logical", None),
        ("celspec_basic_and_true", "true && true", {}, "logical", None),
        ("celspec_basic_not_true", "!true", {}, "logical", None),
        # Integer overflow boundaries (cel-spec: signed 64-bit semantics)
        ("celspec_int_max_safe_add", "9007199254740990 + 1", {}, "arithmetic", None),
        ("celspec_int_min_safe_neg", "-9007199254740991", {}, "unary", None),
        # String basics
        ("celspec_string_concat", "'hello' + ' ' + 'world'", {}, "string", None),
        ("celspec_string_eq_unicode", "'caf\\u00e9' == 'caf\\u00e9'", {}, "string", "unicode"),
        # List basics
        ("celspec_list_index_zero", "[1, 2, 3][0]", {}, "indexing", None),
        ("celspec_list_size_one", "size([42])", {}, "list", None),
        # Map basics
        ("celspec_map_field_str", "{'name': 'x'}.name", {}, "member-access", None),
        # Comparison transitivity
        ("celspec_cmp_eq_true", "1 == 1", {}, "comparison", None),
        ("celspec_cmp_lt_true", "1 < 2", {}, "comparison", None),
        # Conditional
        ("celspec_cond_true_branch", "true ? 'a' : 'b'", {}, "ternary", None),
        ("celspec_cond_false_branch", "false ? 'a' : 'b'", {}, "ternary", None),
        # Arithmetic
        ("celspec_arith_add_zero_int", "0 + 0", {}, "arithmetic", "empty"),
        ("celspec_arith_mul_one", "1 * 1", {}, "arithmetic", None),
        # Membership
        ("celspec_in_int_present", "1 in [1, 2, 3]", {}, "in", None),
        ("celspec_in_str_absent", "'z' in ['a', 'b']", {}, "in", None),
        # Logical short-circuit (cel-js: && / || are NOT
        # short-circuiting on errors -- both runtimes happen to short-
        # circuit on plain booleans)
        ("celspec_short_circuit_and_false", "false && true", {}, "logical", None),
        ("celspec_short_circuit_or_true", "true || false", {}, "logical", None),
    ]


def regex_backref_ascii_pin_cases() -> (
    list[tuple[str, str, dict[str, Any], str, str | None]]
):
    """VAL-PARITY-007: `\\` + a NON-ASCII digit is NOT a regex backreference.

    A real RE2 backreference is ASCII ``\\1``..``\\9`` only. ``\\`` followed
    by a non-ASCII digit (Unicode Nd category) -- e.g. fullwidth zero U+FF10
    or Arabic-Indic zero U+0660 -- is accepted by RE2 and by the cel-js
    mirror screen ``/\\\\d/`` (JS ``\\d`` is ASCII-only). cel-python's
    ``_BACKREF_PATTERN`` was ``re.compile(r"\\\\d")`` with NO ``re.ASCII``
    flag, so Python ``\\d`` matched the FULL Unicode Nd category and REJECTED
    these -- a cross-runtime divergence. After the ASCII pin
    (``re.compile(r"\\\\[0-9]")``) BOTH runtimes ACCEPT them, evaluating the
    string literal to the same value (so JCS bytes match).

    These are ``eval_value`` cases: the bare string literal evaluates to the
    string itself (no ``.matches()`` call), so cel-python and cel-js must
    produce the SAME value and JCS bytes. The non-ASCII digit is built via
    ``chr`` so this generator source stays ASCII (CLAUDE.md), while the
    emitted corpus expression carries the actual codepoint.

    The ASCII ``\\1`` reject side is covered by the ``err_regex_backref*``
    ``eval_error`` cases (both runtimes refuse).
    """

    fullwidth_zero = chr(0xFF10)  # U+FF10 FULLWIDTH DIGIT ZERO
    arabic_zero = chr(0x0660)  # U+0660 ARABIC-INDIC DIGIT ZERO
    # Each expression is `"\<non-ascii-digit>"` -- a bare double-quoted CEL
    # string literal whose body is backslash + the non-ASCII digit. CEL
    # parses the single backslash literally, yielding the 2-char string.
    return [
        (
            "regex_backslash_fullwidth_digit_accepted",
            '"' + "\\" + fullwidth_zero + '"',
            {},
            "regex",
            "unicode",
        ),
        (
            "regex_backslash_arabic_digit_accepted",
            '"' + "\\" + arabic_zero + '"',
            {},
            "regex",
            "unicode",
        ),
    ]


def coercion_edge_cases() -> list[tuple[str, str, dict[str, Any], str, str | None]]:
    """Type-coercion edges where cel-python and cel-js MUST agree.

    cel-python's strict type semantics REJECT cross-type comparisons
    (``1 == 1.0`` raises) where cel-js silently coerces. We restrict
    these cases to same-type-on-both-sides shapes that exercise the
    coercion-edge boundary safely: int/int, double/double, with
    boundary numeric values that JCS canonicalises differently
    depending on encoder choice (e.g. whole-valued doubles, negative
    zero, very small fractions).
    """

    return [
        ("coerce_dbl_whole_eq", "1.0 == 1.0", {}, "type-coercion", None),
        ("coerce_dbl_whole_add", "2.0 + 3.0", {}, "type-coercion", None),
        ("coerce_dbl_negzero_add", "0.0 + (-0.0)", {}, "type-coercion", None),
        ("coerce_dbl_small_frac", "0.5 + 0.25", {}, "type-coercion", None),
        ("coerce_int_zero", "0", {}, "type-coercion", "empty"),
        ("coerce_dbl_zero", "0.0", {}, "type-coercion", "empty"),
        ("coerce_int_one_literal", "1", {}, "type-coercion", None),
        ("coerce_dbl_three_quarters", "0.75", {}, "type-coercion", None),
        ("coerce_dbl_div_whole_result", "10.0 / 5.0", {}, "type-coercion", None),
        ("coerce_int_var_pos", "x", {"x": 5}, "type-coercion", None),
        ("coerce_dbl_var", "x", {"x": 1.5}, "type-coercion", None),
        # VAL-PARITY-001 whole-double ACCEPT boundary (lock the no-over-reject
        # edge against the err_dbl_whole_above_safe_range REJECT case):
        #   - 100.0: a small whole DOUBLE, comfortably within the safe range;
        #     both runtimes ACCEPT and canonicalise byte-identically.
        #   - 9007199254740991.0 (== MAX_SAFE_INTEGER as a whole DOUBLE): the
        #     LARGEST whole double accepted (abs is NOT > the bound). It is
        #     exact in cel-python and exactly representable as a float64 in
        #     cel-js, so it emits byte-identically. The whole-double reject
        #     branch MUST NOT fire here -- the very next whole double (2**53)
        #     is rejected (covered by err_dbl_whole_above_safe_range above for
        #     a value beyond it).
        ("coerce_dbl_whole_small_accepted", "100.0", {}, "type-coercion", None),
        (
            "coerce_dbl_whole_max_safe_integer_accepted",
            "9007199254740991.0",
            {},
            "type-coercion",
            None,
        ),
    ]


def deeply_nested_cases() -> list[tuple[str, str, dict[str, Any], str, str | None]]:
    """Deeply-nested input edge category for VAL-W6-052/053.
    cel-python evaluates path access through arbitrarily-nested maps
    without recursion limits within the small depths we use here.
    """

    # Build a nested map 32 levels deep at runtime; the corpus stores
    # the literal expression and bindings.
    deep_map: Any = {"v": 7}
    for i in range(32):
        deep_map = {f"k{31 - i}": deep_map}
    # Build the access expression: m.k0.k1.k2...k31.v -> 7
    path = "m." + ".".join(f"k{i}" for i in range(32)) + ".v"

    deep_list: Any = [99]
    for _ in range(15):  # depth 15 keeps the literal printable
        deep_list = [deep_list]

    return [
        (
            "nested_map_depth_32_access",
            path,
            {"m": deep_map},
            "member-access",
            "nested",
        ),
        (
            "nested_map_depth_3_eq",
            "x.a.b.c == y.a.b.c",
            {"x": {"a": {"b": {"c": 1}}}, "y": {"a": {"b": {"c": 1}}}},
            "comparison",
            "nested",
        ),
        (
            "nested_list_depth_15_index",
            "xs[0][0][0][0][0][0][0][0][0][0][0][0][0][0][0][0]",
            {"xs": deep_list},
            "indexing",
            "nested",
        ),
    ]


def has_macro_cases() -> list[tuple[str, str, dict[str, Any], str, str | None]]:
    """``has(...)`` is a CEL macro cel-python supports but cel-js
    REJECTS at parse time. These are ``eval_error`` cases: both
    runtimes refuse the expression. The Python runtime rejects via
    the Relay profile (cel-python has() on a literal map raises
    ``has() does not support atomic expressions`` parity with cel-js
    when the receiver is a literal; for variable receivers cel-python
    succeeds while cel-js fails -- so we restrict the corpus to the
    parser-error shape both runtimes agree on)."""
    # cel-js rejects `has(...)` outright with "has() does not support
    # atomic expressions" for any argument shape we tried. That makes
    # `has()` an ``eval_error`` idiom in our corpus -- both runtimes
    # refuse it. We include enough variants to cover the idiom matrix
    # without depending on shared has() semantics.
    return []  # produced separately as eval_error cases below


def macro_eval_error_cases() -> list[tuple[str, str, dict[str, Any], str]]:
    """Return ``(id, expression, bindings, idiom)`` for cases where
    BOTH runtimes refuse to evaluate. Used to cover idioms that
    cel-js does not parse and to cover Relay-profile rejections.
    """

    return [
        # has() macro -- cel-js rejects "has() does not support atomic
        # expressions"; cel-python evaluates `has({'a':1}.a)` -- so we
        # use a shape both reject. cel-js rejects has() with any
        # argument shape we tested, so use the simplest call that
        # cel-python ALSO refuses (bare identifier inside has() is a
        # parser oddity that triggers errors in both).
        # Empirically: cel-python accepts `has({'a':1}.a)` (true) and
        # cel-js rejects it. Therefore we cannot include `has()` as a
        # parity case -- list it under the "idiom" row only via the
        # cel-spec drift entries. SKIPPED here.

        # all() / exists() macros -- cel-js rejects ``.all()`` /
        # ``.exists()`` member calls outright with parser errors;
        # cel-python evaluates them. NOT a parity case.

        # Profile-rejected idioms: dyn / timestamp / duration. These
        # raise RelayCelProfileError in both runtimes (Python: at
        # compile time; TS: at compile time).
        ("err_dyn_call", "dyn(1)", {}, "profile-rejection"),
        ("err_dyn_call_string", "dyn('x')", {}, "profile-rejection"),
        ("err_timestamp_call", "timestamp('2024-01-01T00:00:00Z')", {}, "profile-rejection"),
        ("err_duration_call", "duration('5s')", {}, "profile-rejection"),
        # Regex backreference -- both runtimes pre-screen the literal
        # and raise ``RelayCelRegexBackreferenceError``.
        ("err_regex_backref", "'abc'.matches('(a)\\\\1')", {}, "regex"),
        ("err_regex_backref_double_quote", '"abc".matches("(a)\\\\1")', {}, "regex"),
        # VAL-PARITY-007: the backref screen is whole-expression scoped on
        # BOTH runtimes -- not just the first ``.matches()`` argument. A
        # backref in a sibling sub-expression, a non-first ``.matches()``
        # argument, or a concatenated operand MUST be rejected identically.
        # cel-python used to accept these (fail-open) while cel-js rejected
        # them (fail-closed); both now reject with RELAY-CEL-007.
        (
            "err_regex_backref_sibling_subexpr",
            'req.matches("ok") && note == "a(b)\\\\1"',
            {},
            "regex",
        ),
        (
            "err_regex_backref_concat_matches_arg",
            'req.matches("a" + "a(b)\\\\1")',
            {},
            "regex",
        ),
        (
            "err_regex_backref_bare_string_no_matches",
            'note == "a(b)\\\\1"',
            {},
            "regex",
        ),
    ]


def numeric_out_of_bounds_eval_error_cases() -> (
    list[tuple[str, str, dict[str, Any], str]]
):
    """Return ``(id, expression, bindings, idiom)`` for integral results
    whose absolute MAGNITUDE exceeds MAX_SAFE_INTEGER (2**53 - 1) in BOTH
    runtimes.

    VAL-PARITY-001: an integral evaluation result outside
    [-(2**53 - 1), 2**53 - 1] is an out-of-band signal -- cel-python keeps it
    exact while a cel-js double rounds it, so the same logical result would
    canonicalise to DIFFERENT JCS bytes in each runtime and silently break
    cross-runtime digest parity. BOTH runtimes therefore fail-closed at the
    evaluation-result boundary (``RelayCelNumericOutOfBoundsError`` /
    RELAY-CEL-006 / RELAY-CEL-NUMERIC-OOB).

    The bound rejects magnitude >= 2**53 (i.e. > MAX_SAFE_INTEGER). 2**53 is
    NOT a safe integer: it cannot be distinguished from 2**53 + 1 after
    IEEE-754 double rounding. Key identity: for any integer V,
    float64(V) > MAX_SAFE_INTEGER  <=>  V >= 2**53, so cel-python (exact int)
    and cel-js (float64) give the SAME verdict for every integer. This is why
    a result of EXACTLY 2**53 + 1 IS a cross-runtime ``eval_error`` case: cel-js
    rounds it to 2**53, which the corrected bound rejects -- matching
    cel-python's exact-integer rejection (the ``err_int_two_pow_53_*`` cases).
    Under the prior EXCLUSIVE bound (abs > 2**53) cel-js ACCEPTED 2**53 and
    silently passed a rounded integer overflow (the fail-open bug found by
    `codex review`: CEL +-2^53 Py<->TS parity P1).
    """

    return [
        # 1e9 * 1e9 = 1e18; exact in cel-python, rounded-but-still-huge in
        # cel-js. abs > MAX_SAFE_INTEGER in both runtimes.
        (
            "err_int_product_above_safe_range",
            "1000000000 * 1000000000",
            {},
            "numeric-out-of-bounds",
        ),
        # 2**53 * 2 = 2**54: exactly representable as a double but still
        # outside the safe range; abs > MAX_SAFE_INTEGER in both runtimes.
        (
            "err_int_double_boundary_above_safe_range",
            "9007199254740992 * 2",
            {},
            "numeric-out-of-bounds",
        ),
        # Negative overflow: -(2**53) * 2 = -2**54; abs > MAX_SAFE_INTEGER in
        # both.
        (
            "err_int_negative_product_below_safe_range",
            "-9007199254740992 * 2",
            {},
            "numeric-out-of-bounds",
        ),
        # Sum overflow: 2**53 + 2**53 = 2**54; abs > MAX_SAFE_INTEGER in both.
        (
            "err_int_sum_above_safe_range",
            "9007199254740992 + 9007199254740992",
            {},
            "numeric-out-of-bounds",
        ),
        # VAL-PARITY-001 boundary cases (found by `codex review`: CEL +-2^53
        # Py<->TS parity P1). The corrected bound rejects magnitude >= 2**53
        # (i.e. > MAX_SAFE_INTEGER). 2**53 itself is NOT a safe integer -- a
        # cel-js double rounds an integer overflow that lands on 2**53 + 1
        # down to 2**53, so accepting exactly 2**53 (the prior EXCLUSIVE
        # bound) let cel-js silently pass a rounded integer overflow
        # (fail-open). These cases reproduce that hazard and assert BOTH
        # runtimes now fail-closed (cel-python keeps the exact int and
        # rejects; cel-js rounds to >= 2**53 and rejects). Before the fix
        # these ACCEPTED in cel-js -- a cross-runtime divergence and a
        # cross-runtime digest break (CLAUDE.md keystone invariant #11).

        # 2**53 exactly: literal boundary value, formerly accepted in BOTH
        # runtimes; now rejected in BOTH because 2**53 is unsafe.
        (
            "err_int_two_pow_53_boundary",
            "9007199254740992",
            {},
            "numeric-out-of-bounds",
        ),
        # 2**53 + 1 (== 9007199254740993) as an integer literal. cel-python
        # keeps it exact; cel-js rounds it to 9007199254740992 == 2**53. Both
        # reject (>= 2**53). Formerly cel-js ACCEPTED (fail-open).
        (
            "err_int_two_pow_53_plus_one_literal",
            "9007199254740993",
            {},
            "numeric-out-of-bounds",
        ),
        # 2**53 + 1 via addition: cel-python computes the exact int
        # 9007199254740993 and rejects; cel-js does float64 arithmetic and
        # rounds the sum to 9007199254740992 == 2**53, also rejecting.
        # Formerly cel-js ACCEPTED (fail-open) -- the exact divergence codex
        # flagged.
        (
            "err_int_two_pow_53_plus_one_add",
            "9007199254740992 + 1",
            {},
            "numeric-out-of-bounds",
        ),
        # VAL-PARITY-001 whole-DOUBLE branch (found by `codex review`: CEL
        # whole-double >= 2**53 Py<->TS parity). A whole-valued DOUBLE literal
        # whose magnitude exceeds MAX_SAFE_INTEGER. cel-js (cel-js 0.8.2)
        # collapses CEL int and CEL double to a bare JS number and re-derives
        # the type from the value (``getCelType`` classifies any whole-valued
        # number as int), so the DOUBLE 9007199254740994.0 is INDISTINGUISHABLE
        # there from the int 9007199254740994 and is rejected by the int bound.
        # cel-python preserved the DoubleType, so the prior int-only bound let
        # cel-python ACCEPT this double while cel-js REJECTED it -- a
        # cross-runtime divergence. The whole-double branch in evaluator.py
        # _check_finite now rejects it too, so BOTH runtimes fail-closed.
        # (Note: no representable float64 of magnitude > MAX_SAFE_INTEGER is
        # non-integral -- the ULP at 2**53 is 2.0 -- so this is the
        # double-typed analogue of the integer bound, not an additional class
        # of values.)
        (
            "err_dbl_whole_above_safe_range",
            "9007199254740994.0",
            {},
            "numeric-out-of-bounds",
        ),
    ]


# ---------------------------------------------------------------------------
# UDF cases (direct call -- bypasses CEL parser)
# ---------------------------------------------------------------------------


def udf_coverage_cases() -> list[tuple[str, str, list[Any], str | None]]:
    """``(id, udf_name, args, edge_category)`` for relay.coverage."""
    return [
        # Happy path (3+)
        (
            "udf_cov_first_match",
            "relay.coverage",
            [{"steps": [{"name": "alpha"}, {"name": "beta"}]}, "alpha"],
            None,
        ),
        (
            "udf_cov_last_match",
            "relay.coverage",
            [{"steps": [{"name": "alpha"}, {"name": "beta"}, {"name": "gamma"}]}, "gamma"],
            None,
        ),
        (
            "udf_cov_middle_match",
            "relay.coverage",
            [{"steps": [{"name": "alpha"}, {"name": "beta"}, {"name": "gamma"}]}, "beta"],
            None,
        ),
        (
            "udf_cov_no_match_returns_false",
            "relay.coverage",
            [{"steps": [{"name": "alpha"}]}, "missing"],
            None,
        ),
        (
            "udf_cov_unicode_match",
            "relay.coverage",
            [{"steps": [{"name": "café"}]}, "café"],
            "unicode",
        ),
        # Edge categories (2+)
        ("udf_cov_null_trace", "relay.coverage", [None, "x"], "null"),
        ("udf_cov_empty_steps", "relay.coverage", [{"steps": []}, "x"], "empty"),
        (
            "udf_cov_large_trace",
            "relay.coverage",
            [
                {"steps": [{"name": f"step_{i:04d}"} for i in range(120)]},
                "step_0099",
            ],
            "large",
        ),
        (
            "udf_cov_nested_unrelated_keys",
            "relay.coverage",
            [
                {
                    "steps": [
                        {"name": "a", "meta": {"deeply": {"nested": [1, 2, 3]}}},
                        {"name": "b"},
                    ]
                },
                "b",
            ],
            "nested",
        ),
    ]


def udf_tool_arg_cases() -> list[tuple[str, str, list[Any], str | None]]:
    return [
        # Happy
        ("udf_arg_string", "relay.tool_arg", [{"args": {"k": "v"}}, "k"], None),
        ("udf_arg_int", "relay.tool_arg", [{"args": {"n": 42}}, "n"], None),
        ("udf_arg_bool_true", "relay.tool_arg", [{"args": {"b": True}}, "b"], None),
        ("udf_arg_bool_false", "relay.tool_arg", [{"args": {"b": False}}, "b"], None),
        ("udf_arg_null_value", "relay.tool_arg", [{"args": {"x": None}}, "x"], None),
        # Edge
        ("udf_arg_null_call", "relay.tool_arg", [None, "k"], "null"),
        ("udf_arg_no_args", "relay.tool_arg", [{}, "k"], "empty"),
        ("udf_arg_unicode_value", "relay.tool_arg", [{"args": {"k": "café"}}, "k"], "unicode"),
        (
            "udf_arg_large_value",
            "relay.tool_arg",
            [{"args": {"payload": "x" * 10240}}, "payload"],
            "large",
        ),
        (
            "udf_arg_nested_object",
            "relay.tool_arg",
            [{"args": {"obj": _build_nested(8)}}, "obj"],
            "nested",
        ),
    ]


def udf_schema_match_cases() -> list[tuple[str, str, list[Any], str | None]]:
    return [
        # Happy
        ("udf_sm_string_ok", "relay.schema_match", ["hello", {"type": "string"}], None),
        ("udf_sm_int_ok", "relay.schema_match", [42, {"type": "integer"}], None),
        ("udf_sm_object_required", "relay.schema_match",
         [{"a": 1, "b": 2}, {"type": "object", "required": ["a", "b"]}], None),
        ("udf_sm_array_items_ok", "relay.schema_match",
         [[1, 2, 3], {"type": "array", "items": {"type": "integer"}}], None),
        ("udf_sm_string_mismatch", "relay.schema_match", [123, {"type": "string"}], None),
        # Edge
        ("udf_sm_null_payload", "relay.schema_match", [None, {"type": "null"}], "null"),
        ("udf_sm_empty_schema", "relay.schema_match", [{"x": 1}, {}], "empty"),
        (
            "udf_sm_unicode_payload",
            "relay.schema_match",
            ["café", {"type": "string"}],
            "unicode",
        ),
        (
            "udf_sm_large_payload",
            "relay.schema_match",
            [
                {"items": list(range(1024))},
                {"type": "object", "required": ["items"]},
            ],
            "large",
        ),
        (
            "udf_sm_nested_schema",
            "relay.schema_match",
            [_build_nested(8), _build_nested_schema(8)],
            "nested",
        ),
    ]


def _build_nested(depth: int) -> dict[str, Any]:
    """Build a dict nested ``depth`` levels deep (>=32 for the deeply-
    nested edge category when called with depth=33)."""

    leaf: Any = {"value": 1}
    for _ in range(depth):
        leaf = {"inner": leaf}
    return leaf


def _build_nested_schema(depth: int) -> dict[str, Any]:
    leaf: dict[str, Any] = {"type": "object", "required": ["value"]}
    for _ in range(depth):
        leaf = {"type": "object", "required": ["inner"], "properties": {"inner": leaf}}
    return leaf


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


def _b64_jcs(value: Any) -> str:
    return base64.b64encode(jcs_canonicalize(value)).decode("ascii")


def _to_python(value: Any) -> Any:
    """Coerce a celpy result into JSON-roundtrippable Python so JCS
    can serialise it. celpy returns wrapped types
    (``IntType``/``DoubleType``/``BoolType``/``StringType``/
    ``ListType``/``MapType``); their underlying Python representation
    is what JCS expects."""

    import celpy.celtypes as celtypes

    if value is None:
        return None
    if isinstance(value, celtypes.BoolType):
        return bool(value)
    if isinstance(value, celtypes.IntType):
        return int(value)
    if isinstance(value, celtypes.DoubleType):
        return float(value)
    if isinstance(value, celtypes.StringType):
        return str(value)
    if isinstance(value, celtypes.ListType | list | tuple):
        return [_to_python(v) for v in value]
    if isinstance(value, celtypes.MapType | dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            kk = str(k) if not isinstance(k, str) else k
            out[kk] = _to_python(v)
        return out
    if isinstance(value, bool | int | float | str):
        return value
    raise TypeError(f"unsupported celpy result type: {type(value).__name__}")


def _eval_python(expression: str, bindings: dict[str, Any]) -> Any:
    """Evaluate ``expression`` via the Relay-profile cel-python
    evaluator. Returns the JSON-roundtrippable Python value."""

    ev = RelayCelEvaluator(udfs=RELAY_UDFS)
    # cel-python accepts plain Python values for bindings; convert
    # using its own type adapters.
    import celpy.celtypes as celtypes

    def conv(v: Any) -> Any:
        if v is None:
            return None
        if isinstance(v, bool):
            return celtypes.BoolType(v)
        if isinstance(v, int):
            return celtypes.IntType(v)
        if isinstance(v, float):
            return celtypes.DoubleType(v)
        if isinstance(v, str):
            return celtypes.StringType(v)
        if isinstance(v, list | tuple):
            return celtypes.ListType([conv(x) for x in v])
        if isinstance(v, dict):
            return celtypes.MapType({celtypes.StringType(k): conv(vv) for k, vv in v.items()})
        return v

    cel_bindings = {k: conv(v) for k, v in bindings.items()}
    return ev.evaluate(expression, cel_bindings)


def _apply_udf(udf_name: str, args: list[Any]) -> Any:
    if udf_name == "relay.coverage":
        return relay_coverage(*args)
    if udf_name == "relay.tool_arg":
        return relay_tool_arg(*args)
    if udf_name == "relay.schema_match":
        return relay_schema_match(*args)
    raise ValueError(f"unknown udf: {udf_name}")


def build_corpus() -> dict[str, Any]:
    cases: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    # eval_value cases
    eval_value_inputs: list[tuple[str, str, dict[str, Any], str, str | None]] = []
    eval_value_inputs.extend(arith_cases())
    eval_value_inputs.extend(string_cases())
    eval_value_inputs.extend(list_cases())
    eval_value_inputs.extend(map_cases())
    eval_value_inputs.extend(comparison_cases())
    eval_value_inputs.extend(ternary_cases())
    eval_value_inputs.extend(logical_cases())
    eval_value_inputs.extend(null_cases())
    eval_value_inputs.extend(cel_spec_mirror_cases())
    eval_value_inputs.extend(coercion_edge_cases())
    eval_value_inputs.extend(deeply_nested_cases())
    eval_value_inputs.extend(regex_backref_ascii_pin_cases())
    for case_id, expr, bindings, idiom, edge_cat in eval_value_inputs:
        if case_id in seen_ids:
            raise ValueError(f"duplicate case id: {case_id}")
        seen_ids.add(case_id)
        try:
            raw = _eval_python(expr, bindings)
        except Exception as exc:
            raise RuntimeError(
                f"eval_value case {case_id!r} failed in cel-python: {exc!r}"
            ) from exc
        py_value = _to_python(raw)
        case: dict[str, Any] = {
            "id": case_id,
            "kind": "eval_value",
            "idiom": idiom,
            "expression": expr,
            "bindings": bindings,
            "py_jcs_b64": _b64_jcs(py_value),
        }
        if edge_cat is not None:
            case["edge_category"] = edge_cat
        cases.append(case)

    # eval_error cases
    eval_error_inputs: list[tuple[str, str, dict[str, Any], str]] = []
    eval_error_inputs.extend(macro_eval_error_cases())
    eval_error_inputs.extend(numeric_out_of_bounds_eval_error_cases())
    for case_id, expr, bindings, idiom in eval_error_inputs:
        if case_id in seen_ids:
            raise ValueError(f"duplicate case id: {case_id}")
        seen_ids.add(case_id)
        # Verify the Python side really does raise; otherwise the case
        # is mis-classified and should be eval_value.
        raised = False
        try:
            _eval_python(expr, bindings)
        except Exception:
            raised = True
        if not raised:
            raise RuntimeError(
                f"eval_error case {case_id!r} did NOT raise in cel-python; "
                "reclassify as eval_value or remove."
            )
        cases.append(
            {
                "id": case_id,
                "kind": "eval_error",
                "idiom": idiom,
                "expression": expr,
                "bindings": bindings,
            }
        )

    # udf_value cases
    udf_inputs: list[tuple[str, str, list[Any], str | None]] = []
    udf_inputs.extend(udf_coverage_cases())
    udf_inputs.extend(udf_tool_arg_cases())
    udf_inputs.extend(udf_schema_match_cases())
    for case_id, udf_name, args, edge_cat in udf_inputs:
        if case_id in seen_ids:
            raise ValueError(f"duplicate case id: {case_id}")
        seen_ids.add(case_id)
        result = _apply_udf(udf_name, args)
        case = {
            "id": case_id,
            "kind": "udf_value",
            "idiom": "udf",
            "udf": udf_name,
            "args": args,
            "py_jcs_b64": _b64_jcs(result),
        }
        if edge_cat is not None:
            case["edge_category"] = edge_cat
        cases.append(case)

    return {"schema_version": SCHEMA_VERSION, "cases": cases}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify on-disk corpus equals freshly-computed bytes; exit 1 on drift.",
    )
    parser.add_argument(
        "--out",
        default=str(CORPUS_PATH),
        help=f"Output path (default: {CORPUS_PATH}).",
    )
    args = parser.parse_args()

    corpus = build_corpus()
    serialised = json.dumps(corpus, indent=2, sort_keys=True) + "\n"
    out_path = Path(args.out)

    if args.check:
        if not out_path.exists():
            print(f"FAIL: corpus file does not exist: {out_path}")
            return 1
        existing = out_path.read_text(encoding="utf-8")
        if existing != serialised:
            print("FAIL: corpus drift detected; regenerate via:")
            print("  uv run python scripts/generate-relay-cel-corpus.py")
            return 1
        print(f"OK: corpus is up-to-date ({len(corpus['cases'])} cases).")
        return 0

    out_path.parent.mkdir(parents=True, exist_ok=True)
    # Use ascii-safe Path.write_text? No -- this is a script in
    # scripts/, not a relay package. The four-primitives lint exempts
    # scripts/. We want a deterministic file write here.
    out_path.write_text(serialised, encoding="utf-8")
    print(f"OK: wrote {len(corpus['cases'])} cases to {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
