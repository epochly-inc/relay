"""G6: cross-numeric equality/ordering compares by VALUE (cel-rust-relay fork).

The published cel 0.13.0 numeric `Val::equals` was same-type-only, so `1.0 == 1`
was false. The fork delegates `equals` to the cross-numeric `Comparer::compare`.
These run against the actual wasm; tier-1 plumbing.
"""
import pytest
from relay_cel_wasm import RelayCel

C = RelayCel()


def val(expr):
    r = C.eval(expr)
    assert r["ok"], f"{expr} unexpectedly rejected: {r}"
    return r["value"]


def b(expr):
    v = val(expr)
    assert v["t"] == "bool", f"{expr} -> {v}"
    return v["v"]


@pytest.mark.plumbing
@pytest.mark.parametrize("expr,expected", [
    # cross-numeric equality by value
    ("1.0 == 1", True), ("1 == 1.0", True), ("1 == 1u", True), ("1u == 1", True),
    ("1.0 == 1u", True), ("1u == 1.0", True),
    ("1 != 1.0", False), ("1.0 != 1u", False),
    # not equal when values differ
    ("1 == 1.5", False), ("1 == 2u", False), ("2.0 == 1", False),
    # heterogeneous (non-numeric) -> false, NOT error
    ("1 == 'a'", False), ("1.0 == true", False), ("1u == null", False),
    # int/uint boundary by value (no precision loss)
    ("-1 == 18446744073709551615u", False),
    ("9223372036854775807 == 9223372036854775807u", True),
    ("9223372036854775807 == 9223372036854775808u", False),
    # cross-numeric inside containers + membership
    ("[1.0, 2.0, 3] == [1u, 2, 3u]", True),
    ("1 in [1u, 2u]", True), ("3 in [1u, 2u]", False),
    # same-type still correct
    ("1 == 1", True), ("1.0 == 1.0", True), ("1u == 1u", True),
])
def test_cross_numeric_equality(expr, expected):
    assert b(expr) is expected


@pytest.mark.plumbing
@pytest.mark.parametrize("expr,expected", [
    ("1 < 2u", True), ("1.0 < 2", True), ("2u > 1", True), ("1 <= 1.0", True),
    ("2.0 >= 2u", True), ("1u < 0", False),
])
def test_cross_numeric_ordering(expr, expected):
    assert b(expr) is expected


@pytest.mark.plumbing
def test_nan_not_equal_self():
    # NaN from arithmetic: NaN == NaN is false (compare -> partial_cmp None -> Err).
    assert b("(0.0/0.0) == (0.0/0.0)") is False
    assert b("(0.0/0.0) != (0.0/0.0)") is True
