"""G4: two-variable comprehension macros (cel-rust-relay fork).

CEL `ext.TwoVarComprehensions`: the receiver forms `e.all(i, v, p)`,
`e.exists(i, v, p)`, `e.existsOne(i, v, p)` (and `e.exists_one(...)`),
`e.transformList(i, v[, f], t)`, and `e.transformMap(i, v[, f], t)`. For a LIST
receiver `i` is the 0-based index; for a MAP receiver `i` is the key; `v` is the
value in both cases.

The published cel 0.13.0 only lowered the one-variable forms (`all(v, p)` etc.),
so the two-variable receiver call fell through to an undeclared `exists`/`all`
function. The fork adds the two-variable macro lowering in the parser
(`vendor/cel/src/parser/macros.rs`) plus two-variable binding in the
comprehension engine (`vendor/cel/src/objects.rs`) and the synthetic
`cel.@mapInsert` step used by `transformMap`.

These run against the actual wasm; tier-1 plumbing. The expected values mirror
the cel-spec `macros2.textproto` corpus and the cel-go v0.28 oracle.
"""
import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "python"))

from relay_cel_wasm import RelayCel  # noqa: E402

C = RelayCel()


def res(expr):
    return C.eval(expr)


def val(expr):
    r = res(expr)
    assert r["ok"], f"{expr} unexpectedly rejected: {r}"
    return r["value"]


def b(expr):
    v = val(expr)
    assert v["t"] == "bool", f"{expr} -> {v}"
    return v["v"]


def ints(typed_list):
    """Extract a python list of ints from a {'t':'list','v':[...]} value."""
    assert typed_list["t"] == "list", typed_list
    out = []
    for e in typed_list["v"]:
        assert e["t"] == "int", e
        out.append(int(e["v"]))
    return out


def str_map(typed_map):
    """Extract {str: str} from a {'t':'map','v':[[k,v],...]} value."""
    assert typed_map["t"] == "map", typed_map
    out = {}
    for k, v in typed_map["v"]:
        assert k["t"] == "string" and v["t"] == "string", (k, v)
        out[k["v"]] = v["v"]
    return out


# --------------------------------------------------------------------------
# exists(i, v, predicate)  (corpus section "exists")
# --------------------------------------------------------------------------
@pytest.mark.plumbing
@pytest.mark.parametrize("expr,expected", [
    ("[1, 2, 3].exists(i, v, i > -1 && v > 0)", True),       # list_elem_all_true
    ("[1, 2, 3].exists(i, v, i == 1 && v == 2)", True),      # list_elem_some_true
    ("[1, 2, 3].exists(i, v, i > 2 && v > 3)", False),       # list_elem_none_true
    ("[1, 'foo', 3].exists(i, v, i == 1 && v != '1')", True),  # type_shortcircuit
    ("[1, 'foo', 3].exists(i, v, i == 3 || v == '10')", False),  # type_exhaustive
    ("[].exists(i, v, i == 0 || v == 2)", False),            # list_empty
    ("{'key1':1, 'key2':2}.exists(k, v, k == 'key2' && v == 2)", True),  # map_key
    ("!{'key1':1, 'key2':2}.exists(k, v, k == 'key3' || v == 3)", True),  # not_map_key
    ("{'key':1, 1:21}.exists(k, v, k != 2 && v != 22)", True),  # map_type_shortcircuit
    ("!{'key':1, 1:42}.exists(k, v, k == 2 && v == 43)", True),  # map_type_exhaustive
])
def test_exists2(expr, expected):
    assert b(expr) is expected


@pytest.mark.plumbing
def test_exists2_error():
    # list_elem_exists_error: divide by zero must propagate (i starts at 0).
    r = res("[1, 2, 3].exists(i, v, v / i == 17)")
    assert r["ok"] is False
    assert "Division" in r["error"] or "divide" in r["error"].lower()


# --------------------------------------------------------------------------
# all(i, v, predicate)  (corpus section "all")
# --------------------------------------------------------------------------
@pytest.mark.plumbing
@pytest.mark.parametrize("expr,expected", [
    ("[1, 2, 3].all(i, v, i > -1 && v > 0)", True),          # list_elem_all_true
    ("[1, 2, 3].all(i, v, i == 1 && v == 2)", False),        # list_elem_some_true
    ("[1, 2, 3].all(i, v, i == 3 || v == 4)", False),        # list_elem_none_true
    ("[1, 'foo', 3].all(i, v, i == 0 || v == 1)", False),    # type_shortcircuit
    ("[].all(i, v, i > -1 || v > 0)", True),                 # list_empty
    ("{'key1':1, 'key2':2}.all(k, v, k == 'key2' && v == 2)", False),  # map_key
])
def test_all2(expr, expected):
    assert b(expr) is expected


@pytest.mark.plumbing
def test_all2_error_exhaustive():
    # list_elem_error_exhaustive: v / i with i==0 first element -> divide by zero.
    r = res("[1, 2, 3].all(i, v, v / i != 17)")
    assert r["ok"] is False
    assert "Division" in r["error"] or "divide" in r["error"].lower()


@pytest.mark.plumbing
def test_all2_no_such_overload():
    # list_elem_type_error_exhaustive: 'foo' % 3 -> no_such_overload (string % int).
    r = res("[0, 'foo', 5].all(i, v, v % 3 == i)")
    assert r["ok"] is False


# --------------------------------------------------------------------------
# existsOne(i, v, predicate)  (corpus section "existsOne")
# --------------------------------------------------------------------------
@pytest.mark.plumbing
@pytest.mark.parametrize("expr,expected", [
    ("[].existsOne(i, v, i == 3 || v == 7)", False),         # list_empty
    ("[7].existsOne(i, v, i == 0 && v == 7)", True),         # list_one_true
    ("[8].existsOne(i, v, i == 0 && v == 7)", False),        # list_one_false
    ("[1, 2, 3].existsOne(i, v, i > 2 || v > 3)", False),    # list_none
    ("[5, 7, 8].existsOne(i, v, v % 5 == i)", True),         # list_one
    ("[0, 1, 2, 3, 4].existsOne(i, v, v % 2 == i)", False),  # list_many
    ("['foal', 'foo', 'four'].existsOne(i, v, i > -1 && v.startsWith('fo'))", False),  # list_all
    (
        "{6: 'six', 7: 'seven', 8: 'eight'}.existsOne(k, v, k % 5 == 2 && v == 'seven')",
        True,
    ),  # map_one
])
def test_exists_one2(expr, expected):
    assert b(expr) is expected


@pytest.mark.plumbing
def test_exists_one_alias_exists_one():
    # exists_one is an accepted alias of existsOne for the two-var form.
    assert b("[7].exists_one(i, v, i == 0 && v == 7)") is True


@pytest.mark.plumbing
def test_exists_one2_error():
    # list_no_shortcircuit: existsOne does not short-circuit; v / i with i==0
    # (first element) raises divide by zero.
    r = res("[3, 2, 1, 0].existsOne(i, v, v / i > 1)")
    assert r["ok"] is False
    assert "Division" in r["error"] or "divide" in r["error"].lower()


# --------------------------------------------------------------------------
# transformList(i, v[, filter], transform)  (corpus section "transformList")
# --------------------------------------------------------------------------
@pytest.mark.plumbing
def test_transform_list_empty():
    assert ints(val("[].transformList(i, v, i / v)")) == []


@pytest.mark.plumbing
def test_transform_list_empty_filter():
    assert ints(val("[].transformList(i, v, i > v, i / v)")) == []


@pytest.mark.plumbing
def test_transform_list_one():
    assert ints(val("[3].transformList(i, v, v * v + i)")) == [9]


@pytest.mark.plumbing
def test_transform_list_one_filter():
    assert ints(val("[3].transformList(i, v, i == 0 && v == 3, v * v + i)")) == [9]


@pytest.mark.plumbing
def test_transform_list_many():
    assert ints(val("[2, 4, 6].transformList(i, v, v / 2 + i)")) == [1, 3, 5]


@pytest.mark.plumbing
def test_transform_list_many_filter():
    assert ints(val("[2, 4, 6].transformList(i, v, i != 1 && v != 4, v / 2 + i)")) == [1, 5]


@pytest.mark.plumbing
def test_transform_list_error():
    r = res("[2, 1, 0].transformList(i, v, v / i)")
    assert r["ok"] is False
    assert "Division" in r["error"] or "divide" in r["error"].lower()


@pytest.mark.plumbing
def test_transform_list_error_filter():
    r = res("[2, 1, 0].transformList(i, v, v / i > 0, v)")
    assert r["ok"] is False
    assert "Division" in r["error"] or "divide" in r["error"].lower()


# --------------------------------------------------------------------------
# transformMap(i, v[, filter], transform)  (corpus section "transformMap")
# --------------------------------------------------------------------------
@pytest.mark.plumbing
def test_transform_map_empty():
    assert str_map(val("{}.transformMap(k, v, k + v)")) == {}


@pytest.mark.plumbing
def test_transform_map_empty_filter():
    assert str_map(val("{}.transformMap(k, v, k == 'foo' && v == 'bar', k + v)")) == {}


@pytest.mark.plumbing
def test_transform_map_one():
    assert str_map(val("{'foo': 'bar'}.transformMap(k, v, k + v)")) == {"foo": "foobar"}


@pytest.mark.plumbing
def test_transform_map_one_filter():
    assert str_map(
        val("{'foo': 'bar'}.transformMap(k, v, k == 'foo' && v == 'bar', k + v)")
    ) == {"foo": "foobar"}


@pytest.mark.plumbing
def test_transform_map_many():
    got = str_map(val(
        "{'foo': 'bar', 'baz': 'bux', 'hello': 'world'}.transformMap(k, v, k + v)"
    ))
    assert got == {"foo": "foobar", "baz": "bazbux", "hello": "helloworld"}


@pytest.mark.plumbing
def test_transform_map_many_filter():
    got = str_map(val(
        "{'foo': 'bar', 'baz': 'bux', 'hello': 'world'}"
        ".transformMap(k, v, k != 'baz' && v != 'bux', k + v)"
    ))
    assert got == {"foo": "foobar", "hello": "helloworld"}


@pytest.mark.plumbing
def test_transform_map_error():
    r = res("{'foo': 2, 'bar': 1, 'baz': 0}.transformMap(k, v, 4 / v)")
    assert r["ok"] is False
    assert "Division" in r["error"] or "divide" in r["error"].lower()


@pytest.mark.plumbing
def test_transform_map_error_filter():
    r = res("{'foo': 2, 'bar': 1, 'baz': 0}.transformMap(k, v, k == 'baz' && 4 / v == 0, v)")
    assert r["ok"] is False
    assert "Division" in r["error"] or "divide" in r["error"].lower()


# --------------------------------------------------------------------------
# parse-time guards (cel-go extractIterVars): duplicate/shadow variable names
# --------------------------------------------------------------------------
@pytest.mark.plumbing
@pytest.mark.parametrize("expr", [
    "[1, 2, 3].all(i, i, i > 0)",
    "[1, 2, 3].exists(x, x, x > 0)",
    "{'a': 1}.transformList(k, k, k)",
])
def test_duplicate_iter_var_rejected(expr):
    r = res(expr)
    assert r["ok"] is False
    assert "duplicate variable name" in r["error"]


# --------------------------------------------------------------------------
# binding semantics: index vs key, value lookup
# --------------------------------------------------------------------------
@pytest.mark.plumbing
def test_list_index_is_zero_based():
    # transformList that returns just the index proves 0-based int indices.
    assert ints(val("['a', 'b', 'c'].transformList(i, v, i)")) == [0, 1, 2]


@pytest.mark.plumbing
def test_map_first_var_is_key():
    # all() over a map binds the first var to the KEY, not an index.
    assert b("{'a': 1, 'b': 2}.all(k, v, k == 'a' || k == 'b')") is True


@pytest.mark.plumbing
def test_map_second_var_is_value():
    # the second var is the value associated with the key.
    assert b("{'a': 10, 'b': 20}.all(k, v, (k == 'a' && v == 10) || (k == 'b' && v == 20))") is True


# --------------------------------------------------------------------------
# one-variable macros must NOT regress (arity-2 stays one-var)
# --------------------------------------------------------------------------
@pytest.mark.plumbing
@pytest.mark.parametrize("expr,expected", [
    ("[1, 2, 3].all(v, v > 0)", True),
    ("[1, 2, 3].exists(v, v == 2)", True),
    ("[1, 2, 3].existsOne(v, v == 2)", True),
    ("[1, 2, 3].map(v, v * 2) == [2, 4, 6]", True),
    ("[1, 2, 3, 4].filter(v, v % 2 == 0) == [2, 4]", True),
])
def test_one_var_macros_not_regressed(expr, expected):
    assert b(expr) is expected
