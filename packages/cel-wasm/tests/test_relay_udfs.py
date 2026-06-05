"""Relay contract-DSL UDFs in the wasm (WS4 cutover step 1).

relay.coverage / relay.tool_arg / relay.schema_match are ported from
``packages/contracts/src/relay_contracts/udfs/*.py`` into the vendored fork's
wrapper (``crate/src/lib.rs``) as native Rust, registered under the dotted CEL
name and reached via the fork's qualified-name function resolution. These tests
drive each UDF THROUGH the CEL evaluator (``relay.coverage(trace, step)`` etc.)
against the SAME wasm both hosts load, so the recorded behavior IS the
cross-host byte-parity contract.

They encode the INTENDED, documented semantics (pure, deterministic, TOTAL --
never error, shape mismatch -> false/null) plus VAL-PARITY-002 (an integral CEL
double is an "integer"). Several cases assert behavior where the wasm is
CORRECT and cel-python driven through CEL is BROKEN (it raises KeyError on a
missing map key, and celpy BoolType/DoubleType break the type screens): the
single wasm engine is the source of truth the cutover standardizes on.

tier-1 plumbing (runs against the real wasm).
"""
import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "python"))

from relay_cel_wasm import RelayCel  # noqa: E402

C = RelayCel()


def val(expr, bindings=None):
    r = C.eval(expr, bindings) if bindings else C.eval(expr)
    assert r["ok"], f"{expr} unexpectedly rejected: {r}"
    return r["value"]


def b(expr, bindings=None):
    v = val(expr, bindings)
    assert v["t"] == "bool", f"{expr} -> {v}"
    return v["v"]


# ---------------------------------------------------------------------------
# relay.coverage(trace, step_name) -> bool
# ---------------------------------------------------------------------------
@pytest.mark.plumbing
@pytest.mark.parametrize("expr,expected", [
    # match / no-match / empty
    ('relay.coverage({"steps": [{"name": "a"}, {"name": "b"}]}, "b")', True),
    ('relay.coverage({"steps": [{"name": "a"}]}, "z")', False),
    ('relay.coverage({"steps": []}, "a")', False),
    # non-map step entry is skipped (not iterated as characters)
    ('relay.coverage({"steps": [1, {"name": "a"}]}, "a")', True),
    # step entry missing a "name" key is skipped -- TOTAL (cel-python raises here)
    ('relay.coverage({"steps": [{"other": 1}, {"name": "a"}]}, "a")', True),
    # trace missing "steps" -> false -- TOTAL (cel-python raises here)
    ('relay.coverage({"other": 1}, "a")', False),
    # shape mismatches -> false
    ('relay.coverage(123, "a")', False),
    ('relay.coverage({"steps": [{"name": "a"}]}, 1)', False),
    ('relay.coverage({"steps": "a"}, "a")', False),
    # entry "name" present but non-string -> not a match
    ('relay.coverage({"steps": [{"name": 7}]}, "7")', False),
    # exact codepoint match, no case fold
    ('relay.coverage({"steps": [{"name": "A"}]}, "a")', False),
    # unicode name (ASCII-safe source: CEL decodes the \\u escape to U+00E9)
    ('relay.coverage({"steps": [{"name": "caf\\u00e9"}]}, "caf\\u00e9")', True),
])
def test_coverage(expr, expected):
    assert b(expr) is expected


# ---------------------------------------------------------------------------
# relay.tool_arg(call, key) -> any
# ---------------------------------------------------------------------------
@pytest.mark.plumbing
def test_tool_arg_returns_string():
    assert val('relay.tool_arg({"args": {"k": "v"}}, "k")') == {"t": "string", "v": "v"}


@pytest.mark.plumbing
def test_tool_arg_returns_int():
    assert val('relay.tool_arg({"args": {"k": 7}}, "k")') == {"t": "int", "v": "7"}


@pytest.mark.plumbing
def test_tool_arg_returns_double():
    assert val('relay.tool_arg({"args": {"k": 1.5}}, "k")') == {"t": "double", "v": "1.5"}


@pytest.mark.plumbing
def test_tool_arg_returns_bool():
    assert val('relay.tool_arg({"args": {"k": true}}, "k")') == {"t": "bool", "v": True}


@pytest.mark.plumbing
def test_tool_arg_returns_nested_map_sorted():
    # A returned map must hit the canonical SORTED-key serializer (parity hazard).
    v = val('relay.tool_arg({"args": {"k": {"z": 2, "a": 1}}}, "k")')
    assert v["t"] == "map"
    keys = [k["v"] for k, _ in v["v"]]
    assert keys == ["a", "z"], v  # sorted, deterministic


@pytest.mark.plumbing
@pytest.mark.parametrize("expr", [
    'relay.tool_arg({"args": {"k": null}}, "k")',   # present-null -> null
    'relay.tool_arg({"args": {"k": 1}}, "j")',      # missing key -> null
    'relay.tool_arg(123, "k")',                       # call not a map -> null
    'relay.tool_arg({"args": {"k": 1}}, 5)',         # key not a string -> null
    'relay.tool_arg({"other": 1}, "k")',             # missing args -> null (TOTAL; celpy raises)
    'relay.tool_arg({"args": "x"}, "k")',            # args not a map -> null
])
def test_tool_arg_null(expr):
    assert val(expr) == {"t": "null"}


# ---------------------------------------------------------------------------
# relay.schema_match(payload, schema) -> bool
# ---------------------------------------------------------------------------
@pytest.mark.plumbing
@pytest.mark.parametrize("expr,expected", [
    # empty schema matches anything
    ('relay.schema_match("x", {})', True),
    ('relay.schema_match({"a": 1}, {})', True),
    # VAL-PARITY-002: integral CEL double IS an integer; non-integral is not
    ('relay.schema_match(1.0, {"type": "integer"})', True),
    ('relay.schema_match(1, {"type": "integer"})', True),
    ('relay.schema_match(1.5, {"type": "integer"})', False),
    # booleans are NOT integers / numbers (celpy BoolType gets this WRONG)
    ('relay.schema_match(true, {"type": "integer"})', False),
    ('relay.schema_match(true, {"type": "number"})', False),
    # number = finite int/double
    ('relay.schema_match(1.0, {"type": "number"})', True),
    ('relay.schema_match(1, {"type": "number"})', True),
    # scalar types
    ('relay.schema_match("s", {"type": "string"})', True),
    ('relay.schema_match(7, {"type": "string"})', False),
    ('relay.schema_match(null, {"type": "null"})', True),
    ('relay.schema_match(true, {"type": "boolean"})', True),
    ('relay.schema_match(1, {"type": "boolean"})', False),
    # array + items
    ('relay.schema_match([1, 2], {"type": "array", "items": {"type": "integer"}})', True),
    ('relay.schema_match([1, 1.5], {"type": "array", "items": {"type": "integer"}})', False),
    ('relay.schema_match("s", {"type": "array"})', False),  # string is not an array
    # object required (TOTAL: cel-python raises on schema.get("type"))
    ('relay.schema_match({"a": 1}, {"type": "object", "required": ["a"]})', True),
    ('relay.schema_match({"b": 1}, {"type": "object", "required": ["a"]})', False),
    # required only checks PRESENCE; a present null satisfies it
    ('relay.schema_match({"a": null}, {"required": ["a"]})', True),
    # required with no type, present (TOTAL; celpy raises)
    ('relay.schema_match({"a": 1}, {"required": ["a"]})', True),
    # object properties: only present props validated.
    # noqa E501 below: the first tuple element is a CEL test-vector string that
    # exceeds 100 cols on its own; wrapping it would split/alter the literal.
    ('relay.schema_match({"a": 1}, {"type": "object", "properties": {"a": {"type": "integer"}}})', True),  # noqa: E501
    ('relay.schema_match({"a": "x"}, {"type": "object", "properties": {"a": {"type": "integer"}}})', False),  # noqa: E501
    ('relay.schema_match({"b": 1}, {"type": "object", "properties": {"a": {"type": "integer"}}})', True),  # noqa: E501  # 'a' absent -> not validated
    # unknown type name -> false
    ('relay.schema_match("s", {"type": "frobnicate"})', False),
    # non-string type field -> false
    ('relay.schema_match("s", {"type": 7})', False),
    # null type field is skipped (cel-python .get returns None for present null)
    ('relay.schema_match("s", {"type": null})', True),
    # non-map schema -> false
    ('relay.schema_match("s", 123)', False),
    ('relay.schema_match(1, "x")', False),
])
def test_schema_match(expr, expected):
    assert b(expr) is expected


@pytest.mark.plumbing
def test_schema_match_number_rejects_nan_inf():
    # NaN / Inf are not finite -> not "number". Supplied as typed bindings.
    nan = {"t": "double", "v": "nan"}
    inf = {"t": "double", "v": "inf"}
    assert b('relay.schema_match(x, {"type": "number"})', {"x": nan}) is False
    assert b('relay.schema_match(x, {"type": "number"})', {"x": inf}) is False
    assert b('relay.schema_match(x, {"type": "integer"})', {"x": nan}) is False


def _schema(n):
    s = '{"type": "integer"}'
    for _ in range(n):
        s = '{"type": "object", "properties": {"a": ' + s + '}}'
    return s


def _payload(n, leaf="1"):
    p = leaf
    for _ in range(n):
        p = '{"a": ' + p + "}"
    return p


@pytest.mark.plumbing
def test_schema_match_nested_recursion():
    # Recursive descent validates nested object schemas (depth+1 per level), well
    # within the input parsers' nesting limits.
    assert b(f"relay.schema_match({_payload(8)}, {_schema(8)})") is True
    # A leaf type mismatch deep in the tree fails closed (string leaf vs integer).
    mismatch = _payload(8, leaf='"x"')
    assert b(f"relay.schema_match({mismatch}, {_schema(8)})") is False


@pytest.mark.plumbing
def test_schema_match_pathological_depth_fails_closed():
    # Input nested far beyond any practical schema must be REJECTED with a clean
    # Relay error (the CEL parser / serde request limit bounds nesting well below
    # the in-UDF MAX_DEPTH=64), never a panic/crash. MAX_DEPTH=64 is faithful
    # defense-in-depth from schema_match.py for any path that bypasses that limit.
    r = C.eval(f"relay.schema_match(1, {_schema(150)})")
    assert r["ok"] is False, r
    assert r["code"].startswith("RELAY-CEL-"), r
