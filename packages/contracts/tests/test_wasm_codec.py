"""tier-1 plumbing tests for the wasm typed-canonical codec (WS-A, VAL-CWC-P1HOST-001).

``packages/contracts/src/relay_contracts/wasm_codec.py`` is the canonical
Python implementation of the wasm reactor's typed-canonical value form -- the
cross-host byte-parity contract (CLAUDE.md keystone invariant #16). It MUST be
byte-faithful to the Rust source of truth in
``packages/cel-wasm/crate/src/lib.rs`` ``value_to_typed`` / ``typed_to_value``
/ ``key_to_typed`` / ``key_sort_string`` (verified file:line in the worker
exploration log). The wire form (lib.rs:22-31):

    int       {"t":"int","v":"<decimal i64 as string>"}    (lib.rs:1137)
    uint      {"t":"uint","v":"<decimal u64 as string>"}   (lib.rs:1138)
    double    {"t":"double","v":"<canonical-g | inf|-inf|nan>"} (lib.rs:1139)
    string    {"t":"string","v":"<utf8>"}                  (lib.rs:1140)
    bool      {"t":"bool","v":true|false}                  (lib.rs:1141, JSON bool)
    null      {"t":"null"}                                 (lib.rs:1142, NO "v")
    bytes     {"t":"bytes","v":"<lowercase hex>"}          (lib.rs:1143-1145)
    list      {"t":"list","v":[...]}  order preserved      (lib.rs:1147-1150)
    map       {"t":"map","v":[[k,v],...]} sorted by key_sort_string (lib.rs:1151-1162)

celtypes quirks (empirically confirmed against cel-python):
  - ``BoolType`` is an ``int`` subclass, NOT a ``bool`` subclass, so a CEL
    boolean MUST be classified as bool BEFORE int or it serialises as
    ``{"t":"int"}`` -- a P0 byte divergence.
  - the cel-python unsigned class is ``celpy.celtypes.UintType`` (NOT
    ``UIntType``); ``UintType``/``IntType``/``BoolType`` are independent ``int``
    subclasses (no inheritance between them).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
from typing import Any, cast

import celpy.celtypes as ct
import pytest
from relay_contracts.wasm_codec import py_to_typed, typed_to_py


# ---------------------------------------------------------------------------
# bool-before-int (the keystone P0 hazard)
# ---------------------------------------------------------------------------
@pytest.mark.plumbing
def test_py_to_typed_plain_bool_is_bool_not_int():
    # A Python bool MUST serialise as {"t":"bool","v":true}, never {"t":"int"}.
    assert py_to_typed(True) == {"t": "bool", "v": True}
    assert py_to_typed(False) == {"t": "bool", "v": False}
    # ASCII-faithful: the JSON literal for the bool branch is `true`/`false`.
    assert json.dumps(py_to_typed(True), separators=(",", ":")) == '{"t":"bool","v":true}'


@pytest.mark.plumbing
def test_py_to_typed_celtypes_bool_is_bool_not_int():
    # celpy BoolType is an int subclass but NOT a bool subclass -- it MUST still
    # be classified as bool before int.
    assert isinstance(ct.BoolType(True), int)
    assert not isinstance(ct.BoolType(True), bool)
    assert py_to_typed(ct.BoolType(True)) == {"t": "bool", "v": True}
    assert py_to_typed(ct.BoolType(False)) == {"t": "bool", "v": False}


# ---------------------------------------------------------------------------
# typed_to_py returns the EXACT cel-python celtypes classes
# ---------------------------------------------------------------------------
@pytest.mark.plumbing
def test_typed_to_py_int_is_int_type():
    v = typed_to_py({"t": "int", "v": "3"})
    assert isinstance(v, ct.IntType)
    assert int(v) == 3


@pytest.mark.plumbing
def test_typed_to_py_uint_is_uint_type():
    v = typed_to_py({"t": "uint", "v": "7"})
    assert isinstance(v, ct.UintType)
    assert int(v) == 7


@pytest.mark.plumbing
def test_typed_to_py_double_is_double_type():
    v = typed_to_py({"t": "double", "v": "1.5"})
    assert isinstance(v, ct.DoubleType)
    assert float(v) == 1.5


@pytest.mark.plumbing
def test_typed_to_py_string_is_string_type():
    v = typed_to_py({"t": "string", "v": "hi"})
    assert isinstance(v, ct.StringType)
    assert str(v) == "hi"


@pytest.mark.plumbing
def test_typed_to_py_bool_is_bool_type():
    v = typed_to_py({"t": "bool", "v": True})
    assert isinstance(v, ct.BoolType)
    assert bool(v) is True


@pytest.mark.plumbing
def test_typed_to_py_bytes_is_bytes_type():
    v = typed_to_py({"t": "bytes", "v": "deadbeef"})
    assert isinstance(v, ct.BytesType)
    assert bytes(v) == b"\xde\xad\xbe\xef"


@pytest.mark.plumbing
def test_typed_to_py_list_is_list_type():
    v: Any = typed_to_py({"t": "list", "v": [{"t": "int", "v": "1"}, {"t": "int", "v": "2"}]})
    assert isinstance(v, ct.ListType)
    assert [int(cast(Any, x)) for x in v] == [1, 2]
    assert all(isinstance(x, ct.IntType) for x in v)


@pytest.mark.plumbing
def test_typed_to_py_map_is_map_type():
    v = typed_to_py(
        {
            "t": "map",
            "v": [
                [{"t": "string", "v": "a"}, {"t": "int", "v": "1"}],
                [{"t": "string", "v": "z"}, {"t": "int", "v": "2"}],
            ],
        }
    )
    assert isinstance(v, ct.MapType)
    items: Any = v
    assert {str(k): int(val) for k, val in items.items()} == {"a": 1, "z": 2}


# ---------------------------------------------------------------------------
# wire-form exactness against the Rust source of truth
# ---------------------------------------------------------------------------
@pytest.mark.plumbing
def test_int_uint_are_string_encoded():
    # lib.rs:1137-1138: i.to_string() / u.to_string() -- string-encoded v.
    assert py_to_typed(ct.IntType(3)) == {"t": "int", "v": "3"}
    assert py_to_typed(ct.IntType(-5)) == {"t": "int", "v": "-5"}
    assert py_to_typed(ct.UintType(7)) == {"t": "uint", "v": "7"}


@pytest.mark.plumbing
def test_null_has_no_v_key():
    # lib.rs:1142: json!({"t":"null"}) -- there is no "v" key on null.
    assert py_to_typed(None) == {"t": "null"}
    assert "v" not in py_to_typed(None)


@pytest.mark.plumbing
def test_bytes_lowercase_hex():
    # lib.rs:1143-1145: format!("{byte:02x}") -- lowercase, zero-padded hex.
    assert py_to_typed(ct.BytesType(b"\x00\xff\xab")) == {"t": "bytes", "v": "00ffab"}


@pytest.mark.plumbing
def test_double_canonical_forms():
    # lib.rs:1004-1009 + 1002: nan/inf/-inf sentinels; finite stays decimal.
    assert py_to_typed(ct.DoubleType(1.5)) == {"t": "double", "v": "1.5"}
    assert py_to_typed(ct.DoubleType(float("inf"))) == {"t": "double", "v": "inf"}
    assert py_to_typed(ct.DoubleType(float("-inf"))) == {"t": "double", "v": "-inf"}
    nan = py_to_typed(ct.DoubleType(float("nan")))
    assert nan == {"t": "double", "v": "nan"}


@pytest.mark.plumbing
def test_map_key_ordering_matches_wasm_sort():
    # lib.rs:1126-1133 key_sort_string puts bool(0) < int(1) < uint(2) < string(3),
    # ints offset by 2^63 zero-padded to 20, strings by raw codepoint order.
    # String keys sort lexicographically by codepoint.
    m = ct.MapType()
    m[ct.StringType("z")] = ct.IntType(1)
    m[ct.StringType("a")] = ct.IntType(2)
    m[ct.StringType("m")] = ct.IntType(3)
    out = py_to_typed(m)
    assert out["t"] == "map"
    keys = [k["v"] for k, _ in out["v"]]
    assert keys == ["a", "m", "z"]


@pytest.mark.plumbing
def test_map_mixed_key_types_ordering():
    # Cross-type ordering: bool < int < uint < string (lib.rs:1126-1133).
    m = ct.MapType()
    m[ct.StringType("s")] = ct.IntType(0)
    m[ct.IntType(5)] = ct.IntType(1)
    m[ct.UintType(2)] = ct.IntType(2)
    m[ct.BoolType(True)] = ct.IntType(3)
    out = py_to_typed(m)
    tags = [k["t"] for k, _ in out["v"]]
    assert tags == ["bool", "int", "uint", "string"]


@pytest.mark.plumbing
def test_negative_int_key_ordering():
    # int sort uses (i as i128 + 2^63): negative ints sort before positive.
    m = ct.MapType()
    m[ct.IntType(3)] = ct.IntType(0)
    m[ct.IntType(-3)] = ct.IntType(1)
    m[ct.IntType(0)] = ct.IntType(2)
    out = py_to_typed(m)
    int_vals = [k["v"] for k, _ in out["v"]]
    assert int_vals == ["-3", "0", "3"]


# ---------------------------------------------------------------------------
# round-trip identity over EVERY value class (the acceptance bar)
# ---------------------------------------------------------------------------
@pytest.mark.plumbing
@pytest.mark.parametrize(
    "value,cls",
    [
        (ct.IntType(42), ct.IntType),
        (ct.IntType(-9007199254740991), ct.IntType),
        (ct.UintType(123), ct.UintType),
        (ct.DoubleType(3.25), ct.DoubleType),
        (ct.StringType("hello world"), ct.StringType),
        (ct.BoolType(True), ct.BoolType),
        (ct.BoolType(False), ct.BoolType),
        (ct.BytesType(b"\x01\x02\xfe"), ct.BytesType),
    ],
)
def test_round_trip_scalar_value_classes(value, cls):
    # py_to_typed -> typed_to_py must reproduce the EXACT celtypes class + value.
    decoded = typed_to_py(py_to_typed(value))
    assert isinstance(decoded, cls)
    assert decoded == value


@pytest.mark.plumbing
def test_round_trip_null():
    # null round-trips to Python None (the wasm Value::Null canonical form).
    assert py_to_typed(None) == {"t": "null"}
    assert typed_to_py({"t": "null"}) is None


@pytest.mark.plumbing
def test_round_trip_list():
    value = ct.ListType([ct.IntType(1), ct.StringType("x"), ct.BoolType(True), None])
    decoded: Any = typed_to_py(py_to_typed(value))
    assert isinstance(decoded, ct.ListType)
    assert isinstance(decoded[0], ct.IntType)
    assert isinstance(decoded[1], ct.StringType)
    assert isinstance(decoded[2], ct.BoolType)
    assert decoded[3] is None
    assert [
        (int(cast(Any, decoded[0]))),
        str(decoded[1]),
        bool(decoded[2]),
        decoded[3],
    ] == [1, "x", True, None]


@pytest.mark.plumbing
def test_round_trip_map():
    m = ct.MapType()
    m[ct.StringType("b")] = ct.IntType(2)
    m[ct.StringType("a")] = ct.DoubleType(1.5)
    decoded: Any = typed_to_py(py_to_typed(m))
    assert isinstance(decoded, ct.MapType)
    assert {str(k): float(v) if isinstance(v, ct.DoubleType) else int(cast(Any, v))
            for k, v in decoded.items()} == {"a": 1.5, "b": 2}
    assert all(isinstance(k, ct.StringType) for k in decoded)


@pytest.mark.plumbing
def test_round_trip_nested_list_map():
    # nested list/map round-trips through the recursive codec.
    inner = ct.MapType()
    inner[ct.StringType("k")] = ct.ListType([ct.IntType(7), ct.UintType(8)])
    value = ct.ListType([inner, ct.StringType("tail")])
    decoded: Any = typed_to_py(py_to_typed(value))
    assert isinstance(decoded, ct.ListType)
    assert isinstance(decoded[0], ct.MapType)
    inner_list: Any = cast(Any, decoded[0])[ct.StringType("k")]
    assert isinstance(inner_list, ct.ListType)
    assert isinstance(inner_list[0], ct.IntType)
    assert isinstance(inner_list[1], ct.UintType)
    assert int(cast(Any, inner_list[0])) == 7
    assert int(cast(Any, inner_list[1])) == 8
    assert str(decoded[1]) == "tail"


@pytest.mark.plumbing
def test_round_trip_double_special_values():
    for f in (float("inf"), float("-inf")):
        decoded = typed_to_py(py_to_typed(ct.DoubleType(f)))
        assert isinstance(decoded, ct.DoubleType)
        assert float(decoded) == f
    nan_decoded = typed_to_py(py_to_typed(ct.DoubleType(float("nan"))))
    assert isinstance(nan_decoded, ct.DoubleType)
    assert float(nan_decoded) != float(nan_decoded)  # NaN != NaN


# ---------------------------------------------------------------------------
# error handling
# ---------------------------------------------------------------------------
@pytest.mark.plumbing
def test_py_to_typed_rejects_unsupported_type():
    class Weird:
        pass

    with pytest.raises((TypeError, ValueError)):
        py_to_typed(Weird())


@pytest.mark.plumbing
def test_typed_to_py_rejects_unknown_tag():
    with pytest.raises((TypeError, ValueError, KeyError)):
        typed_to_py({"t": "frobnicate", "v": "x"})
