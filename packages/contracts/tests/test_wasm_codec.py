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


# ---------------------------------------------------------------------------
# FINDING A: typed_to_py / py_to_typed support the wasm type / duration /
# timestamp tags (lib.rs value_to_typed/typed_to_value emit + accept them).
#
# The wasm value_to_typed (lib.rs:1248-1297) emits these tags:
#   type      {"t":"type","v":"<cel-go type name>"}     (lib.rs:1295)
#   duration  {"t":"duration","v":"<secs>.<09-nanos>"}  (lib.rs:1283)
#   timestamp {"t":"timestamp","v":"<RFC3339-Z>"}       (lib.rs:1290)
# These reach the host: `type(x)` is NOT fenced under relay_profile so it can
# arrive on the success envelope, and duration/timestamp VALUES (not the fenced
# constructors) can arrive via bindings echoed back out. typed_to_py raised
# ValueError on every one of them before the fix (the unknown-tag fall-through).
# ---------------------------------------------------------------------------
@pytest.mark.plumbing
@pytest.mark.parametrize(
    "name",
    [
        "int",
        "uint",
        "double",
        "bool",
        "string",
        "bytes",
        "list",
        "map",
        "null_type",
        "type",
        "google.protobuf.Timestamp",
        "google.protobuf.Duration",
    ],
)
def test_typed_to_py_type_tag_is_type_type_carrying_celgo_name(name):
    # lib.rs:1295 emits {"t":"type","v":<cel-go TypeName()>}; lib.rs:1401-1407
    # accepts it back. The decode is a celpy TypeType value carrying the cel-go
    # name verbatim (the faithful mirror of Rust's Value::Type(Arc<str>)).
    decoded = typed_to_py({"t": "type", "v": name})
    assert isinstance(decoded, ct.TypeType)
    assert decoded.__name__ == name


@pytest.mark.plumbing
@pytest.mark.parametrize(
    "name",
    [
        "int",
        "type",
        "google.protobuf.Timestamp",
        "google.protobuf.Duration",
    ],
)
def test_round_trip_type_tag_is_byte_identical(name):
    # typed_to_py -> py_to_typed reproduces the EXACT {"t":"type","v":<name>}.
    typed = {"t": "type", "v": name}
    assert py_to_typed(typed_to_py(typed)) == typed


@pytest.mark.plumbing
def test_typed_to_py_duration_tag_is_duration_type():
    # lib.rs:1283 emits {"t":"duration","v":"<secs>.<09-nanos>"}; the host
    # decodes it to a celpy DurationType (a datetime.timedelta subclass).
    decoded = typed_to_py({"t": "duration", "v": "5.000000000"})
    assert isinstance(decoded, ct.DurationType)
    assert decoded.total_seconds() == 5.0


@pytest.mark.plumbing
@pytest.mark.parametrize(
    "wire,total_seconds",
    [
        ("5.000000000", 5.0),
        ("-5.000000000", -5.0),
        ("1.500000000", 1.5),
        ("-1.500000000", -1.5),
        ("0.000000000", 0.0),
        ("0.250000000", 0.25),
    ],
)
def test_round_trip_duration_tag_microsecond_domain(wire, total_seconds):
    # Round-trip within the celtypes-representable (microsecond) domain: decode
    # then re-encode reproduces the wasm canonical wire form byte-for-byte. The
    # encode mirrors lib.rs:1279-1283 exactly (secs trunc toward zero, then
    # f"{secs}.{abs(rem_nanos):09}", sign carried on secs only).
    decoded = typed_to_py({"t": "duration", "v": wire})
    assert isinstance(decoded, ct.DurationType)
    assert decoded.total_seconds() == total_seconds
    assert py_to_typed(decoded) == {"t": "duration", "v": wire}


@pytest.mark.plumbing
def test_py_to_typed_subsecond_negative_duration_agrees_with_wasm_signloss():
    # The wasm serializer (lib.rs:1283 f"{secs}.{nanos.abs():09}") LOSES the
    # sign of a sub-second negative duration (secs == 0): the empirically
    # confirmed wasm out form for -0.25s is "0.250000000". The codec MUST AGREE
    # with the wasm (byte-parity keystone), so py_to_typed reproduces the same
    # sign-loss. This is a documented wasm characteristic, NOT a codec defect;
    # the codec cannot diverge from the wasm it speaks to.
    neg_quarter = ct.DurationType(seconds=0, nanos=-250_000_000)
    assert neg_quarter.total_seconds() == -0.25
    assert py_to_typed(neg_quarter) == {"t": "duration", "v": "0.250000000"}


@pytest.mark.plumbing
def test_typed_to_py_timestamp_tag_is_timestamp_type():
    # lib.rs:1290 emits {"t":"timestamp","v":"<RFC3339-Z>"}; the host decodes it
    # to a celpy TimestampType (a datetime.datetime subclass).
    decoded = typed_to_py({"t": "timestamp", "v": "2024-01-01T00:00:00Z"})
    assert isinstance(decoded, ct.TimestampType)


@pytest.mark.plumbing
@pytest.mark.parametrize(
    "wire",
    [
        "2024-01-01T00:00:00Z",
        "2024-01-01T00:00:00.500Z",
        "2024-06-15T13:45:30.123456Z",
        "2024-01-01T00:00:00.120Z",
        "2024-01-01T00:00:00.000001Z",
    ],
)
def test_round_trip_timestamp_tag_microsecond_domain(wire):
    # Round-trip within the celtypes-representable (microsecond) domain: decode
    # then re-encode reproduces the wasm canonical RFC3339-Z form byte-for-byte.
    # The encode mirrors lib.rs rfc3339_utc_z (chrono AutoSi: sub-second only
    # when nonzero, grouped in multiples of 3 digits, 'Z' suffix).
    decoded = typed_to_py({"t": "timestamp", "v": wire})
    assert isinstance(decoded, ct.TimestampType)
    assert py_to_typed(decoded) == {"t": "timestamp", "v": wire}


@pytest.mark.plumbing
def test_py_to_typed_timestamp_normalizes_offset_to_utc_z():
    # A non-UTC-offset timestamp value re-encodes to the canonical UTC 'Z' form,
    # mirroring lib.rs rfc3339_utc_z (with_timezone(Utc)). +05:30 at 05:30 local
    # is 00:00 UTC -- the same normalisation the wasm performs.
    decoded = typed_to_py({"t": "timestamp", "v": "2024-01-01T05:30:00+05:30"})
    assert py_to_typed(decoded) == {"t": "timestamp", "v": "2024-01-01T00:00:00Z"}


# ---------------------------------------------------------------------------
# FINDING B: typed_to_py enforces the wire JSON type of `v` (no lenient coerce).
# The Rust request decoder (lib.rs:1352-1399) STRICTLY validates v's JSON type:
# bool needs as_bool, string/int/uint/bytes need as_str. The host must mirror
# this strictness or a malformed wire value is silently mis-decoded (e.g.
# {"t":"bool","v":"false"} -> BoolType(True) because any non-empty string is
# truthy). VALID inputs are unchanged (the parity tests must stay byte-identical).
# ---------------------------------------------------------------------------
@pytest.mark.plumbing
@pytest.mark.parametrize("bad_v", ["false", "true", "", "0", 1, 0, [], {}, None])
def test_typed_to_py_bool_requires_json_bool(bad_v):
    # lib.rs:1392-1397 requires v.as_bool(); a non-bool v is a hard error.
    with pytest.raises(ValueError):
        typed_to_py({"t": "bool", "v": bad_v})


@pytest.mark.plumbing
def test_typed_to_py_bool_accepts_real_json_bool():
    # The VALID wire form is a JSON boolean -- unchanged by the strictness fix.
    assert bool(typed_to_py({"t": "bool", "v": True})) is True
    assert bool(typed_to_py({"t": "bool", "v": False})) is False


@pytest.mark.plumbing
@pytest.mark.parametrize("bad_v", [5, 5.0, True, False, None, [], {}])
def test_typed_to_py_int_requires_string_v(bad_v):
    # lib.rs:1353-1359 requires v.as_str() then i64 parse; a JSON number v is a
    # hard error (the wire form is the decimal string, never a JSON number).
    with pytest.raises(ValueError):
        typed_to_py({"t": "int", "v": bad_v})


@pytest.mark.plumbing
@pytest.mark.parametrize("bad_v", [7, 7.0, True, None, [], {}])
def test_typed_to_py_uint_requires_string_v(bad_v):
    # lib.rs:1361-1367 requires v.as_str() then u64 parse.
    with pytest.raises(ValueError):
        typed_to_py({"t": "uint", "v": bad_v})


@pytest.mark.plumbing
@pytest.mark.parametrize("bad_v", [5, 5.0, True, None, [], {}])
def test_typed_to_py_string_requires_str_v(bad_v):
    # lib.rs:1385-1390 requires v.as_str(); a JSON number v is a hard error
    # (the lenient code stringified it: str(5) -> "5").
    with pytest.raises(ValueError):
        typed_to_py({"t": "string", "v": bad_v})


@pytest.mark.plumbing
@pytest.mark.parametrize("bad_v", [5, 5.0, True, None, [], {}])
def test_typed_to_py_bytes_requires_str_v(bad_v):
    # lib.rs:1408-1414 requires v.as_str() then hex-decode.
    with pytest.raises(ValueError):
        typed_to_py({"t": "bytes", "v": bad_v})


@pytest.mark.plumbing
def test_typed_to_py_scalars_unchanged_for_valid_wire():
    # VALID inputs MUST be byte-identical after the strictness fix (the parity
    # tests depend on this -- the fix only rejects MALFORMED v, never valid v).
    assert int(typed_to_py({"t": "int", "v": "3"})) == 3
    assert int(typed_to_py({"t": "uint", "v": "7"})) == 7
    assert str(typed_to_py({"t": "string", "v": "hi"})) == "hi"
    assert bytes(typed_to_py({"t": "bytes", "v": "deadbeef"})) == b"\xde\xad\xbe\xef"


# ---------------------------------------------------------------------------
# FINDING C: py_to_typed enforces the i64 / u64 WIRE range. The wasm wire form
# is i64 [-2^63, 2^63-1] for int and u64 [0, 2^64-1] for uint (lib.rs:1358 /
# 1366 parse). An out-of-range Python int produces JSON the wasm CANNOT
# deserialize, and _key_sort_string (wasm_codec.py:187) assumes in-range. This
# is the WIRE bound, DISTINCT from the host _check_finite 2^53 result bound.
# ---------------------------------------------------------------------------
_I64_MIN = -(2**63)
_I64_MAX = 2**63 - 1
_U64_MAX = 2**64 - 1


@pytest.mark.plumbing
def test_py_to_typed_int_accepts_i64_boundaries():
    # The i64 endpoints are IN range and serialise as the decimal string.
    assert py_to_typed(_I64_MIN) == {"t": "int", "v": str(_I64_MIN)}
    assert py_to_typed(_I64_MAX) == {"t": "int", "v": str(_I64_MAX)}
    assert py_to_typed(ct.IntType(_I64_MAX)) == {"t": "int", "v": str(_I64_MAX)}


@pytest.mark.plumbing
@pytest.mark.parametrize("oob", [_I64_MAX + 1, _I64_MIN - 1, 2**70, -(2**70)])
def test_py_to_typed_int_rejects_out_of_i64_range(oob):
    # A plain Python int outside [-2^63, 2^63-1] would serialise to JSON the
    # wasm s.parse::<i64>() (lib.rs:1358) rejects -- raise a clear ValueError.
    with pytest.raises(ValueError):
        py_to_typed(oob)


@pytest.mark.plumbing
def test_py_to_typed_uint_accepts_u64_boundaries():
    assert py_to_typed(ct.UintType(0)) == {"t": "uint", "v": "0"}
    assert py_to_typed(ct.UintType(_U64_MAX)) == {"t": "uint", "v": str(_U64_MAX)}


@pytest.mark.plumbing
def test_py_to_typed_uint_rejects_out_of_u64_range():
    # UintType cannot hold > u64 (it clamps), so drive a class that yields an
    # out-of-range int through the uint branch via a UintType subclass-free
    # path: build the value with object.__new__ to bypass the clamp, then encode.
    class _OOBUint(ct.UintType):
        def __new__(cls, value):
            # int.__new__ stores the arbitrary magnitude without celtypes clamp.
            return int.__new__(cls, value)

    too_big = _OOBUint(_U64_MAX + 1)
    assert int(too_big) == _U64_MAX + 1
    with pytest.raises(ValueError):
        py_to_typed(too_big)


@pytest.mark.plumbing
def test_py_to_typed_int_range_check_applies_to_map_keys():
    # Map keys go through the same validated encode path (_key_sort_string +
    # py_to_typed), so an out-of-i64-range int KEY is rejected too.
    bad_map = {_I64_MAX + 1: 1}
    with pytest.raises(ValueError):
        py_to_typed(bad_map)
