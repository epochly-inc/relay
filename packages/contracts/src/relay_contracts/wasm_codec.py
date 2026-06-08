"""Codec between cel-python ``celtypes`` values and the wasm typed-canonical form.

This module is the canonical Python implementation of the wasm CEL reactor's
typed-canonical value wire form -- the cross-host byte-parity contract
(CLAUDE.md keystone invariant #16, a P0). It is byte-faithful to the Rust
source of truth in ``packages/cel-wasm/crate/src/lib.rs``
(``value_to_typed`` / ``typed_to_value`` / ``key_to_typed`` /
``key_sort_string`` / ``canonical_double``). Both the Python loader
(``packages/cel-wasm/python/relay_cel_wasm.py``) request-binding side and its
response-parsing side speak this form; this codec is the single Python
implementation the host evaluation path uses to talk to that loader.

Wire form (lib.rs:22-31, verified file:line):

    int       {"t":"int","v":"<decimal i64 as string>"}      (lib.rs:1137)
    uint      {"t":"uint","v":"<decimal u64 as string>"}     (lib.rs:1138)
    double    {"t":"double","v":"<canonical-g | inf|-inf|nan>"} (lib.rs:1139, 1002-1090)
    string    {"t":"string","v":"<utf8>"}                    (lib.rs:1140)
    bool      {"t":"bool","v":true|false}  (JSON boolean)    (lib.rs:1141)
    null      {"t":"null"}  (NO "v" key)                     (lib.rs:1142)
    bytes     {"t":"bytes","v":"<lowercase hex>"}            (lib.rs:1143-1145)
    list      {"t":"list","v":[...]}  order preserved        (lib.rs:1147-1150)
    map       {"t":"map","v":[[k,v],...]} sorted by key_sort_string (lib.rs:1151-1162)
    type      {"t":"type","v":"<cel-go type name>"}          (lib.rs:1295)
    duration  {"t":"duration","v":"<secs>.<09-nanos>"}       (lib.rs:1283)
    timestamp {"t":"timestamp","v":"<RFC3339-Z>"}            (lib.rs:1290)

The ``type`` / ``duration`` / ``timestamp`` tags reach the host even under the
Relay profile: ``type(x)`` is NOT a fenced constructor (it emits a type value),
and ``duration`` / ``timestamp`` VALUES (distinct from the fenced ``duration(...)``
/ ``timestamp(...)`` constructors) arrive via bindings echoed back out. The
codec decodes them to the celpy ``TypeType`` / ``DurationType`` / ``TimestampType``
and re-encodes them byte-faithfully (a ``TypeType`` carries the cel-go name; a
``DurationType`` / ``TimestampType`` is microsecond-resolution, so sub-microsecond
nanos are not representable -- the byte-faithful round-trip domain is the
microsecond domain). The ``v`` field's JSON type is enforced STRICTLY on decode,
mirroring the Rust request decoder (lib.rs:1352-1465): bool requires a JSON
boolean, the string-encoded scalars require a JSON string, and the int / uint
ENCODE side enforces the i64 / u64 wire range (lib.rs:1358 / 1366).

Critical celtypes quirks (empirically confirmed):
  - ``BoolType`` is an ``int`` subclass but NOT a ``bool`` subclass, so a CEL
    boolean MUST be classified BEFORE int or it serialises as ``{"t":"int"}``
    -- a P0 cross-host byte divergence. ``py_to_typed`` therefore tests
    bool-ness FIRST (both Python ``bool`` and celtypes ``BoolType``).
  - the cel-python unsigned class is ``celpy.celtypes.UintType`` (NOT
    ``UIntType``); ``BoolType`` / ``IntType`` / ``UintType`` are three
    INDEPENDENT ``int`` subclasses (no inheritance among them), so a generic
    ``int`` branch would swallow a ``UintType`` -- it MUST be classified before
    the int branch to preserve the distinct ``uint`` tag (lib.rs:1138).

``typed_to_py`` returns the EXACT cel-python celtypes classes on decode
(``IntType`` / ``UintType`` / ``DoubleType`` / ``StringType`` / ``BoolType`` /
``BytesType`` / ``ListType`` / ``MapType``); the wasm ``Value::Null`` decodes to
Python ``None`` (lib.rs:1286), the canonical CEL-null Python value.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import datetime
import math
from typing import Any

import celpy.celtypes as celtypes

__all__ = ["py_to_typed", "typed_to_py"]

# Wire integer bounds (lib.rs:1358 / 1366): the wasm request decoder parses int
# as i64 and uint as u64, so an out-of-range Python int produces JSON the wasm
# CANNOT deserialize. This is the WIRE bound, DISTINCT from (and wider than) the
# host _check_finite IEEE-754 2**53 SAFE_INTEGER bound applied to RESULTS --
# both exist and both are enforced (FINDING C).
_I64_MIN = -(2**63)
_I64_MAX = 2**63 - 1
_U64_MAX = 2**64 - 1


# ---------------------------------------------------------------------------
# double canonicalisation -- a faithful port of the Rust canonical_double /
# format_double_g (lib.rs:1002-1114), which reproduces cel-go's
# strconv.FormatFloat(f, 'g', -1, 64) used as the conformance ground truth.
# The encode side MUST match these bytes so the same logical double serialises
# byte-identically on the Python host and inside the wasm.
# ---------------------------------------------------------------------------
def _canonical_double(f: float) -> str:
    """Canonical decimal-g string for a CEL double (lib.rs:1002-1009 + 1018-1090)."""
    if math.isnan(f):
        return "nan"
    if math.isinf(f):
        return "inf" if f > 0.0 else "-inf"
    return _format_double_g(f)


def _format_double_g(f: float) -> str:
    """Shortest round-trip decimal with cel-go's 'g'-verb %e/%f selection.

    Port of lib.rs ``format_double_g`` (lib.rs:1018-1090): switch to %e when the
    decimal exponent of the leading significant digit is < -4 or >= 6, else %f;
    %f always carries a decimal point so a whole double (1.0) is textually
    distinct from the int 1.
    """
    if f == 0.0:
        # Go prints 0 as "0"; the typed form forces a decimal point downstream
        # (lib.rs:1019-1025).
        return "-0.0" if math.copysign(1.0, f) < 0 else "0.0"

    # Python's repr(float) yields the shortest decimal that round-trips, the
    # same shortest representation Rust's {} for f64 produces (lib.rs:1030).
    shortest = repr(f)
    neg = shortest.startswith("-")
    mag = shortest[1:] if neg else shortest

    # repr may already be in exponent form (e.g. "1e+16", "1e-05"); normalise to
    # significand digits + decimal exponent of the leading digit.
    if "e" in mag or "E" in mag:
        digits, exp10 = _parse_exponent_form(mag)
    else:
        int_part, _, frac_part = mag.partition(".")
        digits = ""
        if int_part not in ("0", ""):
            # exponent = len(int_part) - 1 (lib.rs:1045-1049)
            exp10 = len(int_part) - 1
            digits += int_part
            digits += frac_part
        else:
            # 0.xxxx -- find first nonzero in frac (lib.rs:1050-1055)
            lead_zeros = 0
            for c in frac_part:
                if c == "0":
                    lead_zeros += 1
                else:
                    break
            exp10 = -lead_zeros - 1
            digits += frac_part[lead_zeros:]

    # Strip trailing zeros of the significand (lib.rs:1056-1062).
    while len(digits) > 1 and digits.endswith("0"):
        digits = digits[:-1]
    if not digits:
        digits = "0"

    sign = "-" if neg else ""

    if exp10 < -4 or exp10 >= 6:
        # %e: d.dddde(+/-)XX, exponent at least two digits (lib.rs:1072-1083).
        first = digits[:1]
        rest = digits[1:]
        mantissa = first if not rest else f"{first}.{rest}"
        esign = "-" if exp10 < 0 else "+"
        eabs = abs(exp10)
        return f"{sign}{mantissa}e{esign}{eabs:02d}"

    # %f form -- reconstruct then force a decimal point (lib.rs:1084-1089).
    s = _reconstruct_fixed(digits, exp10)
    if "." not in s:
        s = f"{s}.0"
    return f"{sign}{s}"


def _parse_exponent_form(mag: str) -> tuple[str, int]:
    """Significand digits + leading-digit base-10 exponent for an exponent-form
    magnitude string like "1e+16" / "1.5e-05" (the >= 1 leading digit form Python
    repr emits). The exponent of the leading digit is the printed exponent plus
    the fractional-digit count adjustment for the decimal point position."""
    mantissa, _, exp_str = mag.partition("e")
    exp = int(exp_str)
    int_part, _, frac_part = mantissa.partition(".")
    # Python repr exponent form normalises to one leading nonzero integer digit
    # (e.g. "1", "1.5"), so the leading-digit exponent is exactly the printed
    # exponent.
    digits = int_part + frac_part
    return digits, exp


def _reconstruct_fixed(digits: str, exp10: int) -> str:
    """Fixed-point text from significand digits + leading-digit exponent
    (lib.rs:1094-1114)."""
    d = list(digits)
    if exp10 >= 0:
        int_len = exp10 + 1
        if len(d) <= int_len:
            # pad with trailing zeros (lib.rs:1098-1102)
            return "".join(d) + "0" * (int_len - len(d))
        int_s = "".join(d[:int_len])
        frac_s = "".join(d[int_len:])
        return f"{int_s}.{frac_s}"
    # 0.00..digits with (-exp10 - 1) leading zeros after the point (lib.rs:1108-1112)
    lead = -exp10 - 1
    return f"0.{'0' * lead}{''.join(d)}"


# ---------------------------------------------------------------------------
# map-key sort -- faithful port of lib.rs key_sort_string (lib.rs:1126-1133):
# a total order over typed keys so the serialised [[k,v],...] pairs are emitted
# in the SAME order the wasm emits them.
#   bool   -> "0:bool:{b}"
#   int    -> "1:int:{:020}"  of (i as i128 + 2^63)
#   uint   -> "2:uint:{:020}"
#   string -> "3:string:{s}"
# ---------------------------------------------------------------------------
_I64_OFFSET = 1 << 63


def _key_sort_string(typed_key: dict[str, Any]) -> str:
    t = typed_key["t"]
    v = typed_key["v"]
    if t == "bool":
        # Rust formats a bool via Display: "true" / "false".
        return f"0:bool:{'true' if v else 'false'}"
    if t == "int":
        return f"1:int:{int(v) + _I64_OFFSET:020}"
    if t == "uint":
        return f"2:uint:{int(v):020}"
    if t == "string":
        return f"3:string:{v}"
    raise ValueError(f"invalid map key type: {t!r}")


def _is_celtype(value: Any, name: str) -> bool:
    """True when ``value`` is exactly the named celtypes class (by class name).

    BoolType / IntType / UintType are independent int subclasses, so a plain
    ``isinstance`` against ``int`` cannot distinguish them; class-name identity
    is the unambiguous discriminator the encode side needs.
    """
    return type(value).__name__ == name


# ---------------------------------------------------------------------------
# encode: cel-python value -> typed-canonical {"t","v"} (or {"t":"null"})
# ---------------------------------------------------------------------------
def py_to_typed(value: Any) -> dict[str, Any]:
    """Encode a cel-python ``celtypes`` value (or the equivalent plain Python
    value) to the wasm typed-canonical form.

    Classification order is load-bearing: bool BEFORE int (BoolType is an int
    subclass), and UintType BEFORE the generic int branch (UintType is an
    independent int subclass), so the distinct ``bool`` / ``uint`` tags survive.
    """
    # bool FIRST -- plain bool OR celtypes BoolType (an int subclass that is NOT
    # a bool subclass; lib.rs:1141 emits a JSON boolean for v).
    if isinstance(value, bool) or _is_celtype(value, "BoolType"):
        return {"t": "bool", "v": bool(value)}

    # null -- Python None OR celtypes NullType (lib.rs:1142: no "v" key).
    if value is None or _is_celtype(value, "NullType"):
        return {"t": "null"}

    # type -- celtypes TypeType carrying the cel-go type name (lib.rs:1295:
    # json!({"t":"type","v": name}); the faithful mirror of Value::Type(Arc<str>)).
    # Classified before the generic branches: a TypeType is a `type` subclass and
    # would not match int/str/etc., but the explicit branch keeps the intent and
    # the cel-go name (its __name__) is emitted verbatim so the round-trip is
    # byte-identical.
    if _is_celtype(value, "TypeType"):
        return {"t": "type", "v": value.__name__}

    # duration -- celtypes DurationType (a timedelta) -> "<secs>.<09-nanos>"
    # (lib.rs:1278-1283). Classified before the numeric/collection branches.
    if _is_celtype(value, "DurationType"):
        return {"t": "duration", "v": _encode_duration(value)}

    # timestamp -- celtypes TimestampType (a datetime) -> RFC3339-Z
    # (lib.rs:1285-1290 via rfc3339_utc_z). Classified before the numeric/
    # collection branches.
    if _is_celtype(value, "TimestampType"):
        return {"t": "timestamp", "v": _encode_timestamp(value)}

    # uint BEFORE int -- UintType is an independent int subclass (lib.rs:1138).
    if _is_celtype(value, "UintType"):
        return {"t": "uint", "v": _encode_uint(value)}

    # int -- celtypes IntType or a plain Python int (lib.rs:1137, string-encoded).
    if _is_celtype(value, "IntType") or isinstance(value, int):
        return {"t": "int", "v": _encode_int(value)}

    # double -- celtypes DoubleType or a plain float (lib.rs:1139, canonical-g).
    if _is_celtype(value, "DoubleType") or isinstance(value, float):
        return {"t": "double", "v": _canonical_double(float(value))}

    # bytes -- celtypes BytesType or plain bytes (lib.rs:1143-1145, lowercase hex).
    if isinstance(value, bytes | bytearray):
        return {"t": "bytes", "v": bytes(value).hex()}

    # string -- celtypes StringType or a plain str (lib.rs:1140).
    if isinstance(value, str):
        return {"t": "string", "v": str(value)}

    # list -- celtypes ListType or a plain list/tuple (lib.rs:1147-1150, order kept).
    if isinstance(value, list | tuple):
        return {"t": "list", "v": [py_to_typed(item) for item in value]}

    # map -- celtypes MapType or a plain dict (lib.rs:1151-1162, sorted pairs).
    if isinstance(value, dict):
        entries = []
        for k, val in value.items():
            typed_key = py_to_typed(k)
            sort_key = _key_sort_string(typed_key)
            entries.append((sort_key, typed_key, py_to_typed(val)))
        entries.sort(key=lambda e: e[0])
        return {"t": "map", "v": [[tk, tv] for _, tk, tv in entries]}

    raise TypeError(
        f"py_to_typed: unsupported value type {type(value).__name__!r}: {value!r}"
    )


def _encode_int(value: Any) -> str:
    """Encode an int (celtypes IntType or plain Python int) as the wire decimal
    string, enforcing the i64 wire range (lib.rs:1358 ``s.parse::<i64>()``).

    An out-of-range Python int would serialise to JSON the wasm CANNOT
    deserialize and would break ``_key_sort_string`` (which assumes the i64
    domain). This is the WIRE bound, DISTINCT from the host ``_check_finite``
    2**53 SAFE_INTEGER bound on RESULTS -- both exist (FINDING C).
    """
    i = int(value)
    if i < _I64_MIN or i > _I64_MAX:
        raise ValueError(
            f"py_to_typed: int {i} is outside the wasm i64 wire range "
            f"[{_I64_MIN}, {_I64_MAX}]; the wasm cannot deserialize it"
        )
    return str(i)


def _encode_uint(value: Any) -> str:
    """Encode a uint (celtypes UintType) as the wire decimal string, enforcing
    the u64 wire range (lib.rs:1366 ``s.parse::<u64>()``)."""
    u = int(value)
    if u < 0 or u > _U64_MAX:
        raise ValueError(
            f"py_to_typed: uint {u} is outside the wasm u64 wire range "
            f"[0, {_U64_MAX}]; the wasm cannot deserialize it"
        )
    return str(u)


def _encode_duration(value: Any) -> str:
    """Encode a celtypes ``DurationType`` (a ``datetime.timedelta``) as the
    wasm wire form ``"<secs>.<09-nanos>"`` (lib.rs:1278-1283).

    Faithful port of the Rust serializer:
    ``secs = d.num_seconds()`` (truncates TOWARD ZERO),
    ``nanos = (d - seconds(secs)).num_nanoseconds()``,
    ``format!("{secs}.{:09}", nanos.abs())`` -- so the sign is carried on the
    ``secs`` part only, and the fractional part is the ABSOLUTE nanoseconds
    zero-padded to 9 digits. This reproduces the wasm's behavior EXACTLY,
    including its sign-loss for a sub-second negative duration (``secs == 0``
    drops the sign): the codec MUST agree with the wasm it speaks to
    (byte-parity keystone #16), so this is intentional, not a defect.

    ``timedelta`` stores microsecond resolution, so a sub-microsecond duration
    is not representable in the celtypes value (the decode already truncates
    nanos to microseconds via DurationType); within the representable
    (microsecond) domain this is the byte-faithful round-trip of the wasm form.
    """
    total_ns = _timedelta_total_nanos(value)
    # num_seconds() truncates TOWARD ZERO (Rust chrono::Duration::num_seconds).
    # Python ``//`` floors (toward -inf), so compute the magnitude with integer
    # division and reattach the sign -- exact integer arithmetic, no float
    # precision loss on large durations.
    secs = (
        total_ns // 1_000_000_000
        if total_ns >= 0
        else -((-total_ns) // 1_000_000_000)
    )
    rem_ns = total_ns - secs * 1_000_000_000
    return f"{secs}.{abs(rem_ns):09d}"


def _timedelta_total_nanos(td: Any) -> int:
    """Total nanoseconds of a ``datetime.timedelta`` as an exact integer.

    ``timedelta`` carries days/seconds/microseconds, so the value is exact at
    microsecond resolution; multiply microseconds by 1000 to express it in the
    nanosecond domain the wasm wire form uses.
    """
    total_us = td.days * 86_400 * 1_000_000 + td.seconds * 1_000_000 + td.microseconds
    return total_us * 1000


def _encode_timestamp(value: Any) -> str:
    """Encode a celtypes ``TimestampType`` (a ``datetime.datetime``) as the wasm
    wire form: RFC3339 in UTC with a 'Z' suffix (lib.rs:1285-1290 / rfc3339_utc_z).

    Faithful port of chrono's ``to_rfc3339_opts(SecondsFormat::AutoSi, true)``
    with UTC conversion: convert to UTC, then emit the sub-second part ONLY when
    nonzero, grouped in multiples of 3 fractional digits (milli/micro/nano), and
    suffix 'Z'. ``datetime`` carries microsecond resolution, so the fractional
    part is 0, 3, or 6 digits (the 9-digit nanosecond group is not representable
    in the celtypes value); within that representable domain this reproduces the
    wasm form byte-for-byte.
    """
    utc = value.astimezone(datetime.UTC)
    base = utc.strftime("%Y-%m-%dT%H:%M:%S")
    micros = utc.microsecond
    if micros == 0:
        return f"{base}Z"
    # AutoSi groups the fraction in multiples of 3 digits; pick the FEWEST
    # (3 or 6, the microsecond-representable groups) that is lossless.
    six = f"{micros:06d}"
    frac = six[:3] if six.endswith("000") else six
    return f"{base}.{frac}Z"


# ---------------------------------------------------------------------------
# decode: typed-canonical {"t","v"} -> EXACT cel-python celtypes value
# ---------------------------------------------------------------------------
def typed_to_py(typed: Any) -> Any:
    """Decode a wasm typed-canonical value into the EXACT cel-python celtypes
    class (lib.rs:1346-1465 inverse): int -> IntType, uint -> UintType,
    double -> DoubleType, string -> StringType, bool -> BoolType,
    bytes -> BytesType, list -> ListType, map -> MapType, null -> Python None,
    type -> TypeType, duration -> DurationType, timestamp -> TimestampType.

    The ``v`` field's JSON type is enforced strictly, mirroring the Rust request
    decoder (lib.rs:1352-1465): bool requires a JSON boolean; string / int /
    uint / bytes / type / duration / timestamp require a JSON string. A
    mismatched ``v`` is a hard ``ValueError`` (FINDING B) -- the lenient
    coercion that turned ``{"t":"bool","v":"false"}`` into ``BoolType(True)`` is
    gone. VALID inputs are unchanged.
    """
    if not isinstance(typed, dict):
        raise TypeError(f"typed_to_py: expected a typed object, got {type(typed).__name__!r}")
    try:
        t = typed["t"]
    except KeyError as exc:
        raise ValueError("typed_to_py: typed object missing 't'") from exc

    if t == "int":
        # lib.rs:1353-1359: as_str() then i64 parse -- v MUST be a JSON string.
        return celtypes.IntType(int(_require_str_v(typed)))
    if t == "uint":
        # lib.rs:1361-1367: as_str() then u64 parse.
        return celtypes.UintType(int(_require_str_v(typed)))
    if t == "double":
        # lib.rs:1369-1384 accepts a string sentinel/decimal OR a raw JSON number.
        return celtypes.DoubleType(_decode_double(_require_v(typed)))
    if t == "string":
        # lib.rs:1385-1390: as_str() -- v MUST be a JSON string (no stringify).
        return celtypes.StringType(_require_str_v(typed))
    if t == "bool":
        # lib.rs:1392-1397: as_bool() -- v MUST be a JSON boolean.
        return celtypes.BoolType(_require_bool_v(typed))
    if t == "null":
        # lib.rs:1399 decodes null to Value::Null; Python None is the canonical
        # CEL-null value cel-python uses.
        return None
    if t == "type":
        # lib.rs:1401-1407: as_str() -> Value::Type(Arc::from(s)). The host
        # mirror is a celpy TypeType carrying the cel-go type name verbatim
        # (FINDING A): `type(1)` yields {"t":"type","v":"int"} from the wasm.
        return _decode_type(_require_str_v(typed))
    if t == "bytes":
        # lib.rs:1408-1414: as_str() then hex-decode.
        return celtypes.BytesType(bytes.fromhex(_require_str_v(typed)))
    if t == "duration":
        # lib.rs:1442-1452: as_str() then split_secs_nanos -> chrono Duration.
        # The host mirror is a celpy DurationType (FINDING A).
        return _decode_duration(_require_str_v(typed))
    if t == "timestamp":
        # lib.rs:1454-1462: as_str() then parse_from_rfc3339. The host mirror is
        # a celpy TimestampType (FINDING A).
        return _decode_timestamp(_require_str_v(typed))
    if t == "list":
        v = _require_v(typed)
        if not isinstance(v, list):
            raise ValueError("typed_to_py: list 'v' must be an array")
        return celtypes.ListType([typed_to_py(item) for item in v])
    if t == "map":
        v = _require_v(typed)
        if not isinstance(v, list):
            raise ValueError("typed_to_py: map 'v' must be an array of [k,v] pairs")
        result = celtypes.MapType()
        for pair in v:
            if not isinstance(pair, list | tuple) or len(pair) != 2:
                raise ValueError("typed_to_py: map entry must be a [k,v] pair")
            key = typed_to_py(pair[0])
            result[key] = typed_to_py(pair[1])
        return result
    raise ValueError(f"typed_to_py: unsupported typed tag {t!r}")


def _require_v(typed: dict[str, Any]) -> Any:
    if "v" not in typed:
        raise ValueError(f"typed_to_py: typed object {typed.get('t')!r} missing 'v'")
    return typed["v"]


def _require_str_v(typed: dict[str, Any]) -> str:
    """Return ``typed['v']`` requiring it to be a JSON string (FINDING B).

    Mirrors the Rust ``obj.get("v").and_then(|v| v.as_str())`` strictness used
    for the int / uint / string / bytes / type / duration / timestamp tags: a
    non-string ``v`` (JSON number, bool, null, array, object) is a hard error,
    never a lenient ``str(...)`` coercion. Note a JSON ``bool`` is NOT a string,
    so it is rejected here too.
    """
    v = _require_v(typed)
    if not isinstance(v, str):
        raise ValueError(
            f"typed_to_py: {typed.get('t')!r} 'v' must be a JSON string; "
            f"got {type(v).__name__}: {v!r}"
        )
    return v


def _require_bool_v(typed: dict[str, Any]) -> bool:
    """Return ``typed['v']`` requiring it to be a JSON boolean (FINDING B).

    Mirrors the Rust ``obj.get("v").and_then(|v| v.as_bool())`` strictness
    (lib.rs:1392-1397). The lenient ``bool(v)`` coercion is gone -- a string
    ``"false"`` (which is truthy) or a number no longer decodes to the wrong
    BoolType. ``bool`` is checked explicitly (not ``int``) so ``0`` / ``1`` are
    rejected as non-bool, matching ``as_bool()``.
    """
    v = _require_v(typed)
    if not isinstance(v, bool):
        raise ValueError(
            f"typed_to_py: bool 'v' must be a JSON boolean; "
            f"got {type(v).__name__}: {v!r}"
        )
    return v


def _decode_type(name: str) -> Any:
    """Decode a ``type`` tag's cel-go type name into a celpy ``TypeType`` value
    carrying that name (FINDING A).

    Mirrors Rust ``Value::Type(Arc::from(s))`` (lib.rs:1406): a type value is
    just a name string. cel-python's ``TypeType`` is a ``type`` metaclass whose
    stock constructor is a type-extractor (not a value carrier), so the value is
    built via ``type.__new__(TypeType, name, (), {})`` -- a genuine
    ``TypeType`` instance whose ``__name__`` is the cel-go name verbatim, so
    ``py_to_typed`` re-emits the IDENTICAL ``{"t":"type","v":<name>}``.
    """
    obj = type.__new__(celtypes.TypeType, name, (), {})
    type.__init__(obj, name, (), {})
    return obj


def _decode_duration(v: str) -> Any:
    """Decode a ``duration`` tag's ``"<secs>.<nanos>"`` wire string into a celpy
    ``DurationType`` (FINDING A).

    Faithful port of Rust ``split_secs_nanos`` (lib.rs:1468-1485): split on the
    first '.', parse the integer seconds, pad/truncate the fractional part to 9
    digits for nanoseconds, and apply the seconds' sign to the nanos. The
    resulting ``DurationType`` (a ``datetime.timedelta``) holds microsecond
    resolution, so sub-microsecond nanos are truncated by celtypes -- the same
    representable-domain limit the encode side documents.
    """
    sec_str, _, nano_str = v.partition(".")
    try:
        secs = int(sec_str)
    except ValueError as exc:
        raise ValueError(f"typed_to_py: bad duration seconds in {v!r}") from exc
    nano_digits = (nano_str + "000000000")[:9]
    try:
        nanos = int(nano_digits) if nano_digits else 0
    except ValueError as exc:
        raise ValueError(f"typed_to_py: bad duration nanos in {v!r}") from exc
    if secs < 0:
        nanos = -nanos
    return celtypes.DurationType(seconds=secs, nanos=nanos)


def _decode_timestamp(v: str) -> Any:
    """Decode a ``timestamp`` tag's RFC3339 wire string into a celpy
    ``TimestampType`` (FINDING A).

    Mirrors Rust ``parse_from_rfc3339`` (lib.rs:1459): the ``TimestampType``
    constructor parses the RFC3339 string directly. An unparseable string raises
    a ``ValueError`` rather than silently mis-decoding.
    """
    try:
        return celtypes.TimestampType(v)
    except Exception as exc:  # noqa: BLE001 -- normalize any parse failure
        raise ValueError(f"typed_to_py: bad timestamp {v!r}: {exc}") from exc


def _decode_double(v: Any) -> float:
    """Decode the double ``v`` field: the canonical inf/-inf/nan sentinels or a
    decimal string, mirroring lib.rs:1256-1270 (which also accepts a raw JSON
    number for robustness)."""
    if isinstance(v, str):
        if v == "inf":
            return math.inf
        if v == "-inf":
            return -math.inf
        if v == "nan":
            return math.nan
        return float(v)
    if isinstance(v, int | float):
        return float(v)
    raise ValueError(f"typed_to_py: double 'v' must be string or number, got {v!r}")
