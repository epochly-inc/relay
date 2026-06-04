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

import math
from typing import Any

import celpy.celtypes as celtypes

__all__ = ["py_to_typed", "typed_to_py"]


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

    # uint BEFORE int -- UintType is an independent int subclass (lib.rs:1138).
    if _is_celtype(value, "UintType"):
        return {"t": "uint", "v": str(int(value))}

    # int -- celtypes IntType or a plain Python int (lib.rs:1137, string-encoded).
    if _is_celtype(value, "IntType") or isinstance(value, int):
        return {"t": "int", "v": str(int(value))}

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


# ---------------------------------------------------------------------------
# decode: typed-canonical {"t","v"} -> EXACT cel-python celtypes value
# ---------------------------------------------------------------------------
def typed_to_py(typed: Any) -> Any:
    """Decode a wasm typed-canonical value into the EXACT cel-python celtypes
    class (lib.rs:1233-1352 inverse): int -> IntType, uint -> UintType,
    double -> DoubleType, string -> StringType, bool -> BoolType,
    bytes -> BytesType, list -> ListType, map -> MapType, null -> Python None.
    """
    if not isinstance(typed, dict):
        raise TypeError(f"typed_to_py: expected a typed object, got {type(typed).__name__!r}")
    try:
        t = typed["t"]
    except KeyError as exc:
        raise ValueError("typed_to_py: typed object missing 't'") from exc

    if t == "int":
        return celtypes.IntType(int(_require_v(typed)))
    if t == "uint":
        return celtypes.UintType(int(_require_v(typed)))
    if t == "double":
        return celtypes.DoubleType(_decode_double(_require_v(typed)))
    if t == "string":
        return celtypes.StringType(str(_require_v(typed)))
    if t == "bool":
        return celtypes.BoolType(bool(_require_v(typed)))
    if t == "null":
        # lib.rs:1286 decodes null to Value::Null; Python None is the canonical
        # CEL-null value cel-python uses.
        return None
    if t == "bytes":
        return celtypes.BytesType(bytes.fromhex(str(_require_v(typed))))
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
