"""Codec between native Python values and the wasm typed-canonical form.

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

THE WIRE FORM IS FROZEN. M6 WS-I changed only the HOST-SIDE TYPE LAYER: the
decode targets are native Python classes (``int`` / ``float`` / ``str`` /
``bool`` / ``bytes`` / ``list`` / ``dict`` / ``None`` /
``datetime.timedelta`` / ``datetime.datetime``) plus the two minimal tagged
wrappers this module owns for the tags Python natives cannot discriminate:

  - :class:`CelUint` -- an ``int`` subclass marking a CEL ``uint`` so the
    round-trip re-emits the distinct ``uint`` tag (a bare ``int`` would
    re-encode as ``int`` and change the engine-side bytes);
  - :class:`CelTypeValue` -- carries a CEL type value's cel-go type name
    verbatim (``type(1)`` evaluates to the type value ``int``).

The ``type`` / ``duration`` / ``timestamp`` tags reach the host even under
the Relay profile: ``type(x)`` is NOT a fenced constructor (it emits a type
value), and ``duration`` / ``timestamp`` VALUES (distinct from the fenced
``duration(...)`` / ``timestamp(...)`` constructors) arrive via bindings
echoed back out. ``timedelta`` / ``datetime`` carry microsecond resolution,
so sub-microsecond nanos are not representable host-side -- the byte-faithful
round-trip domain is the microsecond domain (unchanged from the previous
type layer, which had the same resolution). The ``v`` field's JSON type is
enforced STRICTLY on decode, mirroring the Rust request decoder
(lib.rs:1352-1465): bool requires a JSON boolean, the string-encoded scalars
require a JSON string, and the int / uint ENCODE side enforces the i64 / u64
wire range (lib.rs:1358 / 1366). Typed MAP KEYS take the SAME strict
validation on BOTH the CelMap decode and encode paths
(``_require_valid_map_key``, mirroring lib.rs ``typed_to_key``).

Classification quirk that survives the type-layer move: ``bool`` is an
``int`` subclass in Python, so a CEL boolean MUST be classified BEFORE int or
it serialises as ``{"t":"int"}`` -- a P0 cross-host byte divergence.
``py_to_typed`` therefore tests bool-ness FIRST; ``CelUint`` is likewise
classified before the generic int branch to preserve the distinct ``uint``
tag (lib.rs:1138).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import datetime
import math
import re
from typing import Any

# Absolute import (NOT ``from .errors``): this module is sometimes loaded
# standalone via importlib.spec_from_file_location (the TS cross-host parity
# goldens load wasm_codec.py directly, with no package context), where a
# package-relative import has no parent and raises ImportError. The absolute form
# resolves relay_contracts.errors from sys.path either way (the package is
# installed in the venv), so both the package-submodule and the standalone load
# work.
from relay_contracts.errors import SUBTYPE_ENGINE_REQUEST, RelayCelEngineError

__all__ = ["CelMap", "CelTypeValue", "CelUint", "py_to_typed", "typed_to_py"]

# Wire integer bounds (lib.rs:1358 / 1366): the wasm request decoder parses int
# as i64 and uint as u64, so an out-of-range Python int produces JSON the wasm
# CANNOT deserialize. This is the WIRE bound, DISTINCT from (and wider than) the
# host _check_finite IEEE-754 2**53 SAFE_INTEGER bound applied to RESULTS --
# both exist and both are enforced (FINDING C).
_I64_MIN = -(2**63)
_I64_MAX = 2**63 - 1
_U64_MAX = 2**64 - 1


class CelUint(int):
    """A CEL ``uint`` value: an ``int`` subclass carrying the wire-tag intent.

    Python has one integer type, so without a marker the decode of
    ``{"t":"uint",...}`` would re-encode as ``{"t":"int",...}`` and change
    the engine-side bytes. ``CelUint`` is the minimal discriminator: it
    behaves as its integer value everywhere (arithmetic, equality, dict
    keys) and only the codec's classification reads the class.
    """

    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover -- diagnostic only
        return f"CelUint({int(self)})"


class CelTypeValue:
    """A CEL ``type`` value carrying the cel-go type name verbatim.

    Mirrors Rust ``Value::Type(Arc<str>)`` (lib.rs:1406): a type value is
    just a name string (``type(1)`` -> the type value named ``int``). The
    name round-trips byte-identically through ``{"t":"type","v":<name>}``.

    Deliberately a PLAIN immutable class, NOT a dataclass: this module is
    documented to load STANDALONE via ``spec_from_file_location`` (the TS
    cross-host parity goldens execute it without registering the module in
    ``sys.modules``), and the dataclass machinery's annotation resolution
    requires a registered module -- a frozen dataclass here broke the
    standalone load.
    """

    __slots__ = ("name",)

    def __init__(self, name: str) -> None:
        object.__setattr__(self, "name", name)

    def __setattr__(self, attr: str, value: Any) -> None:
        raise AttributeError(
            f"CelTypeValue is immutable; cannot set {attr!r}"
        )

    def __eq__(self, other: object) -> bool:
        return isinstance(other, CelTypeValue) and other.name == self.name

    def __hash__(self) -> int:
        return hash(("CelTypeValue", self.name))

    def __repr__(self) -> str:  # pragma: no cover -- diagnostic only
        return f"CelTypeValue({self.name!r})"


class CelMap:
    """A CEL map with at least one NON-string key, decoded LOSSLESSLY.

    ROBOREV M6 finding A (HIGH, keystone-adjacent): decoding a typed map
    into a native ``dict`` collapses DISTINCT CEL keys that compare equal in
    Python -- ``CelUint`` is an ``int`` subclass, so the CEL int key 1 and
    the CEL uint key 1 hash-collide (and ``bool True`` collides with ``int
    1``); the second ``dict`` assignment silently OVERWRITES the first,
    corrupting a VALID wasm result (the pinned engine emits ``{1:'a',
    1u:'b'}`` as a TWO-entry map) before any re-encode/canonicalisation.

    The mirror of the TS fix (wasm-evaluator.ts ``typedToNative`` map
    branch, roborev rounds 2/3): a typed map whose keys are NOT all strings
    decodes to this pair-list wrapper instead of a ``dict``. ``pairs`` holds
    ``(typed_key, value)`` 2-tuples in WIRE ORDER, where ``typed_key`` is
    the ORIGINAL typed-canonical key object VERBATIM (``{"t":"int","v":"1"}``
    stays distinct from ``{"t":"uint","v":"1"}``) and ``value`` is the
    decoded native -- exactly the TS ``Map`` whose keys are the original
    ``TypedValue`` objects. ``py_to_typed`` round-trips the wrapper back to
    the byte-identical wire form (same ``key_sort_string`` ordering the
    crate emits), with a collision check that FAILS CLOSED (RELAY-CEL-009 /
    RELAY-CEL-ENGINE-REQUEST) on two distinct typed keys sharing one
    canonical key-sort-string -- on BOTH the decode and encode paths,
    matching the TS codec. All-string-key maps keep decoding to a plain
    ``dict`` (the unchanged fast path).

    Deliberately a PLAIN immutable class (same standalone-load constraint as
    :class:`CelTypeValue`): unhashable (like ``dict``), iterable over its
    pairs, equality by pair sequence.
    """

    __slots__ = ("pairs",)

    # A CEL map is a mutable-conceptually container, like dict: unhashable.
    __hash__ = None  # type: ignore[assignment]

    def __init__(self, pairs: Any) -> None:
        object.__setattr__(
            self, "pairs", tuple((key, value) for key, value in pairs)
        )

    def __setattr__(self, attr: str, value: Any) -> None:
        raise AttributeError(f"CelMap is immutable; cannot set {attr!r}")

    def __len__(self) -> int:
        return len(self.pairs)

    def __iter__(self) -> Any:
        return iter(self.pairs)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, CelMap) and other.pairs == self.pairs

    def __repr__(self) -> str:  # pragma: no cover -- diagnostic only
        return f"CelMap({list(self.pairs)!r})"


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


def _require_valid_map_key(typed_key: Any) -> str:
    """Strictly validate a typed MAP KEY's wire shape, then return its
    ``_key_sort_string``.

    Faithful mirror of the crate's ``typed_to_key`` (lib.rs:1487-1496): a map
    key decodes through the FULL strict scalar decoder (``typed_to_value``)
    BEFORE the restriction to the legal key set Int / Uint / String / Bool,
    so a map key carries EXACTLY the scalar path's strict ``v`` validation
    (FINDING B) plus the wire integer bounds (lib.rs:1358 / 1366):

      bool   -> ``v`` MUST be a JSON boolean            (_require_bool_v)
      int    -> ``v`` MUST be a JSON string within i64  (_require_str_v + _encode_int)
      uint   -> ``v`` MUST be a JSON string within u64  (_require_str_v + _encode_uint)
      string -> ``v`` MUST be a JSON string             (_require_str_v)
      other  -> invalid map key type                    (lib.rs:1494)

    ROBOREV M6 round-2 (MED): the CelMap paths previously validated keys only
    via ``_key_sort_string``, which checks SORTABILITY but never the ``v``
    JSON shape -- a malformed key like ``{"t":"bool","v":"false"}`` (string,
    truthy) was accepted into ``CelMap`` (and sorted as ``0:bool:true``)
    while the scalar decode path and the wasm request decoder both reject
    it. Both CelMap paths (decode storage, encode emit) route every key
    through this validator; the call sites wrap any failure into the
    structured RELAY-CEL-009 / RELAY-CEL-ENGINE-REQUEST error, the same
    fail-closed classification the collision check uses.

    Raises ``TypeError`` / ``ValueError`` (the scalar validators' native
    types); call sites convert to :class:`RelayCelEngineError`.
    """
    if not isinstance(typed_key, dict):
        raise TypeError(
            f"map key must be a typed object; got {type(typed_key).__name__!r}"
        )
    t = typed_key.get("t")
    if t == "bool":
        _require_bool_v(typed_key)
    elif t == "int":
        # Strict Rust-grammar parse + the i64 wire bound in one step (the
        # crate's s.parse::<i64>() enforces both at once, lib.rs:1358).
        # _parse_wire_int rejects every form int() would over-admit
        # (whitespace/underscores/non-ASCII digits/bare sign); its value is
        # discarded -- only the validation matters here.
        _parse_wire_int(_require_str_v(typed_key))
    elif t == "uint":
        # Strict u64 parse + bound (lib.rs:1366); '-' rejected outright.
        _parse_wire_uint(_require_str_v(typed_key))
    elif t == "string":
        _require_str_v(typed_key)
    else:
        raise ValueError(f"invalid map key type: {t!r}")
    return _key_sort_string(typed_key)


# ---------------------------------------------------------------------------
# encode: native Python value -> typed-canonical {"t","v"} (or {"t":"null"})
# ---------------------------------------------------------------------------
def py_to_typed(value: Any) -> dict[str, Any]:
    """Encode a native Python value (or one of this module's tagged wrappers)
    to the wasm typed-canonical form.

    Classification order is load-bearing: bool BEFORE int (``bool`` is an
    ``int`` subclass), and ``CelUint`` BEFORE the generic int branch (it is
    an ``int`` subclass too), so the distinct ``bool`` / ``uint`` tags
    survive the round-trip.
    """
    # bool FIRST -- an int subclass; lib.rs:1141 emits a JSON boolean for v.
    if isinstance(value, bool):
        return {"t": "bool", "v": bool(value)}

    # null (lib.rs:1142: no "v" key).
    if value is None:
        return {"t": "null"}

    # type -- CelTypeValue carrying the cel-go type name (lib.rs:1295:
    # json!({"t":"type","v": name}); the faithful mirror of Value::Type(Arc<str>)).
    if isinstance(value, CelTypeValue):
        return {"t": "type", "v": value.name}

    # duration -- datetime.timedelta -> "<secs>.<09-nanos>" (lib.rs:1278-1283).
    # Classified before the numeric/collection branches.
    if isinstance(value, datetime.timedelta):
        return {"t": "duration", "v": _encode_duration(value)}

    # timestamp -- datetime.datetime -> RFC3339-Z (lib.rs:1285-1290 via
    # rfc3339_utc_z). Classified before the numeric/collection branches.
    if isinstance(value, datetime.datetime):
        return {"t": "timestamp", "v": _encode_timestamp(value)}

    # uint BEFORE int -- CelUint is an int subclass (lib.rs:1138).
    if isinstance(value, CelUint):
        return {"t": "uint", "v": _encode_uint(value)}

    # int (lib.rs:1137, string-encoded).
    if isinstance(value, int):
        return {"t": "int", "v": _encode_int(value)}

    # double (lib.rs:1139, canonical-g).
    if isinstance(value, float):
        return {"t": "double", "v": _canonical_double(float(value))}

    # bytes (lib.rs:1143-1145, lowercase hex).
    if isinstance(value, bytes | bytearray):
        return {"t": "bytes", "v": bytes(value).hex()}

    # string (lib.rs:1140).
    if isinstance(value, str):
        return {"t": "string", "v": str(value)}

    # list (lib.rs:1147-1150, order kept).
    if isinstance(value, list | tuple):
        return {"t": "list", "v": [py_to_typed(item) for item in value]}

    # CelMap -- a losslessly-decoded non-string-keyed CEL map (ROBOREV M6
    # finding A). Re-emit the ORIGINAL typed keys VERBATIM, sorted by
    # key_sort_string (Python str comparison is code-point order, which
    # equals UTF-8 byte order -- the crate's Rust `str` Ord, lib.rs:1270),
    # so decode -> encode is BYTE-IDENTICAL. The collision check fails
    # CLOSED on a duplicate CEL key: the wasm request decoder inserts into a
    # Rust HashMap, which would silently overwrite one value. Mirrors the TS
    # nativeToTyped Map branch.
    if isinstance(value, CelMap):
        cel_map_entries: list[tuple[str, dict[str, Any], dict[str, Any]]] = []
        encode_seen_sort_keys: set[str] = set()
        for typed_key, val in value.pairs:
            try:
                # Strict wire-shape validation BEFORE emit (ROBOREV M6
                # round-2 MED): a hand-built / round-tripped CelMap key must
                # satisfy the SAME scalar-path validation the decode side
                # enforces, or the emitted bytes would be a request the wasm
                # decoder rejects.
                sort_key = _require_valid_map_key(typed_key)
            except (KeyError, TypeError, ValueError) as exc:
                raise RelayCelEngineError(
                    f"py_to_typed: CelMap contains an invalid CEL map key "
                    f"{typed_key!r}: map keys take the SAME strict "
                    "wire-shape validation as the scalar path (bool v must "
                    "be a JSON boolean; int/uint v must be a string-encoded "
                    "integer within the i64/u64 wire bounds; string v must "
                    "be a JSON string; only bool/int/uint/string typed keys "
                    "are orderable in the wasm key_sort_string form) -- "
                    "rejected BEFORE emit (matches the TS keySortString "
                    "fail-closed throw).",
                    subtype=SUBTYPE_ENGINE_REQUEST,
                ) from exc
            if sort_key in encode_seen_sort_keys:
                raise RelayCelEngineError(
                    "py_to_typed: CelMap contains a duplicate / colliding "
                    f"CEL key {typed_key!r} (key_sort_string {sort_key!r}); "
                    "a CEL map cannot carry two equal keys -- failing "
                    "closed rather than letting the wasm HashMap silently "
                    "overwrite one value (matches the TS codec and the "
                    "typed_to_py decode path).",
                    subtype=SUBTYPE_ENGINE_REQUEST,
                )
            encode_seen_sort_keys.add(sort_key)
            cel_map_entries.append((sort_key, typed_key, py_to_typed(val)))
        cel_map_entries.sort(key=lambda e: e[0])
        return {
            "t": "map",
            "v": [[tk, tv] for _, tk, tv in cel_map_entries],
        }

    # map (lib.rs:1151-1162, sorted pairs).
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


# Strict wire-decimal grammar mirroring the crate's Rust integer parse
# (lib.rs:1358 ``s.parse::<i64>()`` / 1366 ``s.parse::<u64>()``). Rust accepts an
# optional single ASCII sign (``+``/``-`` for i64; ``+`` ONLY for u64 -- the
# unsigned parse rejects ``-`` outright, including ``-0``), then one or more
# ASCII digits ``0-9``, and NOTHING else: no surrounding/embedded whitespace
# (ASCII or Unicode), no ``_`` digit separators, no non-ASCII decimal digits
# (e.g. fullwidth), no empty digit run, no bare sign. Python ``int()`` -- which
# the codec previously used raw on both the scalar decode path and the map-key
# paths -- is laxer on ALL of those, so a hand-built key like
# ``{"t":"int","v":"1_000"}`` passed validation and was emitted VERBATIM: bytes
# the wasm request decoder rejects (ROBOREV M6 round-3 MED). ``[0-9]`` matches
# only ASCII digits (Unicode digits would need ``\d``); ``fullmatch`` anchors
# the FULL string with no trailing-newline allowance (unlike ``$``).
_WIRE_INT_RE = re.compile(r"[+-]?[0-9]+")
_WIRE_UINT_RE = re.compile(r"\+?[0-9]+")


def _parse_wire_int(wire: str) -> int:
    """Parse an i64 wire decimal string EXACTLY as Rust ``str::parse::<i64>``.

    Raises ``ValueError`` on every form the crate rejects (whitespace, ``_``,
    non-ASCII digits, empty, bare sign, out-of-i64-range); accepts the
    crate-accepted forms (canonical, leading ``+``, leading zeros, ``-0``). The
    value is computed with ``int()`` only AFTER the grammar check, so ``int``'s
    laxer parsing can never widen what is admitted.
    """
    if not isinstance(wire, str) or _WIRE_INT_RE.fullmatch(wire) is None:
        raise ValueError(
            f"int wire value {wire!r} is not a Rust-parseable i64 decimal "
            "(optional +/- sign then ASCII digits only; no whitespace, "
            "underscores, or non-ASCII digits)"
        )
    value = int(wire)
    if value < _I64_MIN or value > _I64_MAX:
        raise ValueError(
            f"int wire value {wire!r} is outside the i64 range "
            f"[{_I64_MIN}, {_I64_MAX}]"
        )
    return value


def _parse_wire_uint(wire: str) -> int:
    """Parse a u64 wire decimal string EXACTLY as Rust ``str::parse::<u64>``.

    Like :func:`_parse_wire_int` but the unsigned grammar rejects a leading
    ``-`` entirely (including ``-0``); bounds-checks against u64.
    """
    if not isinstance(wire, str) or _WIRE_UINT_RE.fullmatch(wire) is None:
        raise ValueError(
            f"uint wire value {wire!r} is not a Rust-parseable u64 decimal "
            "(optional + sign then ASCII digits only; '-' rejected outright)"
        )
    value = int(wire)
    if value > _U64_MAX:
        raise ValueError(
            f"uint wire value {wire!r} is outside the u64 range [0, {_U64_MAX}]"
        )
    return value


def _encode_int(value: Any) -> str:
    """Encode an int as the wire decimal string, enforcing the i64 wire range
    (lib.rs:1358 ``s.parse::<i64>()``).

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
    """Encode a uint (CelUint) as the wire decimal string, enforcing the u64
    wire range (lib.rs:1366 ``s.parse::<u64>()``)."""
    u = int(value)
    if u < 0 or u > _U64_MAX:
        raise ValueError(
            f"py_to_typed: uint {u} is outside the wasm u64 wire range "
            f"[0, {_U64_MAX}]; the wasm cannot deserialize it"
        )
    return str(u)


def _encode_duration(value: datetime.timedelta) -> str:
    """Encode a ``datetime.timedelta`` as the wasm wire form
    ``"<secs>.<09-nanos>"`` (lib.rs:1278-1283).

    Faithful port of the Rust serializer:
    ``secs = d.num_seconds()`` (truncates TOWARD ZERO),
    ``nanos = (d - seconds(secs)).num_nanoseconds()``,
    ``format!("{secs}.{:09}", nanos.abs())`` -- so the sign is carried on the
    ``secs`` part ONLY, and the fractional part is the ABSOLUTE nanoseconds
    zero-padded to 9 digits.

    ROBOREV finding C (HIGH) -- fail closed on an unrepresentable sign. Because
    the sign rides on ``secs`` alone, a sub-second NEGATIVE duration (``secs ==
    0``, e.g. -0.25s) has NO place to carry its sign: the naive encode emits
    ``"0.250000000"`` (POSITIVE), which a decoder reads back as +0.25s -- silent
    sign corruption. The pinned wasm binary serializes with the identical
    sign-lossy ``format!`` (lib.rs:1283), so we CANNOT invent a sign-preserving
    wire form without diverging from the wasm (byte-parity keystone #16 would
    break) and we MUST NOT change the crate. So we FAIL CLOSED: a duration whose
    SIGNED total cannot be faithfully represented by this wire form raises a
    structured :class:`RelayCelEngineError` (RELAY-CEL-009 /
    RELAY-CEL-ENGINE-REQUEST) -- matching the codec's existing fail-closed
    posture (a value the wire form cannot carry is a request/marshaling error,
    never a silent corruption). The TS codec applies the IDENTICAL guard, so Py
    and TS stay byte-symmetric (both reject the same inputs).

    ``timedelta`` stores microsecond resolution, so a sub-microsecond duration
    is not representable host-side; within the representable (microsecond)
    domain this is the byte-faithful round-trip of the wasm form.
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
    # Fail closed: a negative total with a zero seconds component cannot carry
    # its sign in "<secs>.<09-nanos>" (the sign lives on secs only). Encoding it
    # would silently flip -0.25s to +0.25s. Reject rather than corrupt.
    if total_ns < 0 and secs == 0:
        raise RelayCelEngineError(
            "duration with a sub-second negative magnitude "
            f"({total_ns} ns total) is not representable in the wasm "
            "'<secs>.<09-nanos>' wire form: the sign rides on the integer "
            "seconds component, which is 0 here, so the value would silently "
            "encode as POSITIVE. Refusing to corrupt the binding (the pinned "
            "wasm serializer is identically sign-lossy; this fails closed "
            "rather than diverge from it).",
            subtype=SUBTYPE_ENGINE_REQUEST,
        )
    return f"{secs}.{abs(rem_ns):09d}"


def _timedelta_total_nanos(td: datetime.timedelta) -> int:
    """Total nanoseconds of a ``datetime.timedelta`` as an exact integer.

    ``timedelta`` carries days/seconds/microseconds, so the value is exact at
    microsecond resolution; multiply microseconds by 1000 to express it in the
    nanosecond domain the wasm wire form uses.
    """
    total_us = td.days * 86_400 * 1_000_000 + td.seconds * 1_000_000 + td.microseconds
    return total_us * 1000


def _encode_timestamp(value: datetime.datetime) -> str:
    """Encode a timezone-aware ``datetime.datetime`` as the wasm wire form:
    RFC3339 in UTC with a 'Z' suffix (lib.rs:1285-1290 / rfc3339_utc_z).

    Faithful port of chrono's ``to_rfc3339_opts(SecondsFormat::AutoSi, true)``
    with UTC conversion: convert to UTC, then emit the sub-second part ONLY when
    nonzero, grouped in multiples of 3 fractional digits (milli/micro/nano), and
    suffix 'Z'. ``datetime`` carries microsecond resolution, so the fractional
    part is 0, 3, or 6 digits (the 9-digit nanosecond group is not representable
    host-side); within that representable domain this reproduces the wasm form
    byte-for-byte.

    A NAIVE datetime is rejected fail-closed (RELAY-CEL-009 / ENGINE-REQUEST):
    ``astimezone`` would interpret it in the MACHINE-LOCAL zone, making the
    encoded bytes depend on host configuration -- a determinism violation, not
    a representable value.
    """
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise RelayCelEngineError(
            "timestamp binding must be timezone-aware: a naive datetime "
            "would be interpreted in the machine-local zone and the encoded "
            "bytes would depend on host configuration (refusing the "
            "nondeterministic encode).",
            subtype=SUBTYPE_ENGINE_REQUEST,
        )
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
# decode: typed-canonical {"t","v"} -> native Python value
# ---------------------------------------------------------------------------
def typed_to_py(typed: Any) -> Any:
    """Decode a wasm typed-canonical value into the native Python type
    (lib.rs:1346-1465 inverse): int -> ``int``, uint -> :class:`CelUint`,
    double -> ``float``, string -> ``str``, bool -> ``bool``,
    bytes -> ``bytes``, list -> ``list``, map -> ``dict`` (wire pair order
    preserved as insertion order), null -> ``None``,
    type -> :class:`CelTypeValue`, duration -> ``datetime.timedelta``,
    timestamp -> ``datetime.datetime`` (timezone-aware).

    The ``v`` field's JSON type is enforced strictly, mirroring the Rust request
    decoder (lib.rs:1352-1465): bool requires a JSON boolean; string / int /
    uint / bytes / type / duration / timestamp require a JSON string. A
    mismatched ``v`` is a hard ``ValueError`` (FINDING B) -- never a lenient
    coercion. VALID inputs are unchanged.
    """
    if not isinstance(typed, dict):
        raise TypeError(f"typed_to_py: expected a typed object, got {type(typed).__name__!r}")
    try:
        t = typed["t"]
    except KeyError as exc:
        raise ValueError("typed_to_py: typed object missing 't'") from exc

    if t == "int":
        # lib.rs:1353-1359: as_str() then i64 parse -- v MUST be a JSON string
        # AND parse EXACTLY as Rust str::parse::<i64> (strict grammar + i64
        # bound), never with Python int()'s laxer rules (ROBOREV M6 round-3).
        return _parse_wire_int(_require_str_v(typed))
    if t == "uint":
        # lib.rs:1361-1367: as_str() then u64 parse -- strict Rust grammar +
        # u64 bound ('-' rejected outright), never Python int() (ROBOREV M6 r3).
        return CelUint(_parse_wire_uint(_require_str_v(typed)))
    if t == "double":
        # lib.rs:1369-1384 accepts a string sentinel/decimal OR a raw JSON number.
        return _decode_double(_require_v(typed))
    if t == "string":
        # lib.rs:1385-1390: as_str() -- v MUST be a JSON string (no stringify).
        return _require_str_v(typed)
    if t == "bool":
        # lib.rs:1392-1397: as_bool() -- v MUST be a JSON boolean.
        return _require_bool_v(typed)
    if t == "null":
        # lib.rs:1399 decodes null to Value::Null; Python None is the canonical
        # CEL-null host value.
        return None
    if t == "type":
        # lib.rs:1401-1407: as_str() -> Value::Type(Arc::from(s)). The host
        # mirror is a CelTypeValue carrying the cel-go type name verbatim:
        # `type(1)` yields {"t":"type","v":"int"} from the wasm.
        return CelTypeValue(_require_str_v(typed))
    if t == "bytes":
        # lib.rs:1408-1414: as_str() then hex-decode.
        return bytes.fromhex(_require_str_v(typed))
    if t == "duration":
        # lib.rs:1442-1452: as_str() then split_secs_nanos -> chrono Duration.
        # The host mirror is a datetime.timedelta.
        return _decode_duration(_require_str_v(typed))
    if t == "timestamp":
        # lib.rs:1454-1462: as_str() then parse_from_rfc3339. The host mirror
        # is a timezone-aware datetime.datetime.
        return _decode_timestamp(_require_str_v(typed))
    if t == "list":
        v = _require_v(typed)
        if not isinstance(v, list):
            raise ValueError("typed_to_py: list 'v' must be an array")
        return [typed_to_py(item) for item in v]
    if t == "map":
        v = _require_v(typed)
        if not isinstance(v, list):
            raise ValueError("typed_to_py: map 'v' must be an array of [k,v] pairs")
        # Inspect the RAW typed key tags BEFORE decoding (ROBOREV M6 finding
        # A, mirroring the TS typedToNative map branch): the key TYPE must
        # never be lost. The all-string-key map keeps the legacy plain-dict
        # fast path; ANY non-string key (bool/int/uint, possibly mixed with
        # string keys) routes to the LOSSLESS CelMap wrapper, because native
        # dict hashing collapses CelUint(1) onto int 1 and bool True onto
        # int 1 -- the second assignment would silently OVERWRITE the first.
        raw_pairs: list[tuple[dict[str, Any], Any]] = []
        all_string_keys = True
        for pair in v:
            if not isinstance(pair, list | tuple) or len(pair) != 2:
                raise ValueError("typed_to_py: map entry must be a [k,v] pair")
            raw_key = pair[0]
            if not isinstance(raw_key, dict):
                raise ValueError(
                    "typed_to_py: map key must be a typed object; "
                    f"got {type(raw_key).__name__!r}"
                )
            if raw_key.get("t") != "string":
                all_string_keys = False
            raw_pairs.append((raw_key, pair[1]))
        if all_string_keys:
            result: dict[Any, Any] = {}
            for raw_key, raw_val in raw_pairs:
                result[typed_to_py(raw_key)] = typed_to_py(raw_val)
            return result
        # Lossless decode: keep the ORIGINAL typed keys verbatim; values
        # decode to natives. _require_valid_map_key enforces the SAME strict
        # wire-shape validation the scalar decode path applies (ROBOREV M6
        # round-2 MED: bool v is a JSON boolean; int/uint v is a
        # string-encoded integer within i64/u64; string v is a JSON string;
        # only bool/int/uint/string tags are legal keys, lib.rs
        # typed_to_key) and returns the sort string -- the collision
        # discriminant (int 1 != uint 1 != bool true). A true duplicate CEL
        # key cannot exist (the wasm decoder's Rust HashMap would have
        # silently dropped one entry), so fail CLOSED with the structured
        # engine error -- matching the TS typedToNative decode path.
        seen_sort_keys: set[str] = set()
        out_pairs: list[tuple[dict[str, Any], Any]] = []
        for raw_key, raw_val in raw_pairs:
            try:
                sort_key = _require_valid_map_key(raw_key)
            except (KeyError, TypeError, ValueError) as exc:
                raise RelayCelEngineError(
                    "typed_to_py: map contains an invalid CEL map key "
                    f"{raw_key!r}: map keys take the SAME strict wire-shape "
                    "validation as the scalar decode path (bool v must be a "
                    "JSON boolean; int/uint v must be a string-encoded "
                    "integer within the i64/u64 wire bounds; string v must "
                    "be a JSON string; only bool/int/uint/string tags are "
                    "legal map keys, lib.rs typed_to_key) -- failing closed "
                    "like the wasm request decoder rather than admitting a "
                    "key the scalar path rejects.",
                    subtype=SUBTYPE_ENGINE_REQUEST,
                ) from exc
            if sort_key in seen_sort_keys:
                raise RelayCelEngineError(
                    "typed_to_py: wasm map contains a duplicate / colliding "
                    f"key {raw_key!r} (key_sort_string {sort_key!r}); a CEL "
                    "map cannot carry two equal keys -- failing closed "
                    "rather than silently dropping an entry (matches the TS "
                    "codec).",
                    subtype=SUBTYPE_ENGINE_REQUEST,
                )
            seen_sort_keys.add(sort_key)
            out_pairs.append((raw_key, typed_to_py(raw_val)))
        return CelMap(out_pairs)
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
    (lib.rs:1392-1397). A string ``"false"`` (which is truthy) or a number
    never decodes to the wrong boolean. ``bool`` is checked explicitly (not
    ``int``) so ``0`` / ``1`` are rejected as non-bool, matching ``as_bool()``.
    """
    v = _require_v(typed)
    if not isinstance(v, bool):
        raise ValueError(
            f"typed_to_py: bool 'v' must be a JSON boolean; "
            f"got {type(v).__name__}: {v!r}"
        )
    return v


def _decode_duration(v: str) -> datetime.timedelta:
    """Decode a ``duration`` tag's ``"<secs>.<nanos>"`` wire string into a
    ``datetime.timedelta``.

    Faithful port of Rust ``split_secs_nanos`` (lib.rs:1468-1485): split on the
    first '.', parse the integer seconds, pad/truncate the fractional part to 9
    digits for nanoseconds, and apply the seconds' sign to the nanos. The
    resulting ``timedelta`` holds microsecond resolution, so sub-microsecond
    nanos are truncated (toward zero) -- the same representable-domain limit
    the encode side documents.
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
    # Truncate nanos toward zero into the microsecond domain (timedelta
    # resolution); exact for every wire value in the microsecond domain.
    micros = nanos // 1000 if nanos >= 0 else -((-nanos) // 1000)
    return datetime.timedelta(seconds=secs, microseconds=micros)


def _decode_timestamp(v: str) -> datetime.datetime:
    """Decode a ``timestamp`` tag's RFC3339 wire string into a timezone-aware
    ``datetime.datetime``.

    Mirrors Rust ``parse_from_rfc3339`` (lib.rs:1459). An unparseable string
    -- or one WITHOUT an offset (RFC3339 requires one; a naive datetime would
    poison the deterministic re-encode) -- raises ``ValueError`` rather than
    silently mis-decoding.
    """
    try:
        parsed = datetime.datetime.fromisoformat(v)
    except ValueError as exc:
        raise ValueError(f"typed_to_py: bad timestamp {v!r}: {exc}") from exc
    if parsed.tzinfo is None or parsed.tzinfo.utcoffset(parsed) is None:
        raise ValueError(
            f"typed_to_py: bad timestamp {v!r}: missing UTC offset "
            "(RFC3339 requires one)"
        )
    return parsed


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
