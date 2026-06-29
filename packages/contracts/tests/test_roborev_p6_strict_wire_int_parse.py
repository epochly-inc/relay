"""ROBOREV P6REMOVE round-3 (MED): int/uint wire-string parsing must be
EXACTLY as strict as the Rust request decoder -- never more permissive.

The crate decodes the wire ``v`` of ``{"t":"int"}`` / ``{"t":"uint"}`` with
Rust ``str::parse::<i64>`` / ``str::parse::<u64>`` (lib.rs:1358 / 1366, via
core ``from_str_radix``): an optional single ASCII sign (``+`` or ``-`` for
i64; ``+`` only for u64 -- the unsigned parse rejects ``-``), then one or
more ASCII digits ``0-9``. NOTHING else. Python ``int()`` -- which the codec
previously used raw -- additionally accepts leading/trailing whitespace
(ASCII and Unicode), ``_`` digit separators, non-ASCII decimal digits
(e.g. fullwidth), so a hand-built key like ``{"t":"int","v":"1_000"}``
passed ``_require_valid_map_key`` and was emitted VERBATIM -- bytes the wasm
request decoder rejects. The scalar ``typed_to_py`` int/uint path had the
same leniency PLUS no i64/u64 range check at all.

Crate behavior PROBE-VERIFIED against the PINNED wasm
(``relay_contracts/_wasm/relay_cel_wasm.wasm``, 2026-06-11), both as scalar
bindings and as map keys:

    REJECT ("bad int"/"bad uint"): "1_000", " 1", "1 ", fullwidth digits
        (U+FF11...), "" (empty), "+" (bare sign); uint additionally rejects
        "-1" AND "-0"; out-of-range ("9223372036854775808" for int,
        "18446744073709551616" for uint).
    ACCEPT: "+5" (-> 5), "007" (-> 7), "-5", "-0" (-> 0, int only), and the
        exact i64/u64 endpoints.

This suite pins the Python codec to that exact grammar on BOTH surfaces:

  - the scalar decode path (``typed_to_py`` int/uint) raises ``ValueError``
    (the FINDING B scalar-strictness convention) on every crate-rejected
    form, including out-of-range;
  - the map-key paths (``_require_valid_map_key`` via CelMap decode AND
    encode) fail closed with the structured RELAY-CEL-009 /
    RELAY-CEL-ENGINE-REQUEST error (the round-2 MED convention);
  - crate-ACCEPTED forms keep parsing: canonical strings, the endpoints,
    ``+5`` and ``007`` (with ``+5``/``5`` and ``007``/``7`` map keys
    correctly detected as the SAME CEL key -> collision fail-closed).

ASCII-only per CLAUDE.md "ASCII-Safe Source": the non-ASCII probe
characters (fullwidth digits, NBSP) are built with ``chr()`` so the source
file itself stays pure ASCII.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from relay_contracts.errors import (
    SUBTYPE_ENGINE_REQUEST,
    RelayCelEngineError,
)
from relay_contracts.wasm_codec import (
    CelMap,
    CelUint,
    py_to_typed,
    typed_to_py,
)

pytestmark = pytest.mark.plumbing

_I64_MIN = -(2**63)
_I64_MAX = 2**63 - 1
_U64_MAX = 2**64 - 1

# Fullwidth decimal digits ONE/ZERO (U+FF11 / U+FF10): Python int() accepts
# them; Rust parse does not ("bad int", probe-verified). chr()-built to keep
# this source file ASCII-only.
_FULLWIDTH_10 = chr(0xFF11) + chr(0xFF10)

# NBSP-prefixed digit (U+00A0): int() treats NBSP as strippable whitespace;
# Rust parse rejects it.
_NBSP_1 = chr(0x00A0) + "1"

# Forms Python int() accepts but the pinned wasm decoder REJECTS
# (probe-verified "bad int" / "bad uint"), plus out-of-range strings the
# scalar path previously never bounds-checked.
_CRATE_REJECTED_INT_STRINGS = [
    "1_000",  # '_' separators
    " 1",  # leading ASCII whitespace
    "1 ",  # trailing ASCII whitespace
    "\t1",  # leading tab
    _NBSP_1,  # leading Unicode whitespace
    _FULLWIDTH_10,  # non-ASCII decimal digits
    "",  # empty
    "+",  # bare sign
    "-",  # bare sign
    "+ 5",  # sign then whitespace
    str(_I64_MAX + 1),  # i64 overflow
    str(_I64_MIN - 1),  # i64 underflow
]

_CRATE_REJECTED_UINT_STRINGS = [
    "1_000",
    " 1",
    "1 ",
    _FULLWIDTH_10,
    "",
    "+",
    "-1",  # unsigned parse rejects '-' entirely...
    "-0",  # ...including minus-zero (probe-verified "bad uint '-0'")
    str(_U64_MAX + 1),  # u64 overflow
]


def _wire_bytes(typed: dict[str, Any]) -> str:
    return json.dumps(typed, separators=(",", ":"), sort_keys=True)


def _mixed_map_with_key(typed_key: dict[str, Any]) -> dict[str, Any]:
    """A typed map routing through the CelMap (non-string-key) decode path."""
    return {
        "t": "map",
        "v": [
            [{"t": "int", "v": "7"}, {"t": "string", "v": "anchor"}],
            [typed_key, {"t": "string", "v": "probe"}],
        ],
    }


# ---------------------------------------------------------------------------
# scalar decode path: typed_to_py int/uint must reject every crate-rejected
# form with ValueError (FINDING B convention).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad", _CRATE_REJECTED_INT_STRINGS, ids=ascii)
def test_scalar_int_rejects_crate_rejected_wire_string(bad: str) -> None:
    # BEFORE the fix: int("1_000") == 1000, int(" 1") == 1, fullwidth == 10,
    # and out-of-range strings decoded with NO bounds check -- all ACCEPTED
    # while the pinned wasm rejects them ("bad int", probe-verified).
    with pytest.raises(ValueError):
        typed_to_py({"t": "int", "v": bad})


@pytest.mark.parametrize("bad", _CRATE_REJECTED_UINT_STRINGS, ids=ascii)
def test_scalar_uint_rejects_crate_rejected_wire_string(bad: str) -> None:
    # BEFORE the fix: CelUint(int("-1")) == CelUint(-1) -- a NEGATIVE uint --
    # was accepted; the pinned wasm rejects "bad uint '-1'".
    with pytest.raises(ValueError):
        typed_to_py({"t": "uint", "v": bad})


def test_scalar_int_keeps_canonical_and_crate_accepted_forms() -> None:
    # Regression-keep: every crate-ACCEPTED form keeps decoding, to the same
    # value the crate parses (probe-verified).
    assert typed_to_py({"t": "int", "v": "0"}) == 0
    assert typed_to_py({"t": "int", "v": "-5"}) == -5
    assert typed_to_py({"t": "int", "v": "+5"}) == 5  # crate-accepted
    assert typed_to_py({"t": "int", "v": "007"}) == 7  # crate-accepted
    assert typed_to_py({"t": "int", "v": "-0"}) == 0  # crate-accepted
    assert typed_to_py({"t": "int", "v": str(_I64_MIN)}) == _I64_MIN
    assert typed_to_py({"t": "int", "v": str(_I64_MAX)}) == _I64_MAX


def test_scalar_uint_keeps_canonical_and_crate_accepted_forms() -> None:
    assert typed_to_py({"t": "uint", "v": "0"}) == CelUint(0)
    assert typed_to_py({"t": "uint", "v": "+5"}) == CelUint(5)  # crate-accepted
    u = typed_to_py({"t": "uint", "v": str(_U64_MAX)})
    assert isinstance(u, CelUint)
    assert int(u) == _U64_MAX


# ---------------------------------------------------------------------------
# map-key paths: decode (CelMap storage) and encode (emit) fail closed with
# the structured RELAY-CEL-009 / RELAY-CEL-ENGINE-REQUEST error.
# ---------------------------------------------------------------------------

_CRATE_REJECTED_TYPED_KEYS = [
    *[{"t": "int", "v": s} for s in _CRATE_REJECTED_INT_STRINGS],
    *[{"t": "uint", "v": s} for s in _CRATE_REJECTED_UINT_STRINGS],
]


@pytest.mark.parametrize(
    "bad_key",
    _CRATE_REJECTED_TYPED_KEYS,
    ids=lambda k: f"{k['t']}-{ascii(k['v'])}",
)
def test_decode_rejects_crate_rejected_int_uint_map_key(
    bad_key: dict[str, Any],
) -> None:
    # BEFORE the fix: {"t":"int","v":"1_000"} passed _require_valid_map_key
    # (int("1_000") == 1000) and was stored in CelMap.
    with pytest.raises(RelayCelEngineError) as ctx:
        typed_to_py(_mixed_map_with_key(bad_key))
    assert ctx.value.code == "RELAY-CEL-009"
    assert ctx.value.subtype == SUBTYPE_ENGINE_REQUEST


@pytest.mark.parametrize(
    "bad_key",
    _CRATE_REJECTED_TYPED_KEYS,
    ids=lambda k: f"{k['t']}-{ascii(k['v'])}",
)
def test_encode_rejects_crate_rejected_int_uint_map_key_before_emit(
    bad_key: dict[str, Any],
) -> None:
    # BEFORE the fix: a hand-built CelMap key {"t":"int","v":"1_000"} was
    # emitted VERBATIM -- bytes the wasm request decoder rejects
    # (probe-verified: "bad int '1_000'").
    with pytest.raises(RelayCelEngineError) as ctx:
        py_to_typed(CelMap([(bad_key, "x")]))
    assert ctx.value.code == "RELAY-CEL-009"
    assert ctx.value.subtype == SUBTYPE_ENGINE_REQUEST


def test_canonical_int_uint_keys_still_round_trip_byte_identically() -> None:
    # Regression-keep: canonical engine-emitted keys are untouched.
    typed = {
        "t": "map",
        "v": [
            [{"t": "int", "v": str(_I64_MIN)}, {"t": "string", "v": "lo"}],
            [{"t": "int", "v": "-5"}, {"t": "string", "v": "neg"}],
            [{"t": "int", "v": "0"}, {"t": "string", "v": "zero"}],
            [{"t": "int", "v": str(_I64_MAX)}, {"t": "string", "v": "hi"}],
            [{"t": "uint", "v": "0"}, {"t": "string", "v": "uzero"}],
            [{"t": "uint", "v": str(_U64_MAX)}, {"t": "string", "v": "umax"}],
        ],
    }
    decoded = typed_to_py(typed)
    assert isinstance(decoded, CelMap)
    assert _wire_bytes(py_to_typed(decoded)) == _wire_bytes(typed)


def test_crate_accepted_plus_form_key_is_accepted() -> None:
    # "+5" is crate-ACCEPTED (probe: parses to 5), so it remains a VALID key
    # host-side; CelMap re-emits the original key VERBATIM (not normalized to
    # "5") and the crate accepts those bytes. The input is built in canonical
    # key-sort order ("+5" -> 5 sorts before "7"), so the round-trip -- which
    # sorts on encode, as the wasm does -- is byte-identical: this proves the
    # "+5" key survives verbatim AND is not collapsed onto another key.
    typed = {
        "t": "map",
        "v": [
            [{"t": "int", "v": "+5"}, {"t": "string", "v": "probe"}],
            [{"t": "int", "v": "7"}, {"t": "string", "v": "anchor"}],
        ],
    }
    decoded = typed_to_py(typed)
    assert isinstance(decoded, CelMap)
    assert _wire_bytes(py_to_typed(decoded)) == _wire_bytes(typed)


@pytest.mark.parametrize(
    ("alias_key", "canonical_key"),
    [
        ({"t": "int", "v": "+5"}, {"t": "int", "v": "5"}),
        ({"t": "int", "v": "007"}, {"t": "int", "v": "7"}),
        ({"t": "int", "v": "-0"}, {"t": "int", "v": "0"}),
        ({"t": "uint", "v": "+1"}, {"t": "uint", "v": "1"}),
    ],
    ids=lambda k: f"{k['t']}-{k['v']}",
)
def test_textual_alias_of_same_cel_key_fails_closed_as_collision(
    alias_key: dict[str, Any], canonical_key: dict[str, Any]
) -> None:
    # "+5" and "5" are textually distinct wire keys but the SAME parsed CEL
    # key (the crate's HashMap would silently overwrite one entry --
    # probe-verified: a map with int keys "007" and "7" came back size 1).
    # The host collision check must treat them as equal and fail closed.
    typed = {
        "t": "map",
        "v": [
            [alias_key, {"t": "string", "v": "a"}],
            [canonical_key, {"t": "string", "v": "b"}],
        ],
    }
    with pytest.raises(RelayCelEngineError) as ctx:
        typed_to_py(typed)
    assert ctx.value.code == "RELAY-CEL-009"
    assert ctx.value.subtype == SUBTYPE_ENGINE_REQUEST


# ---------------------------------------------------------------------------
# ROBOREV P6REMOVE round-4 (LOW): a Rust-ACCEPTED in-range value with MANY
# leading zeros must DECODE, not raise. Rust ``str::parse::<i64>`` /
# ``parse::<u64>`` accept arbitrarily many leading zeros (overflow-checked, so
# the only bound is the i64 / u64 RANGE -- not digit count). Python ``int()``
# on 3.12+ enforces a 4300-digit string-conversion limit, so the codec's raw
# ``int()`` RAISED on e.g. "0"*5000 -- a Py<->Rust divergence. The fix strips
# the sign + leading zeros (grammar already checked) before ``int()`` so only
# the bounded-width significant digits reach it.
#
# The probe strings exceed the 4300-digit limit DELIBERATELY: BEFORE the fix
# every assertion here raised ValueError("Exceeds the limit (4300 digits)...");
# AFTER the fix they decode to the small Rust value.
_LEADING_ZERO_5000 = "0" * 5000
# "+" + 5000 zeros + "5" -> Rust parses to 5.
_PLUS_LEADING_ZERO_5000_5 = "+" + "0" * 5000 + "5"
# "-" + 5000 zeros + "5" -> Rust parses to -5 (int only).
_MINUS_LEADING_ZERO_5000_5 = "-" + "0" * 5000 + "5"


def test_scalar_int_long_leading_zeros_decode_not_raise() -> None:
    # RED before fix: int("0"*5000) raises the 4300-digit ValueError.
    # GREEN after fix: normalized to "0", decodes to 0 (Rust-accepted).
    assert typed_to_py({"t": "int", "v": _LEADING_ZERO_5000}) == 0
    assert typed_to_py({"t": "int", "v": _PLUS_LEADING_ZERO_5000_5}) == 5
    assert typed_to_py({"t": "int", "v": _MINUS_LEADING_ZERO_5000_5}) == -5


def test_scalar_uint_long_leading_zeros_decode_not_raise() -> None:
    # RED before fix: int("0"*5000) raises the 4300-digit ValueError.
    # GREEN after fix: normalized to "0", decodes to CelUint(0) (Rust-accepted).
    assert typed_to_py({"t": "uint", "v": _LEADING_ZERO_5000}) == CelUint(0)
    assert typed_to_py({"t": "uint", "v": _PLUS_LEADING_ZERO_5000_5}) == CelUint(5)


def test_scalar_long_leading_zeros_still_range_checked() -> None:
    # Leading zeros do NOT widen the range: a long-leading-zero value whose
    # SIGNIFICANT digits exceed i64/u64 still raises (the bound is on the value,
    # not the digit count). Rust's overflow-checked parse rejects these too.
    over_i64 = "0" * 5000 + str(_I64_MAX + 1)
    over_u64 = "0" * 5000 + str(_U64_MAX + 1)
    with pytest.raises(ValueError):
        typed_to_py({"t": "int", "v": over_i64})
    with pytest.raises(ValueError):
        typed_to_py({"t": "uint", "v": over_u64})


def test_long_leading_zero_int_map_key_decodes_and_collides_with_canonical() -> None:
    # The map-key path (CelMap decode via _require_valid_map_key ->
    # _key_sort_string) must (a) NOT raise the 4300-digit error on a
    # long-leading-zero key and (b) recognize it as the SAME CEL key as its
    # canonical form -- so a map carrying both fails closed as a collision
    # (the wasm HashMap would silently drop one). "0"*5000 is the CEL key 0,
    # which must collide with the canonical "0" key.
    typed = {
        "t": "map",
        "v": [
            [{"t": "int", "v": _LEADING_ZERO_5000}, {"t": "string", "v": "a"}],
            [{"t": "int", "v": "0"}, {"t": "string", "v": "b"}],
        ],
    }
    with pytest.raises(RelayCelEngineError) as ctx:
        typed_to_py(typed)
    assert ctx.value.code == "RELAY-CEL-009"
    assert ctx.value.subtype == SUBTYPE_ENGINE_REQUEST


def test_long_leading_zero_5_int_map_key_collides_with_canonical_5() -> None:
    # "+" + "0"*5000 + "5" is the CEL key 5; it must collide with "5".
    typed = {
        "t": "map",
        "v": [
            [
                {"t": "int", "v": _PLUS_LEADING_ZERO_5000_5},
                {"t": "string", "v": "a"},
            ],
            [{"t": "int", "v": "5"}, {"t": "string", "v": "b"}],
        ],
    }
    with pytest.raises(RelayCelEngineError) as ctx:
        typed_to_py(typed)
    assert ctx.value.code == "RELAY-CEL-009"
    assert ctx.value.subtype == SUBTYPE_ENGINE_REQUEST


def test_long_leading_zero_uint_map_key_collides_with_canonical() -> None:
    # The uint key-sort path must also normalize before int(): "0"*5000 as a
    # uint key is the CEL uint 0, colliding with the canonical "0" uint key.
    typed = {
        "t": "map",
        "v": [
            [{"t": "uint", "v": _LEADING_ZERO_5000}, {"t": "string", "v": "a"}],
            [{"t": "uint", "v": "0"}, {"t": "string", "v": "b"}],
        ],
    }
    with pytest.raises(RelayCelEngineError) as ctx:
        typed_to_py(typed)
    assert ctx.value.code == "RELAY-CEL-009"
    assert ctx.value.subtype == SUBTYPE_ENGINE_REQUEST


def test_long_leading_zero_encode_map_key_round_trips_byte_identically() -> None:
    # A hand-built CelMap with a long-leading-zero key must ENCODE without
    # raising the 4300-digit error (the encode path also routes keys through
    # _require_valid_map_key -> _key_sort_string). The original key bytes are
    # re-emitted VERBATIM (the codec never normalizes the stored wire key), so
    # a single-entry map round-trips byte-identically.
    raw = {"t": "int", "v": _PLUS_LEADING_ZERO_5000_5}
    typed = {"t": "map", "v": [[raw, {"t": "string", "v": "x"}]]}
    decoded = typed_to_py(typed)
    assert isinstance(decoded, CelMap)
    assert _wire_bytes(py_to_typed(decoded)) == _wire_bytes(typed)
