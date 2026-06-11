"""ROBOREV M6 finding A (HIGH, keystone-adjacent): the Python typed-map decode
must be LOSSLESS for non-string CEL map keys, mirroring the TS codec.

The M6 WS-I type-layer move made ``typed_to_py`` decode a typed map into a
native ``dict``. Python hashing collapses DISTINCT CEL keys that compare
equal: ``CelUint`` is an ``int`` subclass, so the CEL int key 1 and the CEL
uint key 1 hash-collide (and ``bool True`` collides with ``int 1``); the
second dict assignment silently OVERWRITES the first -- a VALID wasm result
(the pinned engine emits ``{1: 'a', 1u: 'b'}`` as a TWO-entry map, verified
by direct probe) is corrupted host-side before any re-encode.

The TS codec already fixed this exact class (roborev rounds 2/3,
``packages/contracts-typescript/src/wasm-evaluator.ts``): ``typedToNative``
decodes a non-string-keyed map to a JS ``Map`` whose KEYS are the ORIGINAL
TypedValue objects (lossless), with a ``keySortString`` collision check that
FAILS CLOSED (RelayCelEngineError / RELAY-CEL-ENGINE-REQUEST) on two
distinct typed keys colliding to the same canonical key-sort-string; and
``nativeToTyped`` round-trips that Map back to byte-identical wire form.

This suite pins the Python mirror (``wasm_codec.CelMap``):

  - a typed map whose keys are NOT all strings decodes to a ``CelMap``
    pair-list wrapper carrying (typed key VERBATIM, decoded value) pairs in
    wire order -- int-1 vs uint-1 vs bool-true keys stay DISTINCT;
  - a true duplicate / colliding key fails closed with the structured
    RELAY-CEL-009 / RELAY-CEL-ENGINE-REQUEST error (decode AND encode);
  - ``py_to_typed`` round-trips a ``CelMap`` back to the byte-identical wire
    form (same ``key_sort_string`` ordering the crate uses);
  - the all-string-key fast path still decodes to a plain ``dict``
    (unchanged);
  - the host ``_check_finite`` guard walks ``CelMap`` VALUES (mirroring the
    TS ``checkFinite`` ``Map`` branch, which iterates ``map.values()``).

Py-vs-TS behavior parity note: for every VALID wasm-emitted map both hosts
now decode losslessly and re-encode byte-identically (keystone #16); a
colliding key raises the SAME structured classification on both hosts
(RELAY-CEL-009 / RELAY-CEL-ENGINE-REQUEST). On MALFORMED (non-wasm) key
input each host fails closed with its module-conventional exception type
(Python: ``ValueError`` from ``_key_sort_string``'s tag/parse validation;
TS: the structured ``keySortString`` throw) -- both REJECT, the exception
class differs, and no malformed form decodes successfully on either host.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
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


def _wire_bytes(typed: dict[str, Any]) -> str:
    """Compact JSON text of a typed value (the byte-comparison surface)."""
    return json.dumps(typed, separators=(",", ":"), sort_keys=True)


# ---------------------------------------------------------------------------
# finding A core: int-1 vs uint-1 keys must NOT collapse on decode
# ---------------------------------------------------------------------------


def test_int_and_uint_keys_of_same_value_both_survive_decode() -> None:
    typed = {
        "t": "map",
        "v": [
            [{"t": "int", "v": "1"}, {"t": "string", "v": "as_int"}],
            [{"t": "uint", "v": "1"}, {"t": "string", "v": "as_uint"}],
        ],
    }
    decoded = typed_to_py(typed)
    # NOT a plain dict (a dict would hash-collapse CelUint(1) onto int 1).
    assert isinstance(decoded, CelMap)
    assert len(decoded) == 2
    by_tag = {tk["t"]: val for tk, val in decoded.pairs}
    assert by_tag == {"int": "as_int", "uint": "as_uint"}


def test_bool_true_and_int_one_keys_both_survive_decode() -> None:
    typed = {
        "t": "map",
        "v": [
            [{"t": "bool", "v": True}, {"t": "string", "v": "as_bool"}],
            [{"t": "int", "v": "1"}, {"t": "string", "v": "as_int"}],
        ],
    }
    decoded = typed_to_py(typed)
    assert isinstance(decoded, CelMap)
    assert len(decoded) == 2
    by_tag = {tk["t"]: val for tk, val in decoded.pairs}
    assert by_tag == {"bool": "as_bool", "int": "as_int"}


def test_decoded_values_keep_native_classes() -> None:
    typed = {
        "t": "map",
        "v": [
            [{"t": "int", "v": "1"}, {"t": "uint", "v": "9"}],
            [{"t": "uint", "v": "1"}, {"t": "double", "v": "1.5"}],
        ],
    }
    decoded = typed_to_py(typed)
    assert isinstance(decoded, CelMap)
    values = [val for _tk, val in decoded.pairs]
    assert type(values[0]) is CelUint and values[0] == 9
    assert type(values[1]) is float and values[1] == 1.5


# ---------------------------------------------------------------------------
# collision FAIL-CLOSED (decode): a true duplicate CEL key is data loss
# ---------------------------------------------------------------------------


def test_true_duplicate_key_fails_closed_on_decode() -> None:
    typed = {
        "t": "map",
        "v": [
            [{"t": "int", "v": "5"}, {"t": "string", "v": "first"}],
            [{"t": "int", "v": "5"}, {"t": "string", "v": "second"}],
        ],
    }
    with pytest.raises(RelayCelEngineError) as ctx:
        typed_to_py(typed)
    assert ctx.value.code == "RELAY-CEL-009"
    assert ctx.value.subtype == SUBTYPE_ENGINE_REQUEST


# ---------------------------------------------------------------------------
# round-trip: decode -> encode is BYTE-IDENTICAL wire form
# ---------------------------------------------------------------------------


def test_wasm_emitted_sorted_wire_round_trips_byte_identically() -> None:
    # The pinned engine emits map pairs already sorted by key_sort_string
    # (bool < int < uint < string); decode -> encode must reproduce the
    # EXACT bytes.
    typed = {
        "t": "map",
        "v": [
            [{"t": "bool", "v": True}, {"t": "int", "v": "3"}],
            [{"t": "int", "v": "5"}, {"t": "int", "v": "2"}],
            [{"t": "uint", "v": "2"}, {"t": "int", "v": "1"}],
            [{"t": "string", "v": "s"}, {"t": "int", "v": "0"}],
        ],
    }
    decoded = typed_to_py(typed)
    assert isinstance(decoded, CelMap)
    assert _wire_bytes(py_to_typed(decoded)) == _wire_bytes(typed)


def test_out_of_order_pairs_reencode_in_key_sort_string_order() -> None:
    # Deliberately out of key_sort_string order on the wire so the
    # re-encode's sort is exercised (mirror of the TS round-2 finding-E test).
    typed = {
        "t": "map",
        "v": [
            [{"t": "string", "v": "s"}, {"t": "int", "v": "0"}],
            [{"t": "uint", "v": "2"}, {"t": "int", "v": "1"}],
            [{"t": "int", "v": "5"}, {"t": "int", "v": "2"}],
            [{"t": "bool", "v": True}, {"t": "int", "v": "3"}],
        ],
    }
    expected = {
        "t": "map",
        "v": [
            [{"t": "bool", "v": True}, {"t": "int", "v": "3"}],
            [{"t": "int", "v": "5"}, {"t": "int", "v": "2"}],
            [{"t": "uint", "v": "2"}, {"t": "int", "v": "1"}],
            [{"t": "string", "v": "s"}, {"t": "int", "v": "0"}],
        ],
    }
    decoded = typed_to_py(typed)
    assert isinstance(decoded, CelMap)
    reencoded = py_to_typed(decoded)
    assert reencoded == expected
    assert _wire_bytes(reencoded) == _wire_bytes(expected)
    # And it is NOT the empty-map shape (the TS finding-E bug class).
    assert len(reencoded["v"]) == 4


def test_nested_celmap_value_round_trips() -> None:
    # A non-string-keyed map nested INSIDE a list value round-trips through
    # the recursive codec.
    typed = {
        "t": "list",
        "v": [
            {
                "t": "map",
                "v": [[{"t": "uint", "v": "1"}, {"t": "string", "v": "u"}]],
            }
        ],
    }
    decoded = typed_to_py(typed)
    assert isinstance(decoded, list)
    assert isinstance(decoded[0], CelMap)
    assert _wire_bytes(py_to_typed(decoded)) == _wire_bytes(typed)


# ---------------------------------------------------------------------------
# collision FAIL-CLOSED (encode): a hand-built CelMap cannot smuggle a
# duplicate key onto the wire (the wasm HashMap would silently drop one)
# ---------------------------------------------------------------------------


def test_encode_rejects_colliding_keys_in_hand_built_celmap() -> None:
    colliding = CelMap(
        [
            ({"t": "int", "v": "5"}, "first"),
            ({"t": "int", "v": "5"}, "second"),
        ]
    )
    with pytest.raises(RelayCelEngineError) as ctx:
        py_to_typed(colliding)
    assert ctx.value.code == "RELAY-CEL-009"
    assert ctx.value.subtype == SUBTYPE_ENGINE_REQUEST


def test_encode_rejects_invalid_key_tag_in_hand_built_celmap() -> None:
    # A key tag outside bool/int/uint/string is not an orderable CEL map key;
    # the encode fails closed with the structured engine error (mirrors the
    # TS keySortString throw) rather than mis-encoding.
    bad = CelMap([({"t": "null"}, "x")])
    with pytest.raises(RelayCelEngineError) as ctx:
        py_to_typed(bad)
    assert ctx.value.subtype == SUBTYPE_ENGINE_REQUEST


# ---------------------------------------------------------------------------
# the all-string-key fast path is UNCHANGED
# ---------------------------------------------------------------------------


def test_string_only_map_still_decodes_to_plain_dict() -> None:
    typed = {
        "t": "map",
        "v": [
            [{"t": "string", "v": "a"}, {"t": "int", "v": "1"}],
            [{"t": "string", "v": "z"}, {"t": "int", "v": "2"}],
        ],
    }
    decoded = typed_to_py(typed)
    assert type(decoded) is dict
    assert decoded == {"a": 1, "z": 2}
    assert list(decoded.keys()) == ["a", "z"]


# ---------------------------------------------------------------------------
# CelMap wrapper contract
# ---------------------------------------------------------------------------


def test_celmap_is_immutable_unhashable_and_iterable() -> None:
    m = CelMap([({"t": "int", "v": "1"}, "a")])
    assert len(m) == 1
    assert list(iter(m)) == [({"t": "int", "v": "1"}, "a")]
    assert m == CelMap([({"t": "int", "v": "1"}, "a")])
    assert m != CelMap([({"t": "uint", "v": "1"}, "a")])
    with pytest.raises(AttributeError):
        m.pairs = ()  # type: ignore[misc]
    with pytest.raises(TypeError):
        hash(m)


# ---------------------------------------------------------------------------
# host _check_finite walks CelMap VALUES (mirror of the TS checkFinite
# Map branch)
# ---------------------------------------------------------------------------


def test_check_finite_rejects_nonfinite_value_inside_celmap() -> None:
    from relay_contracts.errors import RelayCelNumericOutOfBoundsError
    from relay_contracts.evaluator import _check_finite

    bad = CelMap([({"t": "int", "v": "1"}, float("inf"))])
    with pytest.raises(RelayCelNumericOutOfBoundsError):
        _check_finite(bad)
    ok = CelMap([({"t": "int", "v": "1"}, 1.5)])
    assert _check_finite(ok) is ok


# ---------------------------------------------------------------------------
# end-to-end through the PINNED engine: the exact corruption case
# ---------------------------------------------------------------------------


def test_engine_int_uint_map_decodes_losslessly_end_to_end() -> None:
    # Probe-verified: the pinned wasm emits {1: 'a', 1u: 'b'} as a TWO-entry
    # map ([[int 1, "a"], [uint 1, "b"]]). The host decode must surface both
    # entries, not silently overwrite one.
    from relay_contracts import RELAY_UDFS, make_cel_evaluator

    ev = make_cel_evaluator(udfs=RELAY_UDFS)
    result = ev.evaluate("{1: 'a', 1u: 'b'}")
    assert isinstance(result, CelMap)
    assert len(result) == 2
    by_tag = {tk["t"]: val for tk, val in result.pairs}
    assert by_tag == {"int": "a", "uint": "b"}


def test_engine_string_keyed_map_still_plain_dict_end_to_end() -> None:
    from relay_contracts import RELAY_UDFS, make_cel_evaluator

    ev = make_cel_evaluator(udfs=RELAY_UDFS)
    result = ev.evaluate("{'x': 1}")
    assert type(result) is dict
    assert result == {"x": 1}
