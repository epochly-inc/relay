"""Tier-1 plumbing tests for cross-numeric MAP equality (G6 extension), driven
through the actual wasm via the loader.

cel-go map equality is cross-numeric on BOTH keys and values:
  {1: 1.0, 2u: 3u} == {1u: 1, 2: 3.0}  -> true
The int key 1 matches the uint key 1u; the double value 1.0 matches the int
value 1. The derived HashMap == HashMap (separate Key Int/UInt variants, exact
value type) wrongly returned false. The fork's DefaultMap::equals now matches
entries cross-numerically via Val::equals (the G6 numeric comparer).
"""
import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "python"))

from relay_cel_wasm import RelayCel  # noqa: E402

pytestmark = pytest.mark.plumbing


@pytest.fixture(scope="module")
def cel():
    wasm = os.path.normpath(
        os.path.join(
            _HERE, "..", "crate", "target", "wasm32-unknown-unknown",
            "release", "relay_cel_wasm.wasm",
        )
    )
    if not os.path.exists(wasm):
        pytest.skip("wasm not built")
    return RelayCel(wasm)


MAP_EQ_TRUE = [
    "{1: 1.0, 2u: 3u} == {1u: 1, 2: 3.0}",
    "{1: 2} == {1u: 2.0}",
    "{1u: 1} == {1: 1.0}",
    "{'a': 1, 'b': 2} == {'a': 1.0, 'b': 2u}",
    "{1: 1} == {1: 1}",
]

MAP_EQ_FALSE = [
    "{1: 1} == {1: 2}",            # value differs
    "{1: 1} == {2: 1}",            # key differs
    "{1: 1} == {1: 1, 2: 2}",     # size differs
    "{1: 1, 2: 2} == {1: 1}",     # size differs
    "{'a': 1} == {'b': 1}",       # string key differs
]


@pytest.mark.parametrize("expr", MAP_EQ_TRUE)
def test_map_eq_true(cel, expr):
    out = cel.eval(expr)
    assert out["ok"] is True, (expr, out)
    assert out["value"] == {"t": "bool", "v": True}, (expr, out)


@pytest.mark.parametrize("expr", MAP_EQ_FALSE)
def test_map_eq_false(cel, expr):
    out = cel.eval(expr)
    assert out["ok"] is True, (expr, out)
    assert out["value"] == {"t": "bool", "v": False}, (expr, out)


def test_map_ne_inverse(cel):
    out = cel.eval("{1: 1.0, 2u: 3u} != {1u: 1, 2: 3.0}")
    assert out["ok"] is True, out
    assert out["value"] == {"t": "bool", "v": False}, out
