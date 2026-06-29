"""Tier-1 plumbing tests for G15 comprehension error short-circuit ordering,
driven through the actual wasm via the loader.

cel-go comprehension macros use error-as-value semantics with the commutative
logical operators: an error produced inside the predicate of `all`/`exists`/
`existsOne` is HELD in the accumulator and ABSORBED if a later element drives
the accumulator to its dominant value (false for `all`, true for `exists`).

  [1, 2, 3].all(e, 6 / (2 - e) == 6)  -> false
    e=1: 6/1==6 -> true; e=2: 6/0 -> error (held); e=3: 6/-1==6 -> false.
    The error is absorbed by the definitive false -> all == false.

  [0, 'foo', 3].all(i, v, v % 2 == i)  -> false (two-var form)
    i=0,v=0: 0%2==0 -> true; i=1,v='foo': 'foo'%2 -> error (held);
    i=2,v=3: 3%2==2 -> 1==2 -> false. The error is absorbed -> false.

An error that is NOT absorbed (no later definitive value) still surfaces.
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
    if not os.path.exists(wasm) and not os.environ.get("CEL_WASM"):
        pytest.skip("wasm not built")
    return RelayCel(wasm)


# --- error absorbed -> definitive result ----------------------------------

def test_all_error_absorbed_by_false(cel):
    out = cel.eval("[1, 2, 3].all(e, 6 / (2 - e) == 6)")
    assert out["ok"] is True, out
    assert out["value"] == {"t": "bool", "v": False}, out


def test_all2_error_absorbed_by_false(cel):
    out = cel.eval("[0, 'foo', 3].all(i, v, v % 2 == i)")
    assert out["ok"] is True, out
    assert out["value"] == {"t": "bool", "v": False}, out


def test_exists_short_circuits_before_error(cel):
    # exists stops at the first true (e=2) before reaching the error at e=3.
    out = cel.eval("[1, 2, 3].exists(e, 6 / (3 - e) == 6)")
    assert out["ok"] is True, out
    assert out["value"] == {"t": "bool", "v": True}, out


# --- error NOT absorbed -> surfaces ---------------------------------------

def test_all_error_not_absorbed_surfaces(cel):
    # The only element triggers DivisionByZero and nothing drives a definitive
    # false afterward -> the error must surface.
    out = cel.eval("[2].all(e, 6 / (2 - e) > 0)")
    assert out["ok"] is False, out
    assert out.get("code") == "RELAY-CEL-004", out
    assert out.get("error") != "ENGINE_PANIC", out


def test_exists_error_not_absorbed_surfaces(cel):
    # No element is true; the error is not absorbed by a true -> surfaces.
    out = cel.eval("[2].exists(e, 6 / (2 - e) == 6)")
    assert out["ok"] is False, out
    assert out.get("code") == "RELAY-CEL-004", out


# --- regression: ordinary comprehensions unaffected -----------------------

CLEAN = [
    ("[1, 2, 3].all(e, e > 0)", {"t": "bool", "v": True}),
    ("[1, 2, 3].all(e, e > 1)", {"t": "bool", "v": False}),
    ("[1, 2, 3].exists(e, e == 2)", {"t": "bool", "v": True}),
    ("[1, 2, 3].exists(e, e == 9)", {"t": "bool", "v": False}),
    ("[1, 2, 3].exists_one(e, e == 2)", {"t": "bool", "v": True}),
    ("[1, 2, 3].map(e, e * 2)",
     {"t": "list", "v": [{"t": "int", "v": "2"}, {"t": "int", "v": "4"},
                          {"t": "int", "v": "6"}]}),
    ("[1, 2, 3].filter(e, e > 1)",
     {"t": "list", "v": [{"t": "int", "v": "2"}, {"t": "int", "v": "3"}]}),
]


@pytest.mark.parametrize("expr,value", CLEAN)
def test_clean_comprehensions_unchanged(cel, expr, value):
    out = cel.eval(expr)
    assert out["ok"] is True, (expr, out)
    assert out["value"] == value, (expr, out)
