"""Tier-1 plumbing tests for the integer_math + lists residuals closed in the
fork-cleanup increment, driven through the actual wasm via the loader.

Against the cel-go oracle / cel-spec ground truth:

  integer_math.textproto:
    - unary_minus_not_bool: `-false` is a TYPE ERROR (cel-go has no negate(bool)
      overload), not logical negation.
    - int64_min_negate: `-(-9223372036854775808)` OVERFLOWS i64 (no +2**63);
      cel-go errors.

  lists.textproto:
    - zero_based_double: an integral DOUBLE index is valid (`[7,8,9][dyn(0.0)]`
      -> 7). A non-integral double (0.5) is an error.
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


# --- integer_math: unary minus errors -------------------------------------

def test_negate_bool_errors(cel):
    out = cel.eval("-false")
    assert out["ok"] is False, out
    assert out.get("code") == "RELAY-CEL-004", out
    assert out.get("error") != "ENGINE_PANIC", out


def test_negate_true_errors(cel):
    out = cel.eval("-true")
    assert out["ok"] is False, out
    assert out.get("code") == "RELAY-CEL-004", out


def test_negate_int64_min_overflows(cel):
    out = cel.eval("-(-9223372036854775808)")
    assert out["ok"] is False, out
    assert out.get("code") == "RELAY-CEL-004", out
    assert out.get("error") != "ENGINE_PANIC", out


# --- regression: ordinary negation still works ----------------------------

NEGATE_OK = [
    ("-5", {"t": "int", "v": "-5"}),
    ("-(-5)", {"t": "int", "v": "5"}),
    ("--19", {"t": "int", "v": "19"}),
    ("-1.5", {"t": "double", "v": "-1.5"}),
    ("-(-9223372036854775807)", {"t": "int", "v": "9223372036854775807"}),
]


@pytest.mark.parametrize("expr,value", NEGATE_OK)
def test_negate_ok(cel, expr, value):
    out = cel.eval(expr)
    assert out["ok"] is True, (expr, out)
    assert out["value"] == value, (expr, out)


def test_logical_not_unchanged(cel):
    # The `!` operator must still work (uses the inherent Bool::negate).
    assert cel.eval("!false")["value"] == {"t": "bool", "v": True}
    assert cel.eval("!true")["value"] == {"t": "bool", "v": False}
    assert cel.eval("!!true")["value"] == {"t": "bool", "v": True}


# --- lists: integral double index -----------------------------------------

def test_double_index_integral(cel):
    out = cel.eval("[7, 8, 9][dyn(0.0)]")
    assert out["ok"] is True, out
    assert out["value"] == {"t": "int", "v": "7"}, out


def test_double_index_integral_nonzero(cel):
    out = cel.eval("[7, 8, 9][dyn(2.0)]")
    assert out["ok"] is True, out
    assert out["value"] == {"t": "int", "v": "9"}, out


def test_double_index_non_integral_errors(cel):
    out = cel.eval("[7, 8, 9][dyn(0.5)]")
    assert out["ok"] is False, out
    assert out.get("code") == "RELAY-CEL-004", out


def test_int_index_unchanged(cel):
    out = cel.eval("[7, 8, 9][1]")
    assert out["ok"] is True, out
    assert out["value"] == {"t": "int", "v": "8"}, out
