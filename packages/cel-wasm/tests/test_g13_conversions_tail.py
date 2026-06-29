"""Tier-1 plumbing tests for the conversions/temporal residual tail closed in
the fork-cleanup increment, driven through the actual wasm via the loader.

Covers three wrapper-side conversion gaps that the cel-go oracle / cel-spec
conversions.textproto + timestamps.textproto ground truth require:

  bool() builtin (cel 0.13 leaves `bool` UndeclaredReference)
    - bool(string): "1","t","true","TRUE","True" -> true;
                    "0","f","false","FALSE","False" -> false;
                    any other string (incl. mixed case 'TrUe') -> error.
    - bool(bool): identity.

  timestamp(int) -> epoch SECONDS (cel-go conversion overload); idempotent
  timestamp(timestamp) already covered by G12. Closes
  `timestamp(timestamp(1000000000)) == timestamp(1000000000)` and
  `dyn(timestamp(0)) == null`.

  string(bytes) over INVALID utf-8 must ERROR (cel-go:
  "invalid UTF-8 in bytes, cannot convert to string"), not lossily replace.
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


# --- bool() builtin -------------------------------------------------------

BOOL_TRUE = ["bool('1')", "bool('t')", "bool('true')", "bool('TRUE')",
             "bool('True')", "bool(true)"]
BOOL_FALSE = ["bool('0')", "bool('f')", "bool('false')", "bool('FALSE')",
              "bool('False')", "bool(false)"]
BOOL_ERROR = ["bool('TrUe')", "bool('FaLsE')", "bool('yes')", "bool('')",
              "bool('2')"]


@pytest.mark.parametrize("expr", BOOL_TRUE)
def test_bool_true(cel, expr):
    out = cel.eval(expr)
    assert out["ok"] is True, (expr, out)
    assert out["value"] == {"t": "bool", "v": True}, (expr, out)


@pytest.mark.parametrize("expr", BOOL_FALSE)
def test_bool_false(cel, expr):
    out = cel.eval(expr)
    assert out["ok"] is True, (expr, out)
    assert out["value"] == {"t": "bool", "v": False}, (expr, out)


@pytest.mark.parametrize("expr", BOOL_ERROR)
def test_bool_bad_string_errors(cel, expr):
    out = cel.eval(expr)
    assert out["ok"] is False, (expr, out)
    assert out.get("code") == "RELAY-CEL-004", (expr, out)
    assert out.get("error") != "ENGINE_PANIC", (expr, out)


# --- timestamp(int) epoch seconds -----------------------------------------

def test_timestamp_from_int(cel):
    out = cel.eval("timestamp(1000000000)")
    assert out["ok"] is True, out
    assert out["value"] == {"t": "timestamp", "v": "2001-09-09T01:46:40Z"}, out


def test_timestamp_from_zero(cel):
    out = cel.eval("timestamp(0)")
    assert out["ok"] is True, out
    assert out["value"] == {"t": "timestamp", "v": "1970-01-01T00:00:00Z"}, out


def test_timestamp_int_roundtrip_eq(cel):
    out = cel.eval("timestamp(timestamp(1000000000)) == timestamp(1000000000)")
    assert out["ok"] is True, out
    assert out["value"] == {"t": "bool", "v": True}, out


def test_dyn_timestamp_zero_ne_null(cel):
    out = cel.eval("dyn(timestamp(0)) == null")
    assert out["ok"] is True, out
    assert out["value"] == {"t": "bool", "v": False}, out


# --- string(bytes) invalid utf-8 errors -----------------------------------

def test_string_invalid_utf8_bytes_errors(cel):
    out = cel.eval(r"string(b'\000\xff')")
    assert out["ok"] is False, out
    assert out.get("code") == "RELAY-CEL-004", out


def test_string_valid_utf8_bytes_ok(cel):
    out = cel.eval("string(b'abc')")
    assert out["ok"] is True, out
    assert out["value"] == {"t": "string", "v": "abc"}, out
