"""Tier-1 plumbing tests for the WS2 conversion shims (G10 + G13), driven
through the actual wasm via the Python loader.

G10 -- int()/uint() must ERROR on an out-of-range / not-exactly-representable
double argument, matching the cel-spec conversions.textproto ground truth and
cel-go's checked conversions (common/types/overflow.go):

    doubleToInt64Checked errors when:
        IsInf || IsNaN || v <= float64(MinInt64) || v >= float64(MaxInt64)
    doubleToUint64Checked errors when:
        IsInf || IsNaN || v < 0 || v >= 2**64

    The boundary cases that cel-rust 0.13 wrongly CLAMPED instead of erroring:
      int(9223372036854775807.0)   -> error ("range") -- the f64 is 2**63
      int(-9223372036854775808.0)  -> error ("range") -- the f64 is -2**63
      int(1e99)                    -> error ("range")
      int(18446744073709551615.0)  -> error ("range") -- the f64 is 2**64
      uint(6.022e23)               -> error ("range")
      uint(-1.0)                   -> error (negative)

    The in-range cases that MUST still produce values (no false positives):
      int(1.9) -> 1, int(-7.9) -> -7, int(-123.456) -> -123, int(11.5) -> 11
      int(double(36028797018963968)) -> 36028797018963968  (2**55, in range)
      uint(3.14159265) -> 3, uint(25.5) -> 25
      int('987') -> 987, uint('300') -> 300   (string parse path unchanged)

G13 -- int(timestamp) returns the Unix epoch SECONDS as an int:
      int(timestamp('1970-01-01T00:00:01Z'))  -> 1
      int(timestamp('2004-09-16T23:59:59Z'))  -> 1095379199

Run:  pytest packages/cel-wasm/tests -v
(requires the wasm built: cargo build --release --target wasm32-unknown-unknown)
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
            _HERE,
            "..",
            "crate",
            "target",
            "wasm32-unknown-unknown",
            "release",
            "relay_cel_wasm.wasm",
        )
    )
    if not os.path.exists(wasm):
        pytest.skip(
            "wasm not built: run "
            "`cargo build --release --target wasm32-unknown-unknown` "
            "in packages/cel-wasm/crate"
        )
    return RelayCel(wasm)


# --------------------------------------------------------------------------
# G10: int(double) / uint(double) must ERROR out of range, not clamp.
# --------------------------------------------------------------------------

INT_DOUBLE_RANGE_ERRORS = [
    "int(9223372036854775807.0)",   # f64 == 2**63 -> >= MaxInt64 (as f64) -> error
    "int(-9223372036854775808.0)",  # f64 == -2**63 -> <= MinInt64 (as f64) -> error
    "int(1e99)",                    # far above range
    "int(-1e99)",                   # far below range
    "int(18446744073709551615.0)",  # f64 == 2**64 -> above int range
    "int(9.3e18)",                  # 9.3e18 > 2**63-1, above range
]

UINT_DOUBLE_RANGE_ERRORS = [
    "uint(6.022e23)",   # far above uint range
    "uint(1e99)",       # far above
    "uint(-1.0)",       # negative -> error
    "uint(-0.5)",       # negative fractional -> error
    "uint(18446744073709551616.0)",  # f64 == 2**64 -> >= 2**64 -> error
]


@pytest.mark.parametrize("expr", INT_DOUBLE_RANGE_ERRORS)
def test_int_double_out_of_range_errors(cel, expr):
    out = cel.eval(expr)
    assert out["ok"] is False, f"{expr!r} must ERROR (range), got {out!r}"
    # Reuse the crate's existing runtime-exec error envelope, not a new code.
    assert out.get("code") == "RELAY-CEL-004", f"{expr!r} -> {out!r}"
    assert out.get("error") != "ENGINE_PANIC", f"{expr!r} TRAPPED: {out!r}"


@pytest.mark.parametrize("expr", UINT_DOUBLE_RANGE_ERRORS)
def test_uint_double_out_of_range_errors(cel, expr):
    out = cel.eval(expr)
    assert out["ok"] is False, f"{expr!r} must ERROR (range), got {out!r}"
    assert out.get("code") == "RELAY-CEL-004", f"{expr!r} -> {out!r}"
    assert out.get("error") != "ENGINE_PANIC", f"{expr!r} TRAPPED: {out!r}"


# In-range doubles must still convert (no false positives from the new check).
INT_DOUBLE_OK = [
    ("int(1.9)", "1"),
    ("int(-7.9)", "-7"),
    ("int(-123.456)", "-123"),
    ("int(11.5)", "11"),
    ("int(-3.5)", "-3"),
    ("int(0.0)", "0"),
    ("int(double(36028797018963968))", "36028797018963968"),  # 2**55, in range
]

UINT_DOUBLE_OK = [
    ("uint(3.14159265)", "3"),
    ("uint(1.9)", "1"),
    ("uint(25.5)", "25"),
    ("uint(0.0)", "0"),
    ("uint(double(36028797018963968u))", "36028797018963968"),  # 2**55, in range
]


@pytest.mark.parametrize("expr,v", INT_DOUBLE_OK)
def test_int_double_in_range_ok(cel, expr, v):
    out = cel.eval(expr)
    assert out["ok"] is True, f"{expr!r} must convert, got {out!r}"
    assert out["value"] == {"t": "int", "v": v}, (expr, out)


@pytest.mark.parametrize("expr,v", UINT_DOUBLE_OK)
def test_uint_double_in_range_ok(cel, expr, v):
    out = cel.eval(expr)
    assert out["ok"] is True, f"{expr!r} must convert, got {out!r}"
    assert out["value"] == {"t": "uint", "v": v}, (expr, out)


# Non-double conversion paths must keep cel 0.13 behavior (no regression).
NON_DOUBLE_OK = [
    ("int('987')", {"t": "int", "v": "987"}),
    ("int(-42)", {"t": "int", "v": "-42"}),
    ("int(42u)", {"t": "int", "v": "42"}),
    ("uint('300')", {"t": "uint", "v": "300"}),
    ("uint(7)", {"t": "uint", "v": "7"}),
    ("uint(7u)", {"t": "uint", "v": "7"}),
]


@pytest.mark.parametrize("expr,value", NON_DOUBLE_OK)
def test_non_double_conversions_unchanged(cel, expr, value):
    out = cel.eval(expr)
    assert out["ok"] is True, f"{expr!r} -> {out!r}"
    assert out["value"] == value, (expr, out)


# Non-numeric string still errors via the stock string-parse path.
def test_int_bad_string_still_errors(cel):
    out = cel.eval("int('not-a-number')")
    assert out["ok"] is False, out
    assert out.get("code") == "RELAY-CEL-004", out


def test_uint_int_negative_overflow_unchanged(cel):
    # uint(-1) (int arg, not double) -> stock cel try_into overflow error.
    out = cel.eval("uint(-1)")
    assert out["ok"] is False, out
    assert out.get("code") == "RELAY-CEL-004", out


# --------------------------------------------------------------------------
# G13: int(timestamp) -> Unix epoch seconds.
# --------------------------------------------------------------------------

INT_TIMESTAMP = [
    ("int(timestamp('1970-01-01T00:00:01Z'))", "1"),
    ("int(timestamp('1970-01-01T00:00:00Z'))", "0"),
    ("int(timestamp('2004-09-16T23:59:59Z'))", "1095379199"),
    ("int(timestamp('2009-02-13T23:31:30Z'))", "1234567890"),
    ("int(timestamp('1969-12-31T23:59:59Z'))", "-1"),  # before epoch
]


@pytest.mark.parametrize("expr,v", INT_TIMESTAMP)
def test_int_timestamp_epoch_seconds(cel, expr, v):
    out = cel.eval(expr)
    assert out["ok"] is True, f"{expr!r} -> {out!r}"
    assert out["value"] == {"t": "int", "v": v}, (expr, out)
