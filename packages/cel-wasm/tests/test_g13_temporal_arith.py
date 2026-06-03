"""Tier-1 plumbing tests for G13 timestamp/duration BINARY arithmetic + the
remaining temporal residuals, driven through the actual wasm via the loader.

Closes the fork-side timestamp/duration tail against the cel-go oracle /
cel-spec timestamps.textproto ground truth:

  duration + timestamp (the commutative sibling of timestamp + duration, which
    the fork already handled): cel-go's add_duration_timestamp overload.
  duration + duration / duration - duration already worked; re-asserted here.
  timestamp - timestamp -> duration, but the result must fit in the int64-nanos
    duration range or ERROR (the 10000-year span overflows).
  timestamp(string) below the MIN ('0001-01-01') or above MAX
    ('9999-12-31T23:59:59.999999999') must ERROR (year 0 is out of range).
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


# --- binary arithmetic: bool results --------------------------------------

ARITH_TRUE = [
    # duration + timestamp (the missing commutative direction)
    "duration('120s') + timestamp('2009-02-13T23:01:00Z') == "
    "timestamp('2009-02-13T23:03:00Z')",
    # timestamp + duration (already worked; guard against regression)
    "timestamp('2009-02-13T23:00:00Z') + duration('240s') == "
    "timestamp('2009-02-13T23:04:00Z')",
    # timestamp - duration
    "timestamp('2009-02-13T23:04:00Z') - duration('240s') == "
    "timestamp('2009-02-13T23:00:00Z')",
    # timestamp - timestamp -> duration
    "timestamp('2009-02-13T23:04:00Z') - timestamp('2009-02-13T23:00:00Z') == "
    "duration('240s')",
    # duration + duration
    "duration('60s') + duration('60s') == duration('120s')",
    # duration - duration
    "duration('120s') - duration('40s') == duration('80s')",
]


@pytest.mark.parametrize("expr", ARITH_TRUE)
def test_temporal_arith_true(cel, expr):
    out = cel.eval(expr)
    assert out["ok"] is True, (expr, out)
    assert out["value"] == {"t": "bool", "v": True}, (expr, out)


# --- direct (non-eq) arithmetic shapes ------------------------------------

def test_duration_plus_timestamp_value(cel):
    out = cel.eval("duration('120s') + timestamp('2009-02-13T23:01:00Z')")
    assert out["ok"] is True, out
    assert out["value"] == {"t": "timestamp", "v": "2009-02-13T23:03:00Z"}, out


def test_timestamp_minus_timestamp_duration(cel):
    out = cel.eval(
        "timestamp('2009-02-13T23:04:00Z') - timestamp('2009-02-13T23:00:00Z')"
    )
    assert out["ok"] is True, out
    assert out["value"] == {"t": "duration", "v": "240.000000000"}, out


# --- overflow / range errors ----------------------------------------------

OVERFLOW_ERRORS = [
    # 10000-year span: the resulting duration exceeds int64 nanoseconds.
    "timestamp('9999-12-31T23:59:59Z') - timestamp('0001-01-01T00:00:00Z')",
    "timestamp('0001-01-01T00:00:00Z') - timestamp('9999-12-31T23:59:59Z')",
    # year 0 is below the timestamp MIN.
    "timestamp('0000-01-01T00:00:00Z')",
]


@pytest.mark.parametrize("expr", OVERFLOW_ERRORS)
def test_temporal_overflow_errors(cel, expr):
    out = cel.eval(expr)
    assert out["ok"] is False, (expr, out)
    assert out.get("code") == "RELAY-CEL-004", (expr, out)
    assert out.get("error") != "ENGINE_PANIC", (expr, out)


# add-duration overflow past the timestamp MAX must error (already in fork).
def test_add_duration_past_max_errors(cel):
    out = cel.eval("timestamp('9999-12-31T23:59:59Z') + duration('86400s')")
    assert out["ok"] is False, out
    assert out.get("code") == "RELAY-CEL-004", out
