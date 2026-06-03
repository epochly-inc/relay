"""Tier-1 plumbing tests for the timestamp/duration getter residuals closed in
the fork-cleanup increment, driven through the actual wasm via the loader.

Covers (against the cel-go oracle / cel-spec timestamps.textproto ground truth):

  Timezone-aware timestamp getters: getFullYear/getMonth/getDayOfMonth/getDate/
  getDayOfWeek/getDayOfYear/getHours/getMinutes/getSeconds/getMilliseconds all
  accept an OPTIONAL timezone string argument. The timezone may be:
    - an IANA name ('Australia/Sydney', 'America/St_Johns', 'Asia/Kathmandu')
    - a fixed offset ('+11:00', '-02:30', '02:00')
  The UTC instant is shifted into that zone before the field is read.

  getMilliseconds() on a DURATION returns the milliseconds COMPONENT of the
  sub-second part (321 for 123.321456789s), NOT the total milliseconds.
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


# --- timezone-aware getters (exact cel-spec corpus cases) -----------------

TZ_GETTERS = [
    ("timestamp('2009-02-13T23:31:30Z').getDate('Australia/Sydney')", "14"),
    ("timestamp('2009-02-13T23:31:30Z').getDayOfMonth('+11:00')", "13"),
    ("timestamp('2009-02-13T02:00:00Z').getDayOfMonth('-02:30')", "11"),
    ("timestamp('2009-02-13T02:00:00Z').getDayOfMonth('America/St_Johns')", "11"),
    ("timestamp('2009-02-13T23:31:30Z').getHours('02:00')", "1"),
    ("timestamp('2009-02-13T23:31:30Z').getMinutes('Asia/Kathmandu')", "16"),
]


@pytest.mark.parametrize("expr,v", TZ_GETTERS)
def test_timezone_getters(cel, expr, v):
    out = cel.eval(expr)
    assert out["ok"] is True, (expr, out)
    assert out["value"] == {"t": "int", "v": v}, (expr, out)


# --- no-arg getters must keep UTC semantics (no regression) ---------------

UTC_GETTERS = [
    ("timestamp('2009-02-13T23:31:30Z').getFullYear()", "2009"),
    ("timestamp('2009-02-13T23:31:30Z').getMonth()", "1"),       # 0-based -> Feb
    ("timestamp('2009-02-13T23:31:30Z').getDate()", "13"),
    ("timestamp('2009-02-13T23:31:30Z').getDayOfMonth()", "12"),  # 0-based
    ("timestamp('2009-02-13T23:31:30Z').getHours()", "23"),
    ("timestamp('2009-02-13T23:31:30Z').getMinutes()", "31"),
    ("timestamp('2009-02-13T23:31:30Z').getSeconds()", "30"),
]


@pytest.mark.parametrize("expr,v", UTC_GETTERS)
def test_utc_getters_unchanged(cel, expr, v):
    out = cel.eval(expr)
    assert out["ok"] is True, (expr, out)
    assert out["value"] == {"t": "int", "v": v}, (expr, out)


# --- getMilliseconds component for duration -------------------------------

def test_duration_get_milliseconds_component(cel):
    out = cel.eval("x.getMilliseconds()", {"x": {"t": "duration", "v": "123.321456789"}})
    assert out["ok"] is True, out
    assert out["value"] == {"t": "int", "v": "321"}, out


def test_timestamp_get_milliseconds_subsec(cel):
    out = cel.eval(
        "timestamp('2009-02-13T23:31:20.123456789Z').getMilliseconds()"
    )
    assert out["ok"] is True, out
    assert out["value"] == {"t": "int", "v": "123"}, out


# --- bad timezone errors ---------------------------------------------------

def test_bad_timezone_errors(cel):
    out = cel.eval("timestamp('2009-02-13T23:31:30Z').getHours('Not/AZone')")
    assert out["ok"] is False, out
    assert out.get("code") == "RELAY-CEL-004", out
