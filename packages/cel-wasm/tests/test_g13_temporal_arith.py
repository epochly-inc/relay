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
    if not os.path.exists(wasm) and not os.environ.get("CEL_WASM"):
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


# --- crate-1 (audit): negative sub-second duration must keep its sign --------
# A timestamp difference in the open interval (-1s, 0s) yields a negative
# sub-second duration. num_seconds() truncates toward zero (== 0 here), so the
# sign lived ONLY in the dropped nanos magnitude: the serializer emitted
# "0.500000000" (a POSITIVE half-second) and the deserializer read "-0.5" back
# as +0.5s. Both the value_to_typed serializer and split_secs_nanos deserializer
# are fixed to carry the sign over the whole open interval.

def test_negative_subsecond_duration_serializes_with_sign(cel):
    # b - a = -0.5s (b is 0.5s before a). secs truncates to 0; the sign must
    # survive on the serialized bytes.
    out = cel.eval(
        "timestamp('2020-01-01T00:00:00Z') - timestamp('2020-01-01T00:00:00.5Z')"
    )
    assert out["ok"] is True, out
    assert out["value"] == {"t": "duration", "v": "-0.500000000"}, out


def test_negative_whole_plus_subsecond_duration_sign(cel):
    # -1.5s already worked (secs=-1 carried the sign); regression guard that the
    # serializer fix keeps the sub-1s tail correct for the whole-second case too.
    out = cel.eval(
        "timestamp('2020-01-01T00:00:00Z') - timestamp('2020-01-01T00:00:01.5Z')"
    )
    assert out["ok"] is True, out
    assert out["value"] == {"t": "duration", "v": "-1.500000000"}, out


def test_negative_subsecond_duration_binding_deserializes_signed(cel):
    # The deserializer must read "-0.500000000" as a NEGATIVE half-second, so it
    # compares below the zero duration. Before the fix "-0" parsed to secs=0 and
    # the sign was lost -> the binding silently became +0.5s.
    out = cel.eval(
        "d < duration('0s')",
        {"d": {"t": "duration", "v": "-0.500000000"}},
    )
    assert out["ok"] is True, out
    assert out["value"] == {"t": "bool", "v": True}, out


def test_negative_subsecond_duration_roundtrips(cel):
    # Full round-trip through deserializer + serializer: bind -0.5s, echo it.
    out = cel.eval("d", {"d": {"t": "duration", "v": "-0.500000000"}})
    assert out["ok"] is True, out
    assert out["value"] == {"t": "duration", "v": "-0.500000000"}, out


# --- vendor-1 (audit): timestamp +/- a huge duration BINDING must not PANIC --
# The duration() builtin caps at ~292y (i64 nanoseconds), but a host duration
# BINDING carries a chrono::Duration with a much wider second-count. timestamp
# arithmetic with it must return a clean RELAY-CEL-004 Overflow, not trap the
# wasm reactor (RELAY-CEL-PANIC) via chrono's panicking Add/Sub.
_HUGE_DUR = {"t": "duration", "v": "9000000000000000.000000000"}  # ~285M years
_TS = {"t": "timestamp", "v": "2020-01-01T00:00:00Z"}


@pytest.mark.parametrize("expr", ["t + d", "d + t", "t - d"])
def test_timestamp_huge_duration_binding_no_panic(cel, expr):
    out = cel.eval(expr, {"t": _TS, "d": _HUGE_DUR}, relay_profile=True)
    assert out["ok"] is False, (expr, out)
    assert out.get("error") != "ENGINE_PANIC", (expr, out)
    assert out.get("code") == "RELAY-CEL-004", (expr, out)


# Regression guard (roborev 8b9bf96): the duration serializer must NOT corrupt a
# duration whose magnitude exceeds i64 NANOSECONDS (~292y). num_nanoseconds()
# returns None there, so deriving the value from it + a saturating fallback would
# clamp a huge host binding (9e15 s) to the i64-nanosecond ceiling
# (9223372036.854775807). The serializer keys on num_seconds() for the bulk, so a
# huge duration BINDING (enabled by the vendor-1 checked-arith fix) round-trips
# with its FULL second count, both signs.
@pytest.mark.parametrize(
    "wire",
    ["9000000000000000.000000000", "-9000000000000000.000000000"],
)
def test_huge_duration_binding_roundtrips_without_saturation(cel, wire):
    out = cel.eval("d", {"d": {"t": "duration", "v": wire}})
    assert out["ok"] is True, (wire, out)
    assert out["value"] == {"t": "duration", "v": wire}, (wire, out)


# Regression guard (audit round-2): the duration BINDING DESERIALIZER must not
# PANIC the wasm reactor on a wire string beyond chrono's representable TimeDelta
# range. split_secs_nanos does NO range check, so reconstructing via chrono's
# panicking Duration::seconds() + `+` traps on a boundary value -- contradicting
# the no-ENGINE_PANIC contract the arithmetic path holds. The CHECKED builder
# returns a clean RELAY-CEL-006 bad-binding error instead (the bindings loop maps
# a typed_to_value Err to codes::REQUEST).
# chrono 0.4.44 TimeDelta is SYMMETRIC: MIN = -9223372036854775.807s, MAX =
# +9223372036854775.807s (verified empirically against the built wasm). One
# millisecond past either bound is out of range and must be rejected -- a clean
# RELAY-CEL-006 bad-binding, never an ENGINE_PANIC.
_DUR_BINDING_OUT_OF_RANGE = [
    "9223372036854775.808000000",  # one ms ABOVE chrono MAX (+...807s)
    "9223372036854776.000000000",  # secs above MAX.secs
    "-9223372036854775.808000000",  # one ms BELOW chrono MIN (-...807s)
    "-9223372036854775.809000000",  # further below chrono MIN
    "-9223372036854776.000000000",  # secs below MIN.secs
]


@pytest.mark.parametrize("wire", _DUR_BINDING_OUT_OF_RANGE)
def test_duration_binding_out_of_range_no_panic(cel, wire):
    out = cel.eval("d", {"d": {"t": "duration", "v": wire}})
    assert out["ok"] is False, (wire, out)
    assert out.get("error") != "ENGINE_PANIC", (wire, out)
    assert out.get("code") == "RELAY-CEL-006", (wire, out)


@pytest.mark.parametrize(
    "wire",
    [
        "9223372036854775.807000000",  # exact chrono TimeDelta::MAX
        "-9223372036854775.807000000",  # exact chrono TimeDelta::MIN (symmetric)
    ],
)
def test_duration_binding_exact_chrono_boundary_round_trips(cel, wire):
    # The exact chrono TimeDelta::MAX / MIN (+/-9223372036854775.807s) are IN range
    # and must round-trip -- the checked builder must not over-reject the boundary
    # itself. One ms past either bound is rejected (see _DUR_BINDING_OUT_OF_RANGE).
    out = cel.eval("d", {"d": {"t": "duration", "v": wire}})
    assert out["ok"] is True, (wire, out)
    assert out["value"] == {"t": "duration", "v": wire}, (wire, out)


def test_string_of_huge_duration_binding_no_saturation(cel):
    # string(d) formats via format_duration_go, which (like the value_to_typed
    # serializer crate-1 fixed) must derive seconds from num_seconds() -- NOT
    # num_nanoseconds(), which overflows i64 beyond ~292y and would SATURATE a
    # huge accepted binding (9e15 s) to ~292 years (9223372036.854775807s)
    # instead of the real value (roborev f2359b2, MED).
    out = cel.eval(
        "string(d)", {"d": {"t": "duration", "v": "9000000000000000.000000000"}}
    )
    assert out["ok"] is True, out
    assert out["value"] == {"t": "string", "v": "9000000000000000s"}, out


def test_string_of_negative_subsecond_duration_sign(cel):
    # Regression guard: string() of a negative sub-second duration keeps its sign
    # and trims trailing zeros (cel-go form): -0.5s -> "-0.5s" (not "0.5s"). This
    # already worked (the value is in i64-nanos range); the format_duration_go fix
    # must preserve it.
    out = cel.eval(
        "string(t1 - t2)",
        {
            "t1": {"t": "timestamp", "v": "2020-01-01T00:00:00Z"},
            "t2": {"t": "timestamp", "v": "2020-01-01T00:00:00.5Z"},
        },
    )
    assert out["ok"] is True, out
    assert out["value"] == {"t": "string", "v": "-0.5s"}, out


def test_max_magnitude_negative_subsecond_duration(cel):
    # The most adversarial sub-second value: secs == 0 with the MAXIMUM nanos
    # magnitude (-0.999999999s) -- the nanosecond-domain boundary where an
    # off-by-one in the "{abs_nanos:09}" zero-padding or the unsigned_abs()/sign
    # logic would surface. The host codec test (test_wasm_codec.py) caps at
    # -0.999999s because datetime.timedelta is microsecond-resolution, so only the
    # wasm level can pin the full nanosecond -0.999999999s. Without the crate-1
    # sign fix this serialized as the POSITIVE "0.999999999".
    out = cel.eval(
        "timestamp('2020-01-01T00:00:00.000000001Z') - "
        "timestamp('2020-01-01T00:00:01Z')"
    )
    assert out["ok"] is True, out
    assert out["value"] == {"t": "duration", "v": "-0.999999999"}, out
    # The same value as a BINDING round-trips byte-identically (deserialize then
    # serialize), exercising split_secs_nanos' sign at the max-nanos magnitude.
    rt = cel.eval("d", {"d": {"t": "duration", "v": "-0.999999999"}})
    assert rt["ok"] is True, rt
    assert rt["value"] == {"t": "duration", "v": "-0.999999999"}, rt
