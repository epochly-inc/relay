"""WS-B: the wasm `udf_trace` response field (VAL-CWC-P1HOST-013).

`crate/src/lib.rs` records every EXECUTED relay.* UDF's typed-canonical return
value into a thread_local `UDF_TRACE` (cleared at the start of each `eval_impl`),
then drains it into a NEW top-level response field `udf_trace` keyed per UDF name
in CALL ORDER. A short-circuited (never-evaluated) UDF branch records nothing.

These drive the SAME built wasm both hosts load via the Python loader, so the
recorded `udf_trace` IS the cross-host byte-parity contract (M1 pipeline wiring
reconstructs `udf_outputs_jcs` from it -- VAL-CWC-P1HOST-014).

Design contract the wasm MUST satisfy (determinism, or `make repro` breaks):
  - `udf_trace` is an ORDER-PRESERVING object: each key maps to a LIST of typed-
    canonical entries, one entry per execution, in call order. Across UDFs the
    insertion order is call order (we assert per-name lists; per-UDF call order
    is what `udf_outputs_jcs` reconstruction depends on).
  - The thread_local is CLEARED first in `eval_impl`, so a prior eval on the same
    thread never leaks entries into the next.
  - Recording happens in the UDF function body's return path, so a short-circuit
    `&&`/`||` branch that never calls the UDF naturally records nothing.
  - The eval RESULT `value` is UNCHANGED -- `udf_trace` is additive metadata.

tier-1 plumbing (runs against the real built wasm).
"""
import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "python"))

from relay_cel_wasm import RelayCel  # noqa: E402

C = RelayCel()


def _eval(expr, bindings=None):
    """Evaluate with the Relay profile on (the host always sets it)."""
    r = C.eval(expr, bindings, relay_profile=True)
    assert r["ok"], f"{expr} unexpectedly rejected: {r}"
    return r


# ---------------------------------------------------------------------------
# (a) a single relay.coverage(t,"s1") -> udf_trace maps relay.coverage to a
#     1-element list of the typed-canonical output.
# ---------------------------------------------------------------------------
@pytest.mark.plumbing
def test_single_coverage_records_one_typed_canonical_entry():
    r = _eval('relay.coverage({"steps": [{"name": "s1"}]}, "s1")')
    assert "udf_trace" in r, f"missing udf_trace: {r}"
    trace = r["udf_trace"]
    assert isinstance(trace, dict), trace
    assert "relay.coverage" in trace, trace
    entries = trace["relay.coverage"]
    assert isinstance(entries, list) and len(entries) == 1, entries
    # The recorded entry is the SAME typed-canonical form as the eval result.
    assert entries[0] == {"t": "bool", "v": True}, entries
    # The recorded value matches the actual eval result value (additive only).
    assert entries[0] == r["value"], r


@pytest.mark.plumbing
def test_tool_arg_records_returned_value():
    r = _eval('relay.tool_arg({"args": {"k": "v"}}, "k")')
    assert r["udf_trace"]["relay.tool_arg"] == [{"t": "string", "v": "v"}], r


@pytest.mark.plumbing
def test_schema_match_records_returned_bool():
    r = _eval('relay.schema_match("s", {"type": "string"})')
    assert r["udf_trace"]["relay.schema_match"] == [{"t": "bool", "v": True}], r


# ---------------------------------------------------------------------------
# (b) call order / multiple UDFs and repeated calls.
# ---------------------------------------------------------------------------
@pytest.mark.plumbing
def test_multiple_distinct_udfs_each_recorded():
    # Both a coverage and a tool_arg call are evaluated (&& is true on the left).
    r = _eval(
        'relay.coverage({"steps": [{"name": "a"}]}, "a") '
        '&& relay.tool_arg({"args": {"k": true}}, "k") == true'
    )
    trace = r["udf_trace"]
    assert trace["relay.coverage"] == [{"t": "bool", "v": True}], trace
    assert trace["relay.tool_arg"] == [{"t": "bool", "v": True}], trace


@pytest.mark.plumbing
def test_repeated_same_udf_records_each_call_in_order():
    # A list comprehension drives relay.coverage twice; both recorded, in order.
    r = _eval(
        '[relay.coverage({"steps": [{"name": "a"}]}, "a"), '
        ' relay.coverage({"steps": [{"name": "b"}]}, "z")]'
    )
    entries = r["udf_trace"]["relay.coverage"]
    assert entries == [{"t": "bool", "v": True}, {"t": "bool", "v": False}], entries


# ---------------------------------------------------------------------------
# (c) a short-circuited UDF records NOTHING.
# ---------------------------------------------------------------------------
@pytest.mark.plumbing
def test_short_circuited_and_records_nothing():
    # `false && relay.coverage(...)` never evaluates the right operand.
    r = _eval('false && relay.coverage({"steps": [{"name": "s1"}]}, "s1")')
    assert r["value"] == {"t": "bool", "v": False}, r
    trace = r.get("udf_trace", {})
    assert "relay.coverage" not in trace, f"short-circuited UDF must not record: {r}"


@pytest.mark.plumbing
def test_short_circuited_or_records_nothing():
    # `true || relay.coverage(...)` never evaluates the right operand.
    r = _eval('true || relay.coverage({"steps": [{"name": "s1"}]}, "s1")')
    assert r["value"] == {"t": "bool", "v": True}, r
    trace = r.get("udf_trace", {})
    assert "relay.coverage" not in trace, f"short-circuited UDF must not record: {r}"


@pytest.mark.plumbing
def test_only_taken_branch_recorded():
    # Conditional: only the executed UDF in the taken branch is recorded.
    r = _eval(
        'true ? relay.coverage({"steps": [{"name": "a"}]}, "a") '
        ': relay.coverage({"steps": [{"name": "b"}]}, "b")'
    )
    entries = r["udf_trace"]["relay.coverage"]
    assert entries == [{"t": "bool", "v": True}], entries


# ---------------------------------------------------------------------------
# (d) udf_trace is empty/absent when no relay.* UDF runs.
# ---------------------------------------------------------------------------
@pytest.mark.plumbing
def test_no_relay_udf_yields_no_trace_entries():
    r = _eval("1 + 2")
    assert r["value"] == {"t": "int", "v": "3"}, r
    # Absent, or present-but-empty -- either way, no relay.* keys.
    trace = r.get("udf_trace", {})
    assert trace == {} or all(not k.startswith("relay.") for k in trace), r


# ---------------------------------------------------------------------------
# Thread-local clearing: a prior eval must not leak into the next on the SAME
# loader handle / thread.
# ---------------------------------------------------------------------------
@pytest.mark.plumbing
def test_trace_cleared_between_evals():
    _eval('relay.coverage({"steps": [{"name": "a"}]}, "a")')
    # The next eval has no relay.* UDF; it must NOT inherit the prior entry.
    r2 = _eval("1 + 2")
    trace = r2.get("udf_trace", {})
    assert "relay.coverage" not in trace, f"trace leaked across evals: {r2}"
    # And a following coverage eval records exactly ONE entry (not two).
    r3 = _eval('relay.coverage({"steps": [{"name": "a"}]}, "a")')
    assert r3["udf_trace"]["relay.coverage"] == [{"t": "bool", "v": True}], r3
