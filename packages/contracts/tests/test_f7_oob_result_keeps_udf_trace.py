"""F7 (keystone #16): a POST-success host finiteness-guard rejection of the
RESULT value must NOT erase the real udf_trace.

Bug (pre-fix): ``WasmCelEvaluator.evaluate_with_trace`` decoded the wasm
envelope (running the host ``_check_finite`` / SAFE_INTEGER_BOUND guard on the
DECODED result value) BEFORE extracting ``udf_trace``. When a relay.* UDF
genuinely ran but the result value was out of the IEEE-754 safe range
(``abs(int) > 2**53 - 1`` -> RELAY-CEL-006 / NUMERIC-OOB), the guard raised and
the trace was never extracted; ``pipeline._evaluate_with_trace`` then set
``udf_trace = {}``, zeroing ``udf_outputs_jcs`` to ``"{}"`` and ``udfs_invoked``
to ``[]``.

The TS host (``packages/contracts-typescript/src/pipeline.ts``
``evaluateUdfOutputs``) reconstructs ``udf_outputs_jcs`` from the SAME ok:true
envelope and runs NO finiteness guard there, so it emitted the REAL non-empty
trace for the same expression. Python "{}" vs TS real-trace is a single-byte (in
fact whole-object) divergence on a CRYPTOGRAPHIC DIGEST input -- a P0 keystone-
#16 cross-host byte split / release-block.

Fix: extract ``udf_trace`` from the success envelope BEFORE the host finiteness
guard, and carry it on the raised :class:`RelayCelError` so the pipeline records
the byte-identical real ``udf_outputs`` while the outcome stays ``error``.

This test pins the Python host behavior directly; the cross-host BYTE parity for
the identical expression is pinned by the wasm golden case
``coverage_then_oob_result_keeps_trace`` in
``packages/contracts-typescript/test/fixtures/udf_outputs_jcs.golden.json``
(asserted by ``pipeline_udf_outputs_parity.test.ts``).

Spec anchors: D, B.4. CLAUDE.md keystone invariant 16 (typed-canonical
cross-host byte parity), banned pattern #16.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json

import pytest
from relay_contracts import RELAY_COVERAGE_NAME, RELAY_UDFS
from relay_contracts.dsl_parser import parse_contract
from relay_contracts.pipeline import _REQUIRED_OUTCOME_KEYS, evaluate_assertion

# 2**53 == 9007199254740992 is the first integer magnitude OUTSIDE the IEEE-754
# safe range [-(2**53 - 1), 2**53 - 1] (SAFE_INTEGER_BOUND == 2**53 - 1), so the
# host _check_finite rejects it with RELAY-CEL-006 / NUMERIC-OOB.
_OOB_INT = 9007199254740992

# relay.coverage(t, "alpha") is TRUE for this binding (a "alpha" step exists), so
# the ternary takes the OOB branch: the UDF RUNS (recorded in udf_trace) AND the
# result value fails the finiteness guard.
_F7_EXPRESSION = f'relay.coverage(t, "alpha") ? {_OOB_INT} : 0'
_F7_BINDINGS = {"t": {"steps": [{"name": "alpha"}, {"name": "beta"}]}}


def _doc(expression: str) -> dict[str, object]:
    return {
        "schema_version": "relay.assertion.behavioral.v1",
        "assertion_id": "VAL-F7-OOB-TRACE",
        "kind": "behavioral",
        "expression": expression,
        "severity": "p0",
        "owner_email": "test@example.com",
        "lifecycle_state": "active",
    }


@pytest.mark.plumbing
def test_oob_result_keeps_real_udf_trace() -> None:
    """A relay.coverage call whose ternary result is out-of-safe-range yields
    outcome=error but RETAINS the real udf_trace (non-empty udf_outputs_jcs).

    Pre-fix RED: udf_outputs_jcs == "{}" and udfs_invoked == [] (the guard
    rejection zeroed the trace before it was extracted)."""
    parsed = parse_contract(_doc(_F7_EXPRESSION))

    envelope = evaluate_assertion(
        parsed, bindings=_F7_BINDINGS, extra_udfs=RELAY_UDFS
    )

    # All six outcome-envelope keys are still bound (the error path does NOT
    # short-circuit the contract).
    for key in _REQUIRED_OUTCOME_KEYS:
        assert key in envelope, f"missing required key {key!r}"

    # The result value failed the finiteness guard -> outcome error (NOT pass).
    assert envelope["outcome"] == "error", envelope["outcome"]

    # The UDF genuinely ran, so its trace is REAL evidence that survives the
    # post-success result rejection.
    assert envelope["udfs_invoked"] == [RELAY_COVERAGE_NAME], envelope[
        "udfs_invoked"
    ]

    # udf_outputs_jcs is the real non-empty trace -- NOT the zeroed "{}".
    assert envelope["udf_outputs_jcs"] != "{}", envelope["udf_outputs_jcs"]
    outputs = json.loads(envelope["udf_outputs_jcs"])
    assert outputs == {
        RELAY_COVERAGE_NAME: [{"t": "bool", "v": True}]
    }, outputs


@pytest.mark.plumbing
def test_oob_result_udf_outputs_jcs_is_byte_stable() -> None:
    """The retained trace canonicalizes to the EXACT bytes the TS host emits for
    the same expression (the cross-host digest input, keystone #16).

    The byte string is pinned here AND in the wasm golden
    (coverage_then_oob_result_keeps_trace) so a regression in either host is
    caught on BOTH sides."""
    parsed = parse_contract(_doc(_F7_EXPRESSION))

    envelope = evaluate_assertion(
        parsed, bindings=_F7_BINDINGS, extra_udfs=RELAY_UDFS
    )

    # Byte-for-byte: the JCS-canonical per-name typed-value list. This is the
    # exact string the TS golden pins (no whitespace, sorted keys, "t" before
    # "v").
    assert (
        envelope["udf_outputs_jcs"]
        == '{"relay.coverage":[{"t":"bool","v":true}]}'
    ), envelope["udf_outputs_jcs"]


@pytest.mark.plumbing
def test_short_circuited_oob_udf_is_not_recorded() -> None:
    """A relay.* call in a SHORT-CIRCUITED branch is NOT recorded even when the
    taken branch is itself out-of-safe-range.

    Confirms the F7 fix did not start recording un-run UDFs: when the coverage
    call is gated out by a leading ``false &&`` the result is the bare OOB int,
    which still fails the finiteness guard (outcome=error), but NO UDF ran so the
    trace stays empty -- the carried trace is the empty dict, byte-identical to
    the pre-fix empty object."""
    # ``false && relay.coverage(...)`` short-circuits to false; the ternary then
    # takes the OOB branch. The coverage UDF is never executed.
    expression = f'(false && relay.coverage(t, "alpha")) ? 0 : {_OOB_INT}'
    parsed = parse_contract(_doc(expression))

    envelope = evaluate_assertion(
        parsed, bindings=_F7_BINDINGS, extra_udfs=RELAY_UDFS
    )

    assert envelope["outcome"] == "error", envelope["outcome"]
    # No UDF executed -> empty trace -> empty JCS object.
    assert envelope["udfs_invoked"] == [], envelope["udfs_invoked"]
    assert envelope["udf_outputs_jcs"] == "{}", envelope["udf_outputs_jcs"]
