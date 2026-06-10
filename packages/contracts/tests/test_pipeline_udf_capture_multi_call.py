"""Round-3 P1 fix #3 (ported to the single wasm engine at M6 WS-I):
pipeline UDF capture records EVERY invocation.

Per the pre-fix code at ``packages/contracts/src/relay_contracts/pipeline.py``
the UDF capture stored only the LAST return value when the same UDF was
invoked multiple times in one CEL expression, losing the forensic trail. The
fix made the capture a list-of-results in CEL-evaluation order.

M6 WS-I (VAL-CWC-P1HOST-016 / ADR Revisions section 4): the caller-supplied
custom-UDF capture was a LEGACY-engine capability -- the wasm engine hosts
only the 3 native ``relay.*`` UDFs and has no registration slot, so
``evaluate_assertion`` / ``publish_contract`` with a custom ``my_check`` UDF
MUST raise :class:`RelayCelUnsupportedUdfError` (RELAY-CEL-004 /
RELAY-CEL-UDF-UNREGISTERED) fail-closed rather than capture. The multi-call
forensic contract itself SURVIVES on the native relay.* UDFs: the engine's
``udf_trace`` records every invocation in call order, and the envelope's
``udf_outputs_jcs`` carries them all (VAL-CWC-P6REMOVE-003: the ran-set comes
from ``udf_trace`` keys, no host AST walk).

Spec anchors: D, B.4 (closed evidence envelope).
CLAUDE.md anchors: keystone invariant 2 (pass without evidence is not a
pass -- "pass" must include the full forensic trail, not just the last
call).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json

import pytest
from relay_contracts import register_udf
from relay_contracts.dsl_parser import parse_contract
from relay_contracts.errors import RelayCelUnsupportedUdfError
from relay_contracts.pipeline import evaluate_assertion, publish_contract
from relay_contracts.wasm_codec import typed_to_py


def _logical_outputs(udf_outputs: dict[str, object], name: str) -> list[object]:
    """Decode the typed-canonical per-call list back to logical Python values.

    The unified contract (VAL-CWC-P1HOST-015) encodes each captured UDF output
    in the typed-canonical ``{"t":...,"v":...}`` form. The capture SEMANTICS
    are a per-name list in call order; decoding each entry yields the logical
    values (the codec decodes a CEL boolean to a native ``bool``).
    """
    captured = udf_outputs[name]
    assert isinstance(captured, list), (
        f"udf_outputs[name] must be a list; got {type(captured).__name__}: "
        f"{captured!r}"
    )
    return [typed_to_py(entry) for entry in captured]


@pytest.mark.plumbing
def test_native_udf_capture_preserves_every_invocation_in_order() -> None:
    """Calling a native relay.* UDF twice in one CEL expression MUST record
    BOTH outputs in the envelope, in evaluation order.

    ``relay.coverage`` is invoked twice with different step names (one
    present, one missing) so the two recorded values are distinguishable
    downstream: the logical capture is ``[True, False]`` -- the full forensic
    trail, not just the last call (Round-3 fix #3, preserved on the wasm
    ``udf_trace`` path).
    """
    doc = {
        "schema_version": "relay.assertion.behavioral.v1",
        "assertion_id": "VAL-RT-MULTI-CAPTURE",
        "kind": "behavioral",
        # Logical AND of a present-step check and a NEGATED missing-step
        # check: both relay.coverage calls execute (no short-circuit).
        "expression": 'relay.coverage(trace, "step1") && !relay.coverage(trace, "missing")',
        "severity": "p0",
        "owner_email": "test@example.com",
        "lifecycle_state": "active",
    }
    parsed = parse_contract(doc)
    publish_contract(parsed)
    bindings = {"trace": {"steps": [{"name": "step1"}]}}
    envelope = evaluate_assertion(parsed, bindings=bindings)

    assert envelope["outcome"] == "pass", envelope
    assert envelope["udfs_invoked"] == ["relay.coverage"], envelope

    # Per Round-3 fix #3: the envelope's udf_outputs_jcs MUST carry a
    # list of return values for each invoked UDF -- BOTH calls, in order.
    udf_outputs = json.loads(envelope["udf_outputs_jcs"])
    assert "relay.coverage" in udf_outputs, udf_outputs
    captured = _logical_outputs(udf_outputs, "relay.coverage")
    assert captured == [True, False], captured


@pytest.mark.plumbing
def test_native_udf_capture_single_call_still_a_list() -> None:
    """A single-call invocation also yields a one-element list.

    The wire shape is consistently a list -- consumers should not need to
    branch on "scalar vs list" based on call count.
    """
    doc = {
        "schema_version": "relay.assertion.behavioral.v1",
        "assertion_id": "VAL-RT-SINGLE-CAPTURE",
        "kind": "behavioral",
        "expression": 'relay.coverage(trace, "step1")',
        "severity": "p0",
        "owner_email": "test@example.com",
        "lifecycle_state": "active",
    }
    parsed = parse_contract(doc)
    publish_contract(parsed)
    bindings = {"trace": {"steps": [{"name": "step1"}, {"name": "step2"}]}}
    envelope = evaluate_assertion(parsed, bindings=bindings)

    udf_outputs = json.loads(envelope["udf_outputs_jcs"])
    captured = _logical_outputs(udf_outputs, "relay.coverage")
    assert captured == [True], captured


# --- VAL-CWC-P1HOST-016: the wasm rejects a custom (non-allowlist) UDF -------
# ADR Revisions section 4: the custom-UDF capture capability is DROPPED under
# the single wasm engine; the ported contract is the STRUCTURED REJECTION.


def _my_check_doc() -> dict[str, object]:
    return {
        "schema_version": "relay.assertion.behavioral.v1",
        "assertion_id": "VAL-RT-WASM-REJECT",
        "kind": "behavioral",
        "expression": 'my_check("a")',
        "severity": "p0",
        "owner_email": "test@example.com",
        "lifecycle_state": "active",
    }


@pytest.mark.plumbing
def test_wasm_rejects_custom_udf_at_evaluate() -> None:
    """evaluate_assertion with a custom my_check UDF raises
    RelayCelUnsupportedUdfError (RELAY-CEL-004 / UDF-UNREGISTERED).

    The wasm hosts only the 3 native relay.* UDFs and has no registration
    slot, so a caller-supplied UDF is rejected fail-closed -- it is NOT
    captured. The factory rejects at evaluator construction.
    """
    def my_check(arg: str) -> bool:
        return arg == "a"

    udf = register_udf("my_check", my_check, pure=True, arity=1)
    parsed = parse_contract(_my_check_doc())

    with pytest.raises(RelayCelUnsupportedUdfError) as exc_info:
        evaluate_assertion(parsed, bindings={}, extra_udfs=[udf])

    err = exc_info.value
    assert err.code == "RELAY-CEL-004", err.code
    assert err.subtype == "RELAY-CEL-UDF-UNREGISTERED", err.subtype


@pytest.mark.plumbing
def test_wasm_rejects_custom_udf_at_publish() -> None:
    """publish_contract with a custom my_check UDF raises
    RelayCelUnsupportedUdfError (RELAY-CEL-004 / UDF-UNREGISTERED)."""
    def my_check(arg: str) -> bool:
        return arg == "a"

    udf = register_udf("my_check", my_check, pure=True, arity=1)
    parsed = parse_contract(_my_check_doc())

    with pytest.raises(RelayCelUnsupportedUdfError) as exc_info:
        publish_contract(parsed, extra_udfs=[udf])

    err = exc_info.value
    assert err.code == "RELAY-CEL-004", err.code
    assert err.subtype == "RELAY-CEL-UDF-UNREGISTERED", err.subtype
