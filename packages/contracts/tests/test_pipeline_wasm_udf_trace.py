"""VAL-CWC-P1HOST-014: pipeline reconstructs udf_outputs_jcs from udf_trace on
the wasm path.

On the wasm engine path ``evaluate_assertion`` MUST:

  - reconstruct ``udf_outputs_jcs`` from the wasm ``udf_trace`` response field
    (a per-UDF-name list of typed-canonical values in CALL ORDER), NOT from a
    host wrapper-capture;
  - derive ``udfs_invoked`` from the ``udf_trace`` keys, with NO host-side
    CEL AST walk on the hot path (VAL-CWC-P6REMOVE-003);
  - still bind ALL SIX required outcome-envelope keys (assertion_id,
    expression_digest, udfs_invoked, udf_outputs_jcs, wall_time_ms, outcome)
    and raise :class:`RelayContractOutcomeError` if any is missing.

M6 WS-I: the wasm engine is the ONLY backend, so these tests run
unconditionally (the M1-M5 RELAY_CEL_ENGINE=wasm skip gate is gone).

Spec anchors: D, B.4. CLAUDE.md keystone invariant 2 (pass without evidence is
not a pass) + invariant 16 (typed-canonical cross-host byte parity).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json

import pytest
from relay_contracts import RELAY_COVERAGE_NAME, RELAY_UDFS
from relay_contracts.dsl_parser import parse_contract
from relay_contracts.pipeline import (
    _REQUIRED_OUTCOME_KEYS,
    evaluate_assertion,
)


def _coverage_doc(expression: str) -> dict[str, object]:
    return {
        "schema_version": "relay.assertion.behavioral.v1",
        "assertion_id": "VAL-RT-WASM-COVERAGE",
        "kind": "behavioral",
        "expression": expression,
        "severity": "p0",
        "owner_email": "test@example.com",
        "lifecycle_state": "active",
    }


@pytest.mark.plumbing
def test_wasm_path_reconstructs_udf_outputs_from_trace() -> None:
    """A relay.coverage assertion under the wasm engine binds the six keys and
    reconstructs udf_outputs_jcs / udfs_invoked from the wasm udf_trace."""
    doc = _coverage_doc('relay.coverage(t, "step1")')
    parsed = parse_contract(doc)
    bindings = {"t": {"steps": [{"name": "step1"}]}}

    envelope = evaluate_assertion(
        parsed, bindings=bindings, extra_udfs=RELAY_UDFS
    )

    # All six keys present (RelayContractOutcomeError would have fired otherwise).
    for key in _REQUIRED_OUTCOME_KEYS:
        assert key in envelope, f"missing required key {key!r}"

    # udfs_invoked derived from the udf_trace keys.
    assert envelope["udfs_invoked"] == [RELAY_COVERAGE_NAME], envelope[
        "udfs_invoked"
    ]

    # udf_outputs_jcs contains the relay.coverage output list (typed-canonical).
    outputs = json.loads(envelope["udf_outputs_jcs"])
    assert RELAY_COVERAGE_NAME in outputs, outputs
    captured = outputs[RELAY_COVERAGE_NAME]
    assert isinstance(captured, list), captured
    assert captured == [{"t": "bool", "v": True}], captured

    # The coverage UDF matched -> the expression is True -> outcome pass.
    assert envelope["outcome"] == "pass", envelope["outcome"]


@pytest.mark.plumbing
def test_wasm_path_no_udf_call_yields_empty_outputs() -> None:
    """An expression with NO relay.* UDF leaves udf_trace absent; the envelope's
    udf_outputs_jcs is the empty-but-valid JCS object and udfs_invoked is []."""
    doc = _coverage_doc("1 + 2 == 3")
    parsed = parse_contract(doc)

    envelope = evaluate_assertion(parsed, bindings={}, extra_udfs=RELAY_UDFS)

    for key in _REQUIRED_OUTCOME_KEYS:
        assert key in envelope, f"missing required key {key!r}"
    assert envelope["udfs_invoked"] == [], envelope["udfs_invoked"]
    assert envelope["udf_outputs_jcs"] == "{}", envelope["udf_outputs_jcs"]
    assert envelope["outcome"] == "pass", envelope["outcome"]


@pytest.mark.plumbing
def test_wasm_path_short_circuited_udf_not_recorded() -> None:
    """A relay.* call in a short-circuited branch is NOT recorded in udf_trace,
    so udfs_invoked stays empty and udf_outputs_jcs is the empty object."""
    doc = _coverage_doc('false && relay.coverage(t, "step1")')
    parsed = parse_contract(doc)
    bindings = {"t": {"steps": [{"name": "step1"}]}}

    envelope = evaluate_assertion(
        parsed, bindings=bindings, extra_udfs=RELAY_UDFS
    )

    assert envelope["udfs_invoked"] == [], envelope["udfs_invoked"]
    assert envelope["udf_outputs_jcs"] == "{}", envelope["udf_outputs_jcs"]
    # false && ... -> False -> outcome fail.
    assert envelope["outcome"] == "fail", envelope["outcome"]
