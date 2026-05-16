"""Round-3 P1 fix #3: pipeline UDF wrapper captures EVERY invocation.

Per the pre-fix code at ``packages/contracts/src/relay_contracts/pipeline.py``
the UDF capture closure stored ``captured_outputs[name] = result`` --
overwriting earlier calls when the same UDF is invoked multiple times in
one CEL expression. The envelope's ``udf_outputs_jcs`` field would then
only carry the LAST return value, losing the forensic trail of every
invocation.

This guard fix changes the capture to a list-of-results: every wrapper
call APPENDS to ``captured_outputs[name]``. The order is preserved (the
order of CEL evaluation), and the JCS canonical bytes carry every
invocation's return value.

Spec anchors: D, B.4 (closed evidence envelope).
CLAUDE.md anchors: keystone invariant 2 (pass without evidence is not a
pass -- "pass" must include the full forensic trail, not just the last
call).
"""

from __future__ import annotations

import json

import pytest
from relay_contracts import register_udf
from relay_contracts.dsl_parser import parse_contract
from relay_contracts.pipeline import evaluate_assertion, publish_contract


@pytest.mark.plumbing
def test_udf_capture_preserves_every_invocation_in_order() -> None:
    """Calling a UDF twice in a CEL expression MUST record both outputs.

    The expression ``my_check("a") && my_check("b")`` invokes the same
    UDF twice with different arguments; the wrapper closure must append
    both return values to ``captured_outputs["my_check"]``. The
    ``udf_outputs_jcs`` field in the envelope MUST carry both -- it is a
    list in evaluation order.
    """
    calls: list[str] = []

    def my_check(arg: str) -> bool:
        calls.append(arg)
        # Return True for "a" and False for "b" so the two values are
        # distinguishable downstream.
        return arg == "a"

    udf = register_udf("my_check", my_check, pure=True, arity=1)
    doc = {
        "schema_version": "relay.assertion.behavioral.v1",
        "assertion_id": "VAL-RT-MULTI-CAPTURE",
        "kind": "behavioral",
        # Use logical AND so cel-python evaluates both sides; bind to
        # the variable form so both calls are unambiguous.
        "expression": 'my_check("a") && !my_check("b")',
        "severity": "p0",
        "owner_email": "test@example.com",
        "lifecycle_state": "active",
    }
    parsed = parse_contract(doc)
    publish_contract(parsed, extra_udfs=[udf])
    envelope = evaluate_assertion(parsed, bindings={}, extra_udfs=[udf])

    # The UDF was invoked twice (different args).
    assert calls == ["a", "b"], calls

    # Per Round-3 fix #3: the envelope's udf_outputs_jcs MUST carry a
    # list of return values for each invoked UDF.
    udf_outputs = json.loads(envelope["udf_outputs_jcs"])
    assert "my_check" in udf_outputs, udf_outputs
    captured = udf_outputs["my_check"]
    assert isinstance(captured, list), (
        f"udf_outputs[name] must be a list; got {type(captured).__name__}: "
        f"{captured!r}"
    )
    # Both return values are recorded, in evaluation order.
    assert captured == [True, False], captured


@pytest.mark.plumbing
def test_udf_capture_single_call_still_a_list() -> None:
    """A single-call invocation also yields a one-element list.

    The post-fix wire shape is consistently a list -- consumers should
    not need to branch on "scalar vs list" based on call count.
    """
    def my_check(trace: list, step: str) -> bool:
        return any(item.get("step") == step for item in trace)

    udf = register_udf("my_check", my_check, pure=True, arity=2)
    doc = {
        "schema_version": "relay.assertion.behavioral.v1",
        "assertion_id": "VAL-RT-SINGLE-CAPTURE",
        "kind": "behavioral",
        "expression": 'my_check(trace, "step1")',
        "severity": "p0",
        "owner_email": "test@example.com",
        "lifecycle_state": "active",
    }
    parsed = parse_contract(doc)
    publish_contract(parsed, extra_udfs=[udf])
    bindings = {"trace": [{"step": "step1"}, {"step": "step2"}]}
    envelope = evaluate_assertion(parsed, bindings=bindings, extra_udfs=[udf])

    udf_outputs = json.loads(envelope["udf_outputs_jcs"])
    captured = udf_outputs["my_check"]
    assert isinstance(captured, list), captured
    assert captured == [True], captured
