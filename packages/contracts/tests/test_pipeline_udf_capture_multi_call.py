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

VAL-CWC-P1HOST-016: the custom-``my_check``-UDF capture behavior is the
CELPY contract. Under the wasm engine there is no registration slot for a
caller-supplied UDF -- the wasm hosts only the 3 native ``relay.*`` UDFs --
so ``evaluate_assertion`` / ``publish_contract`` with a custom ``my_check``
UDF MUST raise :class:`RelayCelUnsupportedUdfError` (RELAY-CEL-004 /
RELAY-CEL-UDF-UNREGISTERED) fail-closed rather than capture. The celpy path
RETAINS the multi-call capture (captured == [True, False]).

Spec anchors: D, B.4 (closed evidence envelope).
CLAUDE.md anchors: keystone invariant 2 (pass without evidence is not a
pass -- "pass" must include the full forensic trail, not just the last
call).
"""

from __future__ import annotations

import json
import os

import pytest
from relay_contracts import register_udf
from relay_contracts.dsl_parser import parse_contract
from relay_contracts.errors import RelayCelUnsupportedUdfError
from relay_contracts.pipeline import evaluate_assertion, publish_contract

# The contracts factory reads RELAY_CEL_ENGINE (engine.py is the ONLY env read
# site). The celpy-capture cases require the default/celpy engine; the
# wasm-rejection cases require the wasm engine. Each block guards on the
# selected engine so the suite is green under either selection. pipeline.py
# never reads this env -- the gate is in the test only.
_WASM_SELECTED = os.environ.get("RELAY_CEL_ENGINE", "").strip() == "wasm"


def _logical_outputs(udf_outputs: dict[str, object], name: str) -> list[object]:
    """Decode the typed-canonical per-call list back to logical Python values.

    The unified contract (VAL-CWC-P1HOST-015) encodes each captured UDF output
    in the typed-canonical ``{"t":...,"v":...}`` form so the celpy and wasm
    ``udf_outputs_jcs`` bytes are identical. The capture SEMANTICS are
    unchanged -- a per-name list in call order -- so decoding each entry yields
    the same logical values the pre-unification raw form carried
    (e.g. ``[True, False]``). ``typed_to_py`` returns celtypes; compare via
    plain Python equality (BoolType == bool).
    """
    from relay_contracts.wasm_codec import typed_to_py

    captured = udf_outputs[name]
    assert isinstance(captured, list), (
        f"udf_outputs[name] must be a list; got {type(captured).__name__}: "
        f"{captured!r}"
    )
    return [typed_to_py(entry) for entry in captured]


@pytest.mark.plumbing
@pytest.mark.skipif(
    _WASM_SELECTED,
    reason="celpy custom-UDF capture; the wasm engine rejects my_check (see "
    "test_wasm_rejects_custom_udf_*)",
)
def test_udf_capture_preserves_every_invocation_in_order() -> None:
    """Calling a UDF twice in a CEL expression MUST record both outputs.

    The expression ``my_check("a") && my_check("b")`` invokes the same
    UDF twice with different arguments; the wrapper closure must append
    both return values to ``captured_outputs["my_check"]``. The
    ``udf_outputs_jcs`` field in the envelope MUST carry both -- it is a
    list in evaluation order. The wire form is typed-canonical
    (VAL-CWC-P1HOST-015); the LOGICAL captured values stay ``[True, False]``.
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
    # Both return values are recorded, in evaluation order. Decode the
    # typed-canonical entries to assert the logical capture is [True, False].
    captured = _logical_outputs(udf_outputs, "my_check")
    assert captured == [True, False], captured


@pytest.mark.plumbing
@pytest.mark.skipif(
    _WASM_SELECTED,
    reason="celpy custom-UDF capture; the wasm engine rejects my_check (see "
    "test_wasm_rejects_custom_udf_*)",
)
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
    captured = _logical_outputs(udf_outputs, "my_check")
    assert captured == [True], captured


# --- VAL-CWC-P1HOST-016: wasm rejects a custom (non-allowlist) UDF ---------


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
@pytest.mark.skipif(
    not _WASM_SELECTED,
    reason="wasm-rejection case; runs only under RELAY_CEL_ENGINE=wasm",
)
def test_wasm_rejects_custom_udf_at_evaluate() -> None:
    """Under the wasm engine, evaluate_assertion with a custom my_check UDF
    raises RelayCelUnsupportedUdfError (RELAY-CEL-004 / UDF-UNREGISTERED).

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
@pytest.mark.skipif(
    not _WASM_SELECTED,
    reason="wasm-rejection case; runs only under RELAY_CEL_ENGINE=wasm",
)
def test_wasm_rejects_custom_udf_at_publish() -> None:
    """Under the wasm engine, publish_contract with a custom my_check UDF
    raises RelayCelUnsupportedUdfError (RELAY-CEL-004 / UDF-UNREGISTERED)."""
    def my_check(arg: str) -> bool:
        return arg == "a"

    udf = register_udf("my_check", my_check, pure=True, arity=1)
    parsed = parse_contract(_my_check_doc())

    with pytest.raises(RelayCelUnsupportedUdfError) as exc_info:
        publish_contract(parsed, extra_udfs=[udf])

    err = exc_info.value
    assert err.code == "RELAY-CEL-004", err.code
    assert err.subtype == "RELAY-CEL-UDF-UNREGISTERED", err.subtype
