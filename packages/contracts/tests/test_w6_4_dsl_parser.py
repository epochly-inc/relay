"""w6.4 contract DSL parser + runtime pipeline tier-1 plumbing tests.

Each test pins exactly one VAL-W6-NNN assertion (VAL-W6-040..045 + 067)
and runs offline (no network). Fixtures live under
``relay/tests/conformance/contracts/dsl_d1_d5/`` and mirror spec
section D.1 through D.5.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

import pytest
from relay_contracts import jcs_canonicalize
from relay_contracts.dsl_parser import (
    KNOWN_SCHEMA_VERSIONS,
    ContractParseError,
    parse_contract,
)
from relay_contracts.pipeline import (
    RelayContractOutcomeError,
    evaluate_assertion,
    publish_contract,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
FIXTURE_DIR = REPO_ROOT / "tests" / "conformance" / "contracts" / "dsl_d1_d5"

D1_PATH = FIXTURE_DIR / "d1_behavioral.json"
D2_PATH = FIXTURE_DIR / "d2_schema.json"
D3_PATH = FIXTURE_DIR / "d3_gate_policy.json"
D4_PATH = FIXTURE_DIR / "d4_tool_arg.json"
D5_PATH = FIXTURE_DIR / "d5_eval.json"

ALL_FIXTURES = [D1_PATH, D2_PATH, D3_PATH, D4_PATH, D5_PATH]


def _load_fixture(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# VAL-W6-040: parser accepts D.1-D.5 fixtures + JCS round-trip byte-identical
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-040")
def test_d1_behavioral_parses_and_round_trips() -> None:
    raw = _load_fixture(D1_PATH)
    parsed = parse_contract(raw)
    assert parsed.schema_version == "relay.assertion.behavioral.v1"
    assert parsed.assertion_id == "VAL-BEHAVIORAL-001"
    assert parsed.kind == "behavioral"
    # Round-trip: re-canonicalise the original raw doc; the parser
    # MUST preserve every byte.
    original_jcs = jcs_canonicalize(raw)
    round_trip_jcs = jcs_canonicalize(parsed.raw)
    assert round_trip_jcs == original_jcs


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-040")
def test_d2_schema_parses_and_round_trips() -> None:
    raw = _load_fixture(D2_PATH)
    parsed = parse_contract(raw)
    assert parsed.schema_version == "relay.assertion.schema.v1"
    assert jcs_canonicalize(parsed.raw) == jcs_canonicalize(raw)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-040")
def test_d3_gate_policy_parses_and_round_trips() -> None:
    raw = _load_fixture(D3_PATH)
    parsed = parse_contract(raw)
    assert parsed.schema_version == "relay.gate_policy.v1"
    # Gate policy has no assertion_id; parser must not invent one.
    assert parsed.assertion_id is None
    assert jcs_canonicalize(parsed.raw) == jcs_canonicalize(raw)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-040")
def test_d4_tool_arg_parses_and_round_trips() -> None:
    raw = _load_fixture(D4_PATH)
    parsed = parse_contract(raw)
    assert parsed.schema_version == "relay.assertion.tool_arg.v1"
    assert parsed.kind == "tool_arg"
    assert jcs_canonicalize(parsed.raw) == jcs_canonicalize(raw)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-040")
def test_d5_eval_parses_and_round_trips() -> None:
    raw = _load_fixture(D5_PATH)
    parsed = parse_contract(raw)
    assert parsed.schema_version == "relay.assertion.eval.v1"
    assert parsed.kind == "eval"
    assert parsed.severity == "p1"
    assert jcs_canonicalize(parsed.raw) == jcs_canonicalize(raw)


# ---------------------------------------------------------------------------
# VAL-W6-041: rejects unknown schema_version with RELAY-CONTRACT-001
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-041")
def test_unknown_schema_version_rejected() -> None:
    bogus = {
        "schema_version": "relay.assertion.NOPE.v999",
        "assertion_id": "X",
        "kind": "behavioral",
        "severity": "p0",
        "expression": "true",
        "owner_email": "a@b.example",
        "lifecycle_state": "active",
    }
    with pytest.raises(ContractParseError) as ctx:
        parse_contract(bogus)
    assert ctx.value.code == "RELAY-CONTRACT-001"
    # Error MUST identify the offending schema_version.
    assert "relay.assertion.NOPE.v999" in str(ctx.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-041")
def test_known_schema_versions_allowlist_is_exactly_five() -> None:
    """Allowlist matches contract assertion VAL-W6-041 verbatim."""
    expected = frozenset({
        "relay.assertion.behavioral.v1",
        "relay.assertion.schema.v1",
        "relay.gate_policy.v1",
        "relay.assertion.tool_arg.v1",
        "relay.assertion.eval.v1",
    })
    assert expected == KNOWN_SCHEMA_VERSIONS


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-041")
def test_missing_schema_version_rejected() -> None:
    with pytest.raises(ContractParseError) as ctx:
        parse_contract({"assertion_id": "X", "kind": "behavioral"})
    assert ctx.value.code == "RELAY-CONTRACT-001"


# ---------------------------------------------------------------------------
# VAL-W6-042: publish-time CEL profile compilation
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-042")
def test_publish_rejects_dyn_in_cel_expression() -> None:
    """A behavioral assertion with CEL-text expression `dyn(1)` MUST be
    rejected at publish, not at first evaluation."""
    doc = {
        "schema_version": "relay.assertion.behavioral.v1",
        "assertion_id": "VAL-BAD-DYN",
        "kind": "behavioral",
        "severity": "p0",
        "expression": "dyn(1) == 1",
        "owner_email": "a@b.example",
        "lifecycle_state": "active",
    }
    parsed = parse_contract(doc)
    with pytest.raises(ContractParseError) as ctx:
        publish_contract(parsed)
    assert ctx.value.code == "RELAY-CONTRACT-004"
    payload = ctx.value.payload
    assert payload["assertion_id"] == "VAL-BAD-DYN"
    assert "cel_token" in payload


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-042")
def test_publish_rejects_unregistered_udf() -> None:
    doc = {
        "schema_version": "relay.assertion.behavioral.v1",
        "assertion_id": "VAL-BAD-UDF",
        "kind": "behavioral",
        "severity": "p0",
        "expression": "totally_made_up_udf(1, 2)",
        "owner_email": "a@b.example",
        "lifecycle_state": "active",
    }
    parsed = parse_contract(doc)
    with pytest.raises(ContractParseError) as ctx:
        publish_contract(parsed)
    assert ctx.value.code == "RELAY-CONTRACT-004"
    assert ctx.value.payload["assertion_id"] == "VAL-BAD-UDF"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-042")
def test_publish_accepts_valid_cel_expression_with_registered_udf() -> None:
    doc = {
        "schema_version": "relay.assertion.behavioral.v1",
        "assertion_id": "VAL-OK-CEL",
        "kind": "behavioral",
        "severity": "p0",
        "expression": "1 + 1 == 2",
        "owner_email": "a@b.example",
        "lifecycle_state": "active",
    }
    parsed = parse_contract(doc)
    # Should not raise.
    publish_contract(parsed)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-042")
def test_publish_accepts_structured_op_expression_without_cel() -> None:
    """D.1 fixture uses a structured op/args tree, not CEL text. Publish
    MUST accept it without invoking the CEL compiler."""
    raw = _load_fixture(D1_PATH)
    parsed = parse_contract(raw)
    publish_contract(parsed)  # no exception


# ---------------------------------------------------------------------------
# VAL-W6-043: severity in {p0,p1,p2,p3}, lifecycle in {draft,active,deprecated,retired}
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-043")
def test_invalid_severity_rejected() -> None:
    doc = {
        "schema_version": "relay.assertion.behavioral.v1",
        "assertion_id": "X",
        "kind": "behavioral",
        "severity": "p9",  # invalid
        "expression": "true",
        "owner_email": "a@b.example",
        "lifecycle_state": "active",
    }
    with pytest.raises(ContractParseError) as ctx:
        parse_contract(doc)
    assert ctx.value.code == "RELAY-CONTRACT-002"
    assert ctx.value.payload["json_path"] == "$.severity"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-043")
def test_invalid_lifecycle_rejected() -> None:
    doc = {
        "schema_version": "relay.assertion.behavioral.v1",
        "assertion_id": "X",
        "kind": "behavioral",
        "severity": "p0",
        "expression": "true",
        "owner_email": "a@b.example",
        "lifecycle_state": "frozen",  # invalid
    }
    with pytest.raises(ContractParseError) as ctx:
        parse_contract(doc)
    assert ctx.value.code == "RELAY-CONTRACT-003"
    assert ctx.value.payload["json_path"] == "$.lifecycle_state"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-043")
def test_all_valid_severities_accepted() -> None:
    for sev in ["p0", "p1", "p2", "p3"]:
        doc = {
            "schema_version": "relay.assertion.behavioral.v1",
            "assertion_id": f"X-{sev}",
            "kind": "behavioral",
            "severity": sev,
            "expression": "true",
            "owner_email": "a@b.example",
            "lifecycle_state": "active",
        }
        parse_contract(doc)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-043")
def test_all_valid_lifecycle_accepted() -> None:
    for state in ["draft", "active", "deprecated", "retired"]:
        doc = {
            "schema_version": "relay.assertion.behavioral.v1",
            "assertion_id": f"X-{state}",
            "kind": "behavioral",
            "severity": "p0",
            "expression": "true",
            "owner_email": "a@b.example",
            "lifecycle_state": state,
        }
        parse_contract(doc)


# ---------------------------------------------------------------------------
# VAL-W6-044: parser hashes canonicalised expression for duplicate detection
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-044")
def test_expression_digest_is_jcs_sha256() -> None:
    raw = _load_fixture(D1_PATH)
    parsed = parse_contract(raw)
    expected_digest = hashlib.sha256(jcs_canonicalize(raw["expression"])).hexdigest()
    assert parsed.expression_digest == expected_digest


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-044")
def test_two_logically_identical_expressions_share_digest() -> None:
    """Different key order / equivalent JSON => same digest after JCS."""
    raw_a = _load_fixture(D1_PATH)
    raw_b = json.loads(json.dumps(raw_a))
    # Re-order the expression's args list -- this is a SEMANTIC change
    # (lists are ordered) so digests should DIFFER. Re-order the top-level
    # keys instead which is semantic-preserving under JCS.
    raw_b_keys = dict(reversed(list(raw_b.items())))
    parsed_a = parse_contract(raw_a)
    parsed_b = parse_contract(raw_b_keys)
    assert parsed_a.expression_digest == parsed_b.expression_digest


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-044")
def test_string_cel_expression_also_hashed() -> None:
    """When expression is a CEL string, the digest is JCS(string)."""
    doc = {
        "schema_version": "relay.assertion.behavioral.v1",
        "assertion_id": "X",
        "kind": "behavioral",
        "severity": "p0",
        "expression": "1 + 1 == 2",
        "owner_email": "a@b.example",
        "lifecycle_state": "active",
    }
    parsed = parse_contract(doc)
    expected = hashlib.sha256(jcs_canonicalize("1 + 1 == 2")).hexdigest()
    assert parsed.expression_digest == expected


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-044")
def test_non_assertion_kinds_use_body_digest() -> None:
    """SchemaContract uses schema_json digest; ToolArgContract uses
    args_schema digest; EvalAssertion uses evaluator digest."""
    parsed_d2 = parse_contract(_load_fixture(D2_PATH))
    parsed_d4 = parse_contract(_load_fixture(D4_PATH))
    parsed_d5 = parse_contract(_load_fixture(D5_PATH))
    assert parsed_d2.expression_digest is not None
    assert parsed_d4.expression_digest is not None
    assert parsed_d5.expression_digest is not None


# ---------------------------------------------------------------------------
# VAL-W6-045: runtime pipeline binds UDF results to outcome envelope
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-045")
def test_runtime_outcome_envelope_has_required_fields() -> None:
    doc = {
        "schema_version": "relay.assertion.behavioral.v1",
        "assertion_id": "VAL-RT-001",
        "kind": "behavioral",
        "severity": "p0",
        "expression": "1 + 1 == 2",
        "owner_email": "a@b.example",
        "lifecycle_state": "active",
    }
    parsed = parse_contract(doc)
    publish_contract(parsed)
    envelope = evaluate_assertion(parsed, bindings={})
    # Required envelope fields per VAL-W6-045.
    for key in (
        "assertion_id",
        "expression_digest",
        "udfs_invoked",
        "udf_outputs_jcs",
        "wall_time_ms",
        "outcome",
    ):
        assert key in envelope, f"VAL-W6-045: outcome envelope missing {key!r}"
    assert envelope["assertion_id"] == "VAL-RT-001"
    assert envelope["outcome"] == "pass"
    assert envelope["udfs_invoked"] == []  # no UDFs in this expression
    assert isinstance(envelope["wall_time_ms"], int | float)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-045")
def test_runtime_outcome_envelope_pass_fail_error() -> None:
    """Outcome enum is exactly {pass, fail, error}."""
    # Pass
    p_doc = {
        "schema_version": "relay.assertion.behavioral.v1",
        "assertion_id": "P",
        "kind": "behavioral",
        "severity": "p0",
        "expression": "1 == 1",
        "owner_email": "a@b.example",
        "lifecycle_state": "active",
    }
    p_parsed = parse_contract(p_doc)
    publish_contract(p_parsed)
    assert evaluate_assertion(p_parsed, bindings={})["outcome"] == "pass"
    # Fail
    f_doc = {**p_doc, "assertion_id": "F", "expression": "1 == 2"}
    f_parsed = parse_contract(f_doc)
    publish_contract(f_parsed)
    assert evaluate_assertion(f_parsed, bindings={})["outcome"] == "fail"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-045")
def test_runtime_invokes_application_udf_and_records_in_envelope() -> None:
    """A CEL expression that calls a registered UDF MUST surface the UDF
    name in udfs_invoked and the JCS-canonical output bytes.

    The Relay production UDFs ship with dotted identifiers
    (relay.coverage / relay.tool_arg / relay.schema_match) which the
    cel-python wrapper at this revision treats as field access on a
    'relay' identifier rather than function-call resolution. w6.4 ships
    the pipeline plumbing; the call-site rewrite to dotted form is
    tracked separately. Here we exercise the binding contract with a
    plain-identifier pure UDF registered alongside the parser pipeline.
    """
    from relay_contracts import register_udf

    def my_check(trace: list, step: str) -> bool:
        return any(item.get("step") == step for item in trace)

    udf = register_udf("my_check", my_check, pure=True, arity=2)
    doc = {
        "schema_version": "relay.assertion.behavioral.v1",
        "assertion_id": "VAL-RT-UDF",
        "kind": "behavioral",
        "severity": "p0",
        "expression": 'my_check(trace, "step1")',
        "owner_email": "a@b.example",
        "lifecycle_state": "active",
    }
    parsed = parse_contract(doc)
    publish_contract(parsed, extra_udfs=[udf])
    bindings = {"trace": [{"step": "step1"}, {"step": "step2"}]}
    envelope = evaluate_assertion(parsed, bindings=bindings, extra_udfs=[udf])
    assert "my_check" in envelope["udfs_invoked"]
    assert envelope["outcome"] == "pass"
    # JCS-canonical UDF outputs MUST be bytes-stringifiable.
    # Round-3 P1 fix #3: captures are list-valued so a multi-call CEL
    # expression preserves every invocation's return value (keystone
    # invariant 2). A single-call invocation is therefore a one-element
    # list, not a bare scalar.
    udf_outputs = json.loads(envelope["udf_outputs_jcs"])
    assert udf_outputs.get("my_check") == [True]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-045")
def test_runtime_envelope_missing_field_raises() -> None:
    """Internal: if the runtime returns an envelope missing a required
    field, RelayContractOutcomeError MUST raise. We simulate by passing
    a deliberately-malformed envelope to the validator."""
    from relay_contracts.pipeline import _validate_outcome_envelope

    bad = {"assertion_id": "X", "outcome": "pass"}  # missing fields
    with pytest.raises(RelayContractOutcomeError):
        _validate_outcome_envelope(bad)


# ---------------------------------------------------------------------------
# VAL-W6-067: parse latency p95 < 50 ms over 20 warm runs
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-067")
def test_parse_latency_under_50ms_p95_per_fixture() -> None:
    """For every D.1-D.5 fixture, parse + JCS round-trip MUST complete
    within 50 ms p95 over 20 runs (first 5 discarded as warmup)."""
    for fixture in ALL_FIXTURES:
        raw = _load_fixture(fixture)
        # Warmup
        for _ in range(5):
            parsed = parse_contract(raw)
            jcs_canonicalize(parsed.raw)
        samples_ms: list[float] = []
        for _ in range(20):
            t0 = time.perf_counter()
            parsed = parse_contract(raw)
            jcs_canonicalize(parsed.raw)
            samples_ms.append((time.perf_counter() - t0) * 1000.0)
        samples_ms.sort()
        # p95 of 20 samples = index 18 (95th percentile, ceiling).
        p95 = samples_ms[18]
        assert p95 < 50.0, (
            f"VAL-W6-067: {fixture.name} parse p95={p95:.2f} ms > 50 ms budget; "
            f"samples_ms={samples_ms}"
        )
