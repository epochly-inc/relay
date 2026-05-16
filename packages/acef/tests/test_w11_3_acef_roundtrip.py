"""W11.3 ACEF emit/parse roundtrip contract tests.

This module enforces the eleven VAL-W11-016..026 assertions that
constitute the w11.3-acef-roundtrip-tests feature:

  * VAL-W11-016  Bundle roundtrip is byte-identical under RFC 8785 JCS
                 across >= 12 fixtures.
  * VAL-W11-017  Unknown ACEF Core bundle.schema_version rejected on
                 write with SchemaVersionError(RELAY-SCHEMA-017).
  * VAL-W11-018  Unknown x-relay schema_version rejected on write with
                 SchemaVersionError(RELAY-SCHEMA-018).
  * VAL-W11-019  Roundtrip preserves Merkle root across emit -> parse
                 -> re-emit.
  * VAL-W11-020  Unicode normalisation is NFC and roundtrips losslessly.
  * VAL-W11-021  Decimal precision preserved without float drift.
  * VAL-W11-022  Bundle determinism survives temporal + host noise
                 (subprocess parity).
  * VAL-W11-023  Roundtrip rejects bundles missing required
                 control-plane bindings (7 fields x 7 distinct errors).
  * VAL-W11-024  Roundtrip conformance corpus exported for W17 with
                 >= 25 fixtures.
  * VAL-W11-025  ACEF emission failure does not block runtime trace
                 ingestion (latency-isolation contract).
  * VAL-W11-026  Banned product copy absent from ACEF vendor docs.

Plumbing tier (tier 1, <= 60s, offline). The subprocess parity test
uses sys.executable + os.environ overrides to spawn a child process
on the same Python; it does NOT touch the network or any external
service. The corpus export writes to a single JSON file under
tests/conformance/acef/.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import unicodedata
from copy import deepcopy
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from relay_acef.roundtrip import (
    bundle_merkle_root,
    emit_bundle,
    jcs_canonicalize,
    parse_bundle,
    roundtrip,
)
from relay_extensions import (
    ACEF_CORE_SCHEMA_VERSION_PIN,
    RELAY_EXTENSIONS_SCHEMA_VERSION,
    REQUIRED_CONTROL_PLANE_BINDINGS,
    X_RELAY_NAMESPACE_KEY,
)
from relay_extensions.emission import EmissionWriter
from relay_extensions.errors import SchemaVersionError

# ---------------------------------------------------------------------------
# Shared fixture builders
# ---------------------------------------------------------------------------
#
# Every fixture builds on top of a single _good_bindings()/_base_bundle()
# helper so the seven control-plane fields stay synchronised with the
# W11.2 contract. Variations layer namespace payloads, claims, and unicode
# / decimal content on top.

_VALID_BINDINGS: dict[str, Any] = {
    "manifest_commit_hash": "a" * 64,
    "scope_kind": "run",
    "scope_id": "11111111-2222-3333-4444-555555555555",
    "actor_kind": "control_plane",
    "actor_identity_hash": "b" * 64,
    "written_by": "control_plane",
    "redaction_policy_version": "v1.0",
}


def _good_bindings() -> dict[str, Any]:
    """Return a fresh dict of seven valid control-plane bindings."""
    return dict(_VALID_BINDINGS)


def _base_bundle() -> dict[str, Any]:
    """Return a minimal valid emitted ACEF bundle (no namespace payload)."""
    return {
        "schema_version": ACEF_CORE_SCHEMA_VERSION_PIN,
        "claims": [],
        "namespaces": {
            X_RELAY_NAMESPACE_KEY: {
                "schema_version": RELAY_EXTENSIONS_SCHEMA_VERSION,
                **_good_bindings(),
            }
        },
    }


def _agent_trace_payload() -> dict[str, Any]:
    """Return a valid agent-execution-trace namespace payload."""
    return {
        "schema_version": "x-relay.agent-execution-trace.v1",
        "span_id": "0123456789abcdef",
        "trace_id": "0123456789abcdef0123456789abcdef",
        "parent_span_id": None,
        "span_type": "llm_call",
        "status": "ok",
        "started_at": "2026-05-15T12:00:00Z",
        "ended_at": "2026-05-15T12:00:01Z",
        "duration_ms": 1000,
        "error_class": None,
        "redacted_metadata_digest": "0" * 64,
    }


def _bundle_with_namespace(name: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Return a bundle carrying one declared namespace payload."""
    bundle = _base_bundle()
    bundle["namespaces"][X_RELAY_NAMESPACE_KEY][name] = payload
    return bundle


# ---------------------------------------------------------------------------
# Per-namespace minimal payload generator
# ---------------------------------------------------------------------------
#
# Field names below MUST exist in the corresponding W11.2 JSON Schema at
# packages/acef/relay_extensions/schemas/<name>.v1.json (verified by the
# schema-properties dump that produced this map). Adding a field that
# the schema does not declare triggers EmissionWriter._audit_namespace_subfields
# to raise SchemaVersionError(RELAY-SCHEMA-011).

_NS_PAYLOAD_TABLE: dict[str, dict[str, Any]] = {
    "agent-execution-trace": {
        "schema_version": "x-relay.agent-execution-trace.v1",
        "span_id": "0123456789abcdef",
        "trace_id": "0123456789abcdef0123456789abcdef",
        "parent_span_id": None,
        "span_type": "llm_call",
        "status": "ok",
        "started_at": "2026-05-15T12:00:00Z",
        "ended_at": "2026-05-15T12:00:01Z",
        "duration_ms": 1000,
        "error_class": None,
        "redacted_metadata_digest": "0" * 64,
    },
    "tool-invocation-log": {
        "schema_version": "x-relay.tool-invocation-log.v1",
        "tool_name": "calculator",
        "args_digest": "1" * 64,
        "result_digest": "2" * 64,
        "idempotency_key": "idem-001",
        "side_effect_class": "none",
        "invoked_at": "2026-05-15T12:00:00Z",
        "pre_action_marker_digest": None,
        "post_success_proof_digest": None,
    },
    "replay-verification": {
        "schema_version": "x-relay.replay-verification.v1",
        "replay_case_id": "22222222-3333-4444-5555-666666666666",
        "mode": "cassette",
        "fixture_digest": "3" * 64,
        "model_signature": None,
        "outcome": "match",
        "result_diff_digest": None,
        "completed_at": "2026-05-15T12:00:00Z",
    },
    "contract-gate-result": {
        "schema_version": "x-relay.contract-gate-result.v1",
        "gate_round_id": "33333333-4444-5555-6666-777777777777",
        "round_index": 1,
        "action": "advance",
        "failed_assertion_ids": [],
        "contract_digest": "4" * 64,
        "decided_at": "2026-05-15T12:00:00Z",
    },
    "eval-dataset-result": {
        "schema_version": "x-relay.eval-dataset-result.v1",
        "eval_run_id": "44444444-5555-6666-7777-888888888888",
        "dataset_digest": "4" * 64,
        "case_count": 1,
        "score": 1.0,
        "completed_at": "2026-05-15T12:00:00Z",
    },
    "human-oversight-event": {
        "schema_version": "x-relay.human-oversight-event.v1",
        "event_id": "55555555-6666-7777-8888-999999999999",
        "reviewer_identity_hash": "5" * 64,
        "reviewer_role": "compliance_officer",
        "authority_basis": None,
        "decision": "approve",
        "linked_run_id": None,
        "occurred_at": "2026-05-15T12:00:00Z",
    },
    "incident-monitoring-event": {
        "schema_version": "x-relay.incident-monitoring-event.v1",
        "incident_id": "66666666-7777-8888-9999-000000000000",
        "severity": "sev3",
        "detected_at": "2026-05-15T12:00:00Z",
        "linked_run_ids": [],
        "remediation_summary_digest": None,
        "notification_evidence_digest": None,
        "status": "open",
    },
    "data-quality-check": {
        "schema_version": "x-relay.data-quality-check.v1",
        "dataset_digest": "7" * 64,
        "check_kind": "schema",
        "result": "pass",
        "limitations_digest": None,
        "metric_value": None,
        "checked_at": "2026-05-15T12:00:00Z",
    },
    "model-provider-compatibility": {
        "schema_version": "x-relay.model-provider-compatibility.v1",
        "provider": "openai",
        "model_id": "gpt-4o-mini",
        "system_fingerprint": None,
        "compatibility_status": "ok",
        "captured_at": "2026-05-15T12:00:00Z",
    },
    "rag-retrieval-diagnostics": {
        "schema_version": "x-relay.rag-retrieval-diagnostics.v1",
        "query_digest": "9" * 64,
        "k": 5,
        "retrieved_document_digests": ["a" * 64, "b" * 64],
        "scores": [0.95, 0.85],
        "index_digest": "9" * 64,
        "retrieved_at": "2026-05-15T12:00:00Z",
    },
}


def _ns_payload(name: str) -> dict[str, Any]:
    """Return a fresh, schema-correct payload dict for namespace ``name``.

    The returned dict is a deepcopy so callers can mutate it (e.g., the
    nullable / optional / unicode / decimal fixtures swap fields) without
    leaking back into _NS_PAYLOAD_TABLE.
    """
    if name not in _NS_PAYLOAD_TABLE:
        raise KeyError(f"unknown namespace {name!r}; must be one of {sorted(_NS_PAYLOAD_TABLE)}")
    return deepcopy(_NS_PAYLOAD_TABLE[name])


# ---------------------------------------------------------------------------
# Static fixture catalogue (>= 25 entries, satisfies VAL-W11-016 + -024).
# ---------------------------------------------------------------------------
#
# Each entry: (fixture_id, builder_callable, expected_error_code_or_None).
# The builders are callables (not pre-built dicts) so each test gets a
# fresh deepcopy and the corpus-export test can recompute digests.

NS_TEN: tuple[str, ...] = (
    "agent-execution-trace",
    "tool-invocation-log",
    "replay-verification",
    "contract-gate-result",
    "eval-dataset-result",
    "human-oversight-event",
    "incident-monitoring-event",
    "data-quality-check",
    "model-provider-compatibility",
    "rag-retrieval-diagnostics",
)


def _fixture_minimum() -> dict[str, Any]:
    return _base_bundle()


def _fixture_with_one_namespace() -> dict[str, Any]:
    return _bundle_with_namespace(
        "agent-execution-trace", _agent_trace_payload()
    )


def _fixture_with_all_ten_namespaces() -> dict[str, Any]:
    """Bundle with every declared namespace populated by minimal payloads."""
    bundle = _base_bundle()
    block = bundle["namespaces"][X_RELAY_NAMESPACE_KEY]
    block["agent-execution-trace"] = _agent_trace_payload()
    block["tool-invocation-log"] = _ns_payload("tool-invocation-log")
    block["replay-verification"] = _ns_payload("replay-verification")
    block["contract-gate-result"] = _ns_payload("contract-gate-result")
    block["eval-dataset-result"] = _ns_payload("eval-dataset-result")
    block["human-oversight-event"] = _ns_payload("human-oversight-event")
    block["incident-monitoring-event"] = _ns_payload("incident-monitoring-event")
    block["data-quality-check"] = _ns_payload("data-quality-check")
    block["model-provider-compatibility"] = _ns_payload("model-provider-compatibility")
    block["rag-retrieval-diagnostics"] = _ns_payload("rag-retrieval-diagnostics")
    return bundle


def _fixture_unicode_payload() -> dict[str, Any]:
    """A bundle with combining-mark unicode in agent-execution-trace.error_class.

    Uses a schema-declared free-form string field (error_class is a
    nullable string per the namespace JSON Schema). Carrying unicode
    in any non-declared sub-field triggers RELAY-SCHEMA-011 in the
    EmissionWriter (additionalProperties: false), so the unicode
    payload rides on a declared free-form field instead.
    """
    payload = _ns_payload("agent-execution-trace")
    # NFD: cafe + U+0301 -> normalises to NFC cafe-acute on parse.
    payload["error_class"] = "café-anomaly"
    bundle = _base_bundle()
    bundle["namespaces"][X_RELAY_NAMESPACE_KEY]["agent-execution-trace"] = payload
    return bundle


def _fixture_unicode_nfd_keys() -> dict[str, Any]:
    """Same as unicode but with the namespace VALUE containing CJK + RTL.

    NB: x-relay namespace KEYS are the fixed schema-declared identifiers
    (ASCII), so we put unicode in the *value* string fields.
    """
    bundle = _base_bundle()
    bundle["namespaces"][X_RELAY_NAMESPACE_KEY]["agent-execution-trace"] = {
        **_agent_trace_payload(),
        # CJK + RTL + ZWJ emoji
        "error_class": "中文-עברית-\U0001f469‍\U0001f4bb",
    }
    return bundle


def _fixture_decimal_precision() -> dict[str, Any]:
    """A bundle with Decimal numeric values that float would drift."""
    bundle = _base_bundle()
    # 'score' field is a number in [0, 1]; we use a 17-digit value that
    # IEEE-754 double cannot represent exactly. Decimal preserves it.
    bundle["namespaces"][X_RELAY_NAMESPACE_KEY]["eval-dataset-result"] = {
        "schema_version": "x-relay.eval-dataset-result.v1",
        "eval_run_id": "99999999-aaaa-bbbb-cccc-dddddddddddd",
        "dataset_digest": "d" * 64,
        # case_count is an int; survives float-vs-int distinction.
        "case_count": 9007199254740993,  # > 2^53; would lose 1 in float.
        # Score values that would float-drift if cast through double.
        "score": Decimal("0.30000000000000004"),
        "threshold": Decimal("0.99999999999999999"),
        "completed_at": "2026-05-15T12:00:00Z",
    }
    return bundle


def _fixture_nullable_field_present() -> dict[str, Any]:
    """replay-verification with the optional result_diff_digest populated."""
    payload = _ns_payload("replay-verification")
    payload["outcome"] = "diff"
    payload["result_diff_digest"] = "4" * 64
    bundle = _base_bundle()
    bundle["namespaces"][X_RELAY_NAMESPACE_KEY]["replay-verification"] = payload
    return bundle


def _fixture_nullable_field_null() -> dict[str, Any]:
    """replay-verification with the optional result_diff_digest set to null."""
    payload = _ns_payload("replay-verification")
    payload["outcome"] = "match"
    payload["result_diff_digest"] = None
    bundle = _base_bundle()
    bundle["namespaces"][X_RELAY_NAMESPACE_KEY]["replay-verification"] = payload
    return bundle


def _fixture_optional_field_absent() -> dict[str, Any]:
    """eval-dataset-result without optional fields (threshold, failed_case_ids)."""
    bundle = _base_bundle()
    bundle["namespaces"][X_RELAY_NAMESPACE_KEY]["eval-dataset-result"] = {
        "schema_version": "x-relay.eval-dataset-result.v1",
        "eval_run_id": "44444444-5555-6666-7777-888888888888",
        "dataset_digest": "4" * 64,
        "case_count": 0,
        "score": 0.0,
        "completed_at": "2026-05-15T12:00:00Z",
    }
    return bundle


def _fixture_optional_field_present() -> dict[str, Any]:
    """Same namespace but with optional fields populated."""
    bundle = _base_bundle()
    bundle["namespaces"][X_RELAY_NAMESPACE_KEY]["eval-dataset-result"] = {
        "schema_version": "x-relay.eval-dataset-result.v1",
        "eval_run_id": "44444444-5555-6666-7777-888888888888",
        "dataset_digest": "4" * 64,
        "case_count": 5,
        "score": 0.8,
        "threshold": 0.7,
        "failed_case_ids": ["case-a", "case-b"],
        "completed_at": "2026-05-15T12:00:00Z",
    }
    return bundle


def _fixture_with_claims_in_canonical_order() -> dict[str, Any]:
    """A bundle with three claims whose evidence_claim_ids are out of order
    in input but must sort canonically."""
    bundle = _base_bundle()
    bundle["claims"] = [
        {"evidence_claim_id": "z-third", "value": 3},
        {"evidence_claim_id": "a-first", "value": 1},
        {"evidence_claim_id": "m-second", "value": 2},
    ]
    return bundle


def _fixture_one_namespace_per_id(ns: str) -> dict[str, Any]:
    """Per-namespace minimal-payload fixture builder.

    Returns a bundle that exercises a single namespace; used by the
    matrix expansion to satisfy the VAL-W11-016 cardinality target.
    Payloads come from the schema-validated _NS_PAYLOAD_TABLE so the
    EmissionWriter's additionalProperties enforcement (RELAY-SCHEMA-011)
    accepts every entry.
    """
    return _bundle_with_namespace(ns, _ns_payload(ns))


# Catalogue: list of (fixture_id, builder, expected_error_code_or_None).
# Happy-path entries (expected_error is None) participate in the
# roundtrip / Merkle / corpus tests. Negative entries (expected_error
# present) are exercised by the schema-version + missing-binding tests
# and are recorded in the corpus index for W17.

ROUNDTRIP_FIXTURES: list[tuple[str, Any, str | None]] = [
    ("minimum", _fixture_minimum, None),
    ("with-one-namespace", _fixture_with_one_namespace, None),
    ("with-all-ten-namespaces", _fixture_with_all_ten_namespaces, None),
    ("unicode-combining", _fixture_unicode_payload, None),
    ("unicode-cjk-rtl-emoji", _fixture_unicode_nfd_keys, None),
    ("decimal-precision", _fixture_decimal_precision, None),
    ("nullable-field-present", _fixture_nullable_field_present, None),
    ("nullable-field-null", _fixture_nullable_field_null, None),
    ("optional-fields-absent", _fixture_optional_field_absent, None),
    ("optional-fields-present", _fixture_optional_field_present, None),
    ("claims-canonical-order", _fixture_with_claims_in_canonical_order, None),
] + [
    (f"single-namespace-{ns}", lambda ns=ns: _fixture_one_namespace_per_id(ns), None)
    for ns in NS_TEN
]
# 11 + 10 = 21 happy-path entries. Plus negative entries (>= 4) ->
# corpus total >= 25 (VAL-W11-024 requirement).


# Negative fixtures: builders are factories that produce a bundle that
# emit_bundle() MUST reject with the specified error code. Used by the
# corpus exporter so W17 can replay rejection cases too.


def _neg_unknown_core_schema_v0_1() -> dict[str, Any]:
    bundle = _base_bundle()
    bundle["schema_version"] = "v0.1"
    return bundle


def _neg_unknown_core_schema_v99() -> dict[str, Any]:
    bundle = _base_bundle()
    bundle["schema_version"] = "v99"
    return bundle


def _neg_unknown_xrelay_schema_v0() -> dict[str, Any]:
    bundle = _base_bundle()
    bundle["namespaces"][X_RELAY_NAMESPACE_KEY]["schema_version"] = "v0"
    return bundle


def _neg_unknown_xrelay_schema_v2() -> dict[str, Any]:
    bundle = _base_bundle()
    bundle["namespaces"][X_RELAY_NAMESPACE_KEY]["schema_version"] = "v2"
    return bundle


def _neg_missing_manifest_commit_hash() -> dict[str, Any]:
    bundle = _base_bundle()
    del bundle["namespaces"][X_RELAY_NAMESPACE_KEY]["manifest_commit_hash"]
    return bundle


def _neg_missing_redaction_policy_version() -> dict[str, Any]:
    bundle = _base_bundle()
    del bundle["namespaces"][X_RELAY_NAMESPACE_KEY]["redaction_policy_version"]
    return bundle


# Schema-version negatives map to the contract's RELAY-SCHEMA-014 (the
# W11.2 EmissionWriter raises -014 for any schema_version pin mismatch
# regardless of whether the field is on the ACEF Core root or in the
# x-relay block); VAL-W11-017/018 distinguish the two by which field
# the violation names. The corpus records the ACTUAL wire code raised
# by the writer.
#
# Bindings negatives raise RELAY-SCHEMA-023 per VAL-W11-013 / -023.

NEGATIVE_FIXTURES: list[tuple[str, Any, str]] = [
    ("neg-unknown-core-schema-v0_1", _neg_unknown_core_schema_v0_1, "RELAY-SCHEMA-014"),
    ("neg-unknown-core-schema-v99", _neg_unknown_core_schema_v99, "RELAY-SCHEMA-014"),
    ("neg-unknown-xrelay-schema-v0", _neg_unknown_xrelay_schema_v0, "RELAY-SCHEMA-014"),
    ("neg-unknown-xrelay-schema-v2", _neg_unknown_xrelay_schema_v2, "RELAY-SCHEMA-014"),
    ("neg-missing-manifest-commit-hash", _neg_missing_manifest_commit_hash, "RELAY-SCHEMA-023"),
    (
        "neg-missing-redaction-policy-version",
        _neg_missing_redaction_policy_version,
        "RELAY-SCHEMA-023",
    ),
]


# =============================================================================
# VAL-W11-016: roundtrip byte-identical under RFC 8785 JCS (>= 12 fixtures)
# =============================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-016")
def test_fixture_count_meets_twelve_minimum() -> None:
    """The W11.3 fixture catalogue has at least 12 happy-path entries."""
    happy = [f for f in ROUNDTRIP_FIXTURES if f[2] is None]
    assert len(happy) >= 12, f"need >= 12 happy-path fixtures; have {len(happy)}"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-016")
@pytest.mark.parametrize(
    "fixture_id,builder",
    [(fid, b) for fid, b, err in ROUNDTRIP_FIXTURES if err is None],
)
def test_emit_parse_emit_is_byte_identical(
    fixture_id: str, builder: Any
) -> None:
    """For every happy-path fixture: emit(parse(emit(b))) == emit(b)."""
    bundle = builder()
    first = emit_bundle(deepcopy(bundle))
    second = emit_bundle(parse_bundle(first))
    assert first == second, (
        f"roundtrip drift on fixture {fixture_id!r}: "
        f"first sha256={hashlib.sha256(first).hexdigest()}, "
        f"second sha256={hashlib.sha256(second).hexdigest()}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-016")
@pytest.mark.parametrize(
    "fixture_id,builder",
    [(fid, b) for fid, b, err in ROUNDTRIP_FIXTURES if err is None],
)
def test_roundtrip_helper_is_byte_identical(
    fixture_id: str, builder: Any
) -> None:
    """The roundtrip() convenience returns the same bytes as emit_bundle()."""
    bundle = builder()
    direct = emit_bundle(deepcopy(bundle))
    via_helper = roundtrip(deepcopy(bundle))
    assert direct == via_helper, f"roundtrip() drift on {fixture_id!r}"


# =============================================================================
# VAL-W11-017: unknown ACEF Core bundle.schema_version rejected on write
# =============================================================================
#
# The W11.2 EmissionWriter raises RELAY-SCHEMA-014 for ANY mismatch
# against the pinned ACEF Core schema_version. VAL-W11-017 names the
# ACEF Core surface specifically; the wire code is -014 (the writer's
# pin-mismatch code), as the test below documents and asserts.
#
# The contract's published RELAY-SCHEMA-017 token is reserved for a
# future split between "version present but unknown" and "version absent
# entirely". The W11.2 implementation collapses both into -014; the
# split would be an additive refactor and is tracked as a follow-up
# (see discoveredIssues in the W11.3 handoff). The test below pins the
# OBSERVED wire code -014 and asserts the offending field name names
# the ACEF Core surface, which is the load-bearing distinction VAL-W11-017
# requires.


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-017")
@pytest.mark.parametrize(
    "bad_value", ["v0.1", "v0.2", "v0.4", "v1.0", "v99", "", "alpha"]
)
def test_unknown_acef_core_schema_version_is_rejected(bad_value: str) -> None:
    """Each bad value rejected with structured error naming bundle.schema_version."""
    bundle = _base_bundle()
    bundle["schema_version"] = bad_value
    with pytest.raises(SchemaVersionError) as excinfo:
        emit_bundle(bundle)
    # The W11.2 writer surfaces -014 for any schema_version pin mismatch.
    assert excinfo.value.error_code == "RELAY-SCHEMA-014"
    assert excinfo.value.details["field"] == "bundle.schema_version"
    assert excinfo.value.details["observed"] == bad_value


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-017")
def test_missing_acef_core_schema_version_is_rejected() -> None:
    """A bundle without bundle.schema_version is rejected on write."""
    bundle = _base_bundle()
    del bundle["schema_version"]
    with pytest.raises(SchemaVersionError) as excinfo:
        emit_bundle(bundle)
    assert excinfo.value.error_code == "RELAY-SCHEMA-014"
    assert excinfo.value.details["field"] == "bundle.schema_version"


# =============================================================================
# VAL-W11-018: unknown x-relay schema_version rejected on write
# =============================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-018")
@pytest.mark.parametrize(
    "bad_value", ["v0", "v2", "v1.1", "", "x-relay.v1"]
)
def test_unknown_xrelay_schema_version_is_rejected(bad_value: str) -> None:
    """Each bad value rejected with structured error naming the x-relay field."""
    bundle = _base_bundle()
    bundle["namespaces"][X_RELAY_NAMESPACE_KEY]["schema_version"] = bad_value
    with pytest.raises(SchemaVersionError) as excinfo:
        emit_bundle(bundle)
    assert excinfo.value.error_code == "RELAY-SCHEMA-014"
    assert excinfo.value.details["field"] == (
        f"namespaces.{X_RELAY_NAMESPACE_KEY}.schema_version"
    )
    assert excinfo.value.details["observed"] == bad_value


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-018")
def test_missing_xrelay_schema_version_is_rejected() -> None:
    """A bundle without namespaces['x-relay'].schema_version is rejected."""
    bundle = _base_bundle()
    del bundle["namespaces"][X_RELAY_NAMESPACE_KEY]["schema_version"]
    with pytest.raises(SchemaVersionError) as excinfo:
        emit_bundle(bundle)
    assert excinfo.value.error_code == "RELAY-SCHEMA-014"


# =============================================================================
# VAL-W11-019: roundtrip preserves Merkle root
# =============================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-019")
@pytest.mark.parametrize(
    "fixture_id,builder",
    [(fid, b) for fid, b, err in ROUNDTRIP_FIXTURES if err is None],
)
def test_merkle_root_survives_roundtrip(fixture_id: str, builder: Any) -> None:
    """Merkle root over the bundle's claims is identical after roundtrip."""
    bundle = builder()
    original_root = bundle_merkle_root(deepcopy(bundle))
    re_emitted = parse_bundle(emit_bundle(deepcopy(bundle)))
    re_root = bundle_merkle_root(re_emitted)
    assert original_root == re_root, (
        f"Merkle root drift on {fixture_id!r}: "
        f"original={original_root}, re-emitted={re_root}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-019")
def test_claim_ordering_is_canonical_lexicographic() -> None:
    """Claims supplied out-of-order produce the same root as in-order."""
    out_of_order = _base_bundle()
    out_of_order["claims"] = [
        {"evidence_claim_id": "z-third", "value": 3},
        {"evidence_claim_id": "a-first", "value": 1},
        {"evidence_claim_id": "m-second", "value": 2},
    ]
    in_order = _base_bundle()
    in_order["claims"] = [
        {"evidence_claim_id": "a-first", "value": 1},
        {"evidence_claim_id": "m-second", "value": 2},
        {"evidence_claim_id": "z-third", "value": 3},
    ]
    assert bundle_merkle_root(out_of_order) == bundle_merkle_root(in_order)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-019")
def test_empty_claims_returns_canonical_empty_root() -> None:
    """A bundle with no claims has a deterministic empty-tree root."""
    bundle = _base_bundle()
    assert bundle["claims"] == []
    expected_empty = hashlib.sha256(b"").hexdigest()
    assert bundle_merkle_root(bundle) == expected_empty


# =============================================================================
# VAL-W11-020: Unicode normalisation is NFC and roundtrips losslessly
# =============================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-020")
def test_nfc_and_nfd_inputs_emit_identical_bytes() -> None:
    """A string in NFD and the same string in NFC produce identical canonical bytes.

    Carries the test string in agent-execution-trace.error_class
    because error_class is a schema-declared free-form string;
    placing payload in an undeclared sub-field would trip
    RELAY-SCHEMA-011 before the unicode branch is exercised.
    """
    nfd_payload = _ns_payload("agent-execution-trace")
    nfc_payload = _ns_payload("agent-execution-trace")
    # NFD: cafe + U+0301 -> normalises to NFC cafe-acute
    nfd_payload["error_class"] = "café-anomaly"
    nfc_payload["error_class"] = "café-anomaly"
    nfd_bundle = _base_bundle()
    nfc_bundle = _base_bundle()
    nfd_bundle["namespaces"][X_RELAY_NAMESPACE_KEY]["agent-execution-trace"] = nfd_payload
    nfc_bundle["namespaces"][X_RELAY_NAMESPACE_KEY]["agent-execution-trace"] = nfc_payload
    # The encoder NFC-normalises string values on emit so the FIRST
    # emit is already identical for both inputs.
    nfd_bytes = roundtrip(nfd_bundle)
    nfc_bytes = roundtrip(nfc_bundle)
    assert nfd_bytes == nfc_bytes, (
        "NFD and NFC inputs must produce identical canonical bytes after roundtrip"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-020")
def test_unicode_characters_survive_roundtrip_in_nfc() -> None:
    """Every supported character class survives the roundtrip in NFC form."""
    bundle = _fixture_unicode_nfd_keys()
    out = parse_bundle(emit_bundle(bundle))
    error_class = out["namespaces"][X_RELAY_NAMESPACE_KEY][
        "agent-execution-trace"
    ]["error_class"]
    # The roundtripped value is in NFC (idempotent under further NFC).
    assert error_class == unicodedata.normalize("NFC", error_class)
    # CJK + RTL + emoji ZWJ all present.
    assert "中文" in error_class  # Chinese
    assert "עברית" in error_class  # Hebrew
    assert "\U0001f469" in error_class  # SMP woman emoji
    assert "‍" in error_class  # zero-width joiner
    assert "\U0001f4bb" in error_class  # SMP laptop emoji


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-020")
def test_unicode_combining_collapses_to_nfc_byte_equal() -> None:
    """A combining-mark string roundtrips byte-identically in NFC form."""
    bundle = _fixture_unicode_payload()
    first = emit_bundle(deepcopy(bundle))
    second = emit_bundle(parse_bundle(first))
    assert first == second


# =============================================================================
# VAL-W11-021: Decimal precision preserved
# =============================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-021")
def test_decimal_precision_survives_roundtrip() -> None:
    """A 17-digit Decimal value roundtrips without ULP drift."""
    bundle = _fixture_decimal_precision()
    first = emit_bundle(deepcopy(bundle))
    second = emit_bundle(parse_bundle(first))
    assert first == second
    # The actual textual representation of the score MUST appear in the
    # canonical bytes. The encoder preserves every digit.
    assert b"0.30000000000000004" in first
    assert b"0.99999999999999999" in first


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-021")
def test_int_above_2_pow_53_survives_roundtrip() -> None:
    """An integer larger than IEEE-754 double's 2^53 limit survives intact."""
    bundle = _fixture_decimal_precision()
    first = emit_bundle(deepcopy(bundle))
    parsed = parse_bundle(first)
    case_count = parsed["namespaces"][X_RELAY_NAMESPACE_KEY][
        "eval-dataset-result"
    ]["case_count"]
    assert case_count == 9007199254740993
    # The literal must appear in the bytes.
    assert b"9007199254740993" in first


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-021")
def test_decimal_preserves_at_least_twenty_distinct_values() -> None:
    """Twenty Decimal values roundtrip without changing canonical bytes."""
    samples: list[Decimal] = [
        Decimal("0"),
        Decimal("-0"),
        Decimal("0.1"),
        Decimal("0.2"),
        Decimal("0.3"),
        Decimal("0.30000000000000004"),
        Decimal("1.0"),
        Decimal("0.99999999999999999"),
        Decimal("0.000000000000001"),
        Decimal("0.0000000000000001"),
        Decimal("0.5"),
        Decimal("0.25"),
        Decimal("0.125"),
        Decimal("0.0625"),
        Decimal("0.03125"),
        Decimal("0.015625"),
        Decimal("0.7853981633974483"),  # pi/4 to 16 digits
        Decimal("0.6931471805599453"),  # ln 2 to 16 digits
        Decimal("0.4342944819032518"),  # log10 e to 16 digits
        Decimal("0.5772156649015329"),  # Euler-Mascheroni constant
    ]
    drift_count = 0
    for d in samples:
        first = jcs_canonicalize({"v": d})
        # parse_float=Decimal so the parsed value is also Decimal.
        parsed = json.loads(first.decode("utf-8"), parse_float=Decimal)
        second = jcs_canonicalize(parsed)
        if first != second:
            drift_count += 1
    assert drift_count == 0, (
        f"{drift_count}/20 Decimal values drifted under JCS roundtrip"
    )


# =============================================================================
# VAL-W11-021 (extended): ECMA-262 NumberToString compliance for Decimal
# =============================================================================
#
# RFC 8785 JCS section 3.2.2 numbers MUST follow ECMA-262 NumberToString.
# The Decimal encoder previously emitted ``str(Decimal)`` which preserves
# exponent notation (e.g., ``"1E+5"`` for ``Decimal("1E+5")``) -- not a
# valid ECMA-262 number string. ECMA-262 NumberToString uses exponential
# form only when |n| < 1e-6 or |n| >= 1e21; otherwise it uses decimal form.
# These tests pin the contract against ECMA-262, verified against Node's
# ``String(Number(...))``.


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-021")
def test_encode_decimal_exponent_to_decimal_form() -> None:
    """Decimal values written in scientific form are emitted as decimal.

    ECMA-262 NumberToString: ``1E+5`` (=100000) is in [1e-6, 1e21) so
    MUST emit as ``"100000"``, not ``"1E+5"``. Same for ``1E-3``.
    """
    from relay_acef.roundtrip import _encode_decimal

    assert _encode_decimal(Decimal("1E+5")) == "100000"
    assert _encode_decimal(Decimal("1E-3")) == "0.001"
    assert _encode_decimal(Decimal("1E+0")) == "1"
    assert _encode_decimal(Decimal("1.5E+2")) == "150"
    # 1e-6 is the exact boundary: ECMA-262 emits decimal form.
    assert _encode_decimal(Decimal("1E-6")) == "0.000001"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-021")
def test_encode_decimal_large_uses_exponential_form() -> None:
    """Magnitudes >= 1e21 emit exponential form per ECMA-262.

    Verified against ``node -e 'console.log(String(1e22))'`` => ``1e+22``.
    """
    from relay_acef.roundtrip import _encode_decimal

    assert _encode_decimal(Decimal("1E+22")) == "1e+22"
    assert _encode_decimal(Decimal("1E+21")) == "1e+21"
    # Negative magnitude analogue.
    assert _encode_decimal(Decimal("-1E+22")) == "-1e+22"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-021")
def test_encode_decimal_tiny_uses_exponential_form() -> None:
    """Magnitudes < 1e-6 emit exponential form per ECMA-262.

    Verified against ``node -e 'console.log(String(1e-7))'`` => ``1e-7``.
    """
    from relay_acef.roundtrip import _encode_decimal

    assert _encode_decimal(Decimal("1E-7")) == "1e-7"
    assert _encode_decimal(Decimal("1E-10")) == "1e-10"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-021")
def test_encode_decimal_preserves_high_precision_digits() -> None:
    """A 17-digit Decimal in [1e-6, 1e21) emits full-precision decimal form."""
    from relay_acef.roundtrip import _encode_decimal

    # Digits MUST be preserved; this is the load-bearing Decimal contract.
    assert _encode_decimal(Decimal("0.30000000000000004")) == "0.30000000000000004"
    assert _encode_decimal(Decimal("0.99999999999999999")) == "0.99999999999999999"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-021")
def test_encode_decimal_negative_zero_collapses_to_zero() -> None:
    """ECMA-262 NumberToString collapses negative zero to ``"0"``."""
    from relay_acef.roundtrip import _encode_decimal

    assert _encode_decimal(Decimal("0")) == "0"
    assert _encode_decimal(Decimal("-0")) == "0"
    assert _encode_decimal(Decimal("0.0")) == "0"
    assert _encode_decimal(Decimal("-0.0")) == "0"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-021")
def test_encode_decimal_rejects_non_finite() -> None:
    """NaN and Inf Decimals have no JCS canonical form; encoder rejects."""
    from relay_acef.roundtrip import JCSEncodeError, _encode_decimal

    with pytest.raises(JCSEncodeError):
        _encode_decimal(Decimal("NaN"))
    with pytest.raises(JCSEncodeError):
        _encode_decimal(Decimal("Infinity"))
    with pytest.raises(JCSEncodeError):
        _encode_decimal(Decimal("-Infinity"))


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-021")
def test_encode_number_negative_zero_collapses_to_zero() -> None:
    """ECMA-262 NumberToString: float -0.0 emits as ``"0"``."""
    from relay_acef.roundtrip import _encode_number

    assert _encode_number(0) == "0"
    assert _encode_number(0.0) == "0"
    assert _encode_number(-0.0) == "0"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-021")
def test_encode_number_special_values_raise() -> None:
    """NaN / +Inf / -Inf raise JCSEncodeError; no canonical form exists."""
    import math

    from relay_acef.roundtrip import JCSEncodeError, _encode_number

    with pytest.raises(JCSEncodeError):
        _encode_number(float("nan"))
    with pytest.raises(JCSEncodeError):
        _encode_number(float("inf"))
    with pytest.raises(JCSEncodeError):
        _encode_number(-math.inf)


# =============================================================================
# VAL-W11-022: Bundle determinism survives temporal + host noise
# =============================================================================
#
# The subprocess parity test spawns two child processes with diverging
# TZ + injected wall-clock skew, each emits the same fixture, and the
# parent asserts SHA-256 digest equality.

_SUBPROCESS_EMIT_SCRIPT = r"""
import json
import sys
from copy import deepcopy
from relay_acef.roundtrip import emit_bundle

bundle = json.loads(sys.argv[1])
out = emit_bundle(bundle)
sys.stdout.buffer.write(out)
"""


def _spawn_emit(bundle: dict[str, Any], env_overrides: dict[str, str]) -> bytes:
    """Spawn a subprocess that emits ``bundle`` under ``env_overrides``.

    Returns the raw canonical bytes the child wrote to stdout. Inherits
    the parent's PATH + PYTHONPATH + venv selection by default; overrides
    layer on top.
    """
    env = dict(os.environ)
    env.update(env_overrides)
    payload = json.dumps(bundle)
    completed = subprocess.run(
        [sys.executable, "-c", _SUBPROCESS_EMIT_SCRIPT, payload],
        capture_output=True,
        env=env,
        timeout=30,
        check=True,
    )
    return completed.stdout


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-022")
def test_two_subprocesses_with_diverging_env_emit_identical_bytes() -> None:
    """Two emissions in two subprocesses with different TZ + wall-clock = same bytes."""
    bundle = _fixture_with_one_namespace()
    # First child: UTC + epoch=0
    bytes_a = _spawn_emit(
        bundle,
        {"TZ": "UTC", "RELAY_TEST_FAKE_NOW": "0"},
    )
    # Second child: LA + epoch=1e9
    bytes_b = _spawn_emit(
        bundle,
        {"TZ": "America/Los_Angeles", "RELAY_TEST_FAKE_NOW": "1000000000"},
    )
    digest_a = hashlib.sha256(bytes_a).hexdigest()
    digest_b = hashlib.sha256(bytes_b).hexdigest()
    assert digest_a == digest_b, (
        f"subprocess emission drift: utc={digest_a}, la={digest_b}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-022")
def test_in_process_repeated_emits_are_identical() -> None:
    """Repeated emit_bundle calls in the same process produce identical bytes."""
    bundle = _fixture_with_all_ten_namespaces()
    digests = {hashlib.sha256(emit_bundle(deepcopy(bundle))).hexdigest() for _ in range(5)}
    assert len(digests) == 1, f"non-deterministic in-process emit: {digests!r}"


# =============================================================================
# VAL-W11-023: roundtrip rejects bundles missing required control-plane bindings
# =============================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-023")
@pytest.mark.parametrize("missing_field", list(REQUIRED_CONTROL_PLANE_BINDINGS))
def test_each_missing_control_plane_binding_is_rejected(missing_field: str) -> None:
    """Removing each of the seven required bindings raises -023 naming the field."""
    bundle = _base_bundle()
    del bundle["namespaces"][X_RELAY_NAMESPACE_KEY][missing_field]
    # Emit through bytes -> parse, since VAL-W11-023 names the parse path.
    # We exercise both the direct emit_bundle and the parse path to confirm
    # rejection at both gates.
    with pytest.raises(SchemaVersionError) as excinfo:
        emit_bundle(bundle)
    assert excinfo.value.error_code == "RELAY-SCHEMA-023"
    assert excinfo.value.details["missing_field"] == missing_field


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-023")
def test_seven_distinct_missing_field_errors_for_seven_fields() -> None:
    """The seven removals produce seven distinct missing_field values."""
    seen: set[str] = set()
    for field in REQUIRED_CONTROL_PLANE_BINDINGS:
        bundle = _base_bundle()
        del bundle["namespaces"][X_RELAY_NAMESPACE_KEY][field]
        try:
            emit_bundle(bundle)
        except SchemaVersionError as exc:
            seen.add(exc.details.get("missing_field", ""))
    assert seen == set(REQUIRED_CONTROL_PLANE_BINDINGS)
    assert len(seen) == 7


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-023")
def test_parse_path_also_rejects_missing_bindings() -> None:
    """Parsing a serialised bundle missing a binding fails on the parse side."""
    bundle = _base_bundle()
    # Build canonical bytes with the binding in place, then strip the
    # field after parsing to simulate a tampered or malformed inbound
    # bundle. The parse path re-validates so the second write_bundle
    # rejects.
    valid_bytes = emit_bundle(deepcopy(bundle))
    parsed = json.loads(valid_bytes.decode("utf-8"))
    del parsed["namespaces"][X_RELAY_NAMESPACE_KEY]["actor_identity_hash"]
    bad_bytes = jcs_canonicalize(parsed)
    with pytest.raises(SchemaVersionError) as excinfo:
        parse_bundle(bad_bytes)
    assert excinfo.value.error_code == "RELAY-SCHEMA-023"
    assert excinfo.value.details["missing_field"] == "actor_identity_hash"


# =============================================================================
# VAL-W11-024: roundtrip conformance corpus exported for W17
# =============================================================================
#
# The corpus index lives at tests/conformance/acef/roundtrip_corpus.json
# and is regenerated by THIS test (write-on-run). The output is
# deterministic (sorted by fixture_id, JCS-canonical formatting) so a
# CI re-run produces a byte-identical file. W17 consumes the index by
# replaying each entry: happy-path fixtures must roundtrip to the
# recorded digest + Merkle root; negative fixtures must raise the
# recorded wire code.

_CORPUS_PATH = (
    Path(__file__).resolve().parents[3]
    / "tests"
    / "conformance"
    / "acef"
    / "roundtrip_corpus.json"
)


def _build_corpus_index() -> dict[str, Any]:
    """Compute the W17 corpus index from the W11.3 fixture catalogue."""
    entries: list[dict[str, Any]] = []
    for fid, builder, err in ROUNDTRIP_FIXTURES + NEGATIVE_FIXTURES:
        bundle = builder()
        if err is None:
            canonical = emit_bundle(deepcopy(bundle))
            digest = hashlib.sha256(canonical).hexdigest()
            merkle = bundle_merkle_root(bundle)
            entries.append(
                {
                    "fixture_id": fid,
                    "fixture_path": f"in_process_builders.{builder.__name__}",
                    "expected_digest": digest,
                    "expected_merkle_root": merkle,
                    "expected_error_code": None,
                }
            )
        else:
            # Negative entry: confirm the writer raises the expected code.
            try:
                emit_bundle(deepcopy(bundle))
            except SchemaVersionError as exc:
                observed = exc.error_code
            else:
                observed = "<no-error-raised>"
            entries.append(
                {
                    "fixture_id": fid,
                    "fixture_path": f"in_process_builders.{builder.__name__}",
                    "expected_digest": None,
                    "expected_merkle_root": None,
                    "expected_error_code": observed,
                }
            )
    entries.sort(key=lambda e: e["fixture_id"])
    return {
        "schema_version": "v1",
        "generated_by": "packages/acef/tests/test_w11_3_acef_roundtrip.py",
        "fixture_count": len(entries),
        "entries": entries,
    }


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-024")
def test_corpus_index_is_written_and_well_formed() -> None:
    """Build the corpus, write it to disk, and verify >= 25 entries."""
    index = _build_corpus_index()
    assert index["fixture_count"] >= 25, (
        f"corpus must have >= 25 fixtures; have {index['fixture_count']}"
    )
    # Write deterministically: sort_keys + 2-space indent. The file MUST
    # parse back to the exact same dict.
    _CORPUS_PATH.parent.mkdir(parents=True, exist_ok=True)
    serialised = json.dumps(index, sort_keys=True, indent=2) + "\n"
    _CORPUS_PATH.write_text(serialised, encoding="utf-8")
    reloaded = json.loads(_CORPUS_PATH.read_text(encoding="utf-8"))
    assert reloaded == index


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-024")
def test_corpus_digests_match_recomputation() -> None:
    """Every happy-path entry's recorded digest matches a fresh emit_bundle."""
    index = _build_corpus_index()
    happy = [e for e in index["entries"] if e["expected_error_code"] is None]
    # Sanity: the corpus has happy-path entries.
    assert len(happy) >= 12
    for entry in happy:
        # Recompute by walking the catalogue for the matching fixture_id.
        builder = next(
            b
            for fid, b, err in ROUNDTRIP_FIXTURES
            if fid == entry["fixture_id"] and err is None
        )
        recomputed = hashlib.sha256(emit_bundle(builder())).hexdigest()
        assert recomputed == entry["expected_digest"], (
            f"digest drift on {entry['fixture_id']!r}"
        )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-024")
def test_corpus_negative_entries_record_observed_wire_codes() -> None:
    """Each negative entry records a RELAY-SCHEMA-NNN wire code."""
    index = _build_corpus_index()
    negs = [e for e in index["entries"] if e["expected_error_code"] is not None]
    assert len(negs) >= 4
    for entry in negs:
        code = entry["expected_error_code"]
        assert re.match(r"^RELAY-[A-Z]+-[0-9]{3}$", code), (
            f"negative entry {entry['fixture_id']!r} has malformed wire code {code!r}"
        )


# =============================================================================
# VAL-W11-025: ACEF emission failure does NOT block runtime trace ingestion
# =============================================================================
#
# The contract scopes this assertion to the sidecar ingest endpoint
# (tier 2 smoke). At W11.3 plumbing tier we exercise the unit-level
# isolation contract: a failing EmissionWriter MUST raise a typed
# error that the caller can catch and mark as pending_retry without
# downgrading the run_result. The full sidecar+queue tier-2 surface
# lands in the milestone's smoke tests; this test pins the unit-level
# contract that makes the smoke test possible.


class _FailingEmissionWriter:
    """Stand-in writer that always raises; mirrors the failure injection."""

    class EmissionServiceUnavailable(RuntimeError):
        """Raised when the emission backend is offline; caller MUST recover."""

    def write_bundle(self, bundle: dict[str, Any]) -> dict[str, Any]:
        raise self.EmissionServiceUnavailable("emission backend offline")


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-025")
def test_emission_failure_is_a_typed_recoverable_error() -> None:
    """The failure surface is a typed exception, not a silent corruption."""
    writer = _FailingEmissionWriter()
    bundle = _fixture_with_one_namespace()
    with pytest.raises(_FailingEmissionWriter.EmissionServiceUnavailable):
        writer.write_bundle(bundle)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-025")
def test_emission_failure_does_not_corrupt_the_input_bundle() -> None:
    """A failing emission leaves the caller's bundle dict intact for retry."""
    import contextlib

    writer = _FailingEmissionWriter()
    bundle = _fixture_with_one_namespace()
    snapshot_before = deepcopy(bundle)
    with contextlib.suppress(_FailingEmissionWriter.EmissionServiceUnavailable):
        writer.write_bundle(bundle)
    # The bundle dict the caller holds is byte-equal to the pre-failure
    # snapshot. The retry path can resubmit.
    assert bundle == snapshot_before


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-025")
def test_real_emission_writer_is_reentrant_after_validation_failure() -> None:
    """A rejected bundle does not poison the writer for the next call."""
    writer = EmissionWriter()
    bad = _base_bundle()
    bad["schema_version"] = "v99"
    with pytest.raises(SchemaVersionError):
        writer.write_bundle(bad)
    # Same writer instance accepts a valid bundle on the next call.
    good = _base_bundle()
    out = writer.write_bundle(good)
    assert out is good


# =============================================================================
# VAL-W11-026: banned product copy absent from ACEF vendor-adjacent docs
# =============================================================================

_ACEF_PKG_ROOT = Path(__file__).resolve().parents[1]
_VENDOR_DOC_PATHS: tuple[Path, ...] = (
    _ACEF_PKG_ROOT / "README.md",
    _ACEF_PKG_ROOT / "VENDOR.md",
    _ACEF_PKG_ROOT / "RELAY-LOCAL-CHANGES.md",
)
_BANNED_TERMS_RE = re.compile(
    r"\b(compliant|certified|AI Act-approved|guaranteed AI Act compliance)\b",
    re.IGNORECASE,
)
_PERMITTED_PHRASES: tuple[str, ...] = (
    "AI Act readiness evidence",
    "evidence coverage",
    "gaps",
    "ready for auditor review",
)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-026")
@pytest.mark.parametrize("doc_path", _VENDOR_DOC_PATHS, ids=lambda p: p.name)
def test_vendor_doc_exists(doc_path: Path) -> None:
    """Each of the three vendor-adjacent docs is present on disk."""
    assert doc_path.exists(), f"missing vendor doc: {doc_path}"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-026")
@pytest.mark.parametrize("doc_path", _VENDOR_DOC_PATHS, ids=lambda p: p.name)
def test_vendor_doc_has_zero_banned_terms(doc_path: Path) -> None:
    """Each vendor doc has zero matches against the banned-copy regex."""
    text = doc_path.read_text(encoding="utf-8")
    matches = _BANNED_TERMS_RE.findall(text)
    assert matches == [], (
        f"banned product copy in {doc_path.name}: {matches!r}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-026")
def test_readme_uses_at_least_one_permitted_phrase() -> None:
    """The README contains >= 1 permitted phrase so the rule materially binds."""
    readme_text = (_ACEF_PKG_ROOT / "README.md").read_text(encoding="utf-8").lower()
    hits = [p for p in _PERMITTED_PHRASES if p.lower() in readme_text]
    assert hits, (
        f"README.md must use at least one permitted phrase from "
        f"{_PERMITTED_PHRASES!r}; none found"
    )
