"""W9.2 assertion-template library plumbing tests.

Covers VAL-W9-009 .. VAL-W9-015 per the W9.2 contract block in
``/Users/chandlervaughn/.ops-runtime/relay-v0.1-oss-wedge/contract.md``.

Tier-1 plumbing only -- the templates are pure, deterministic, offline.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import re
from typing import Any

import pytest
from relay_evals import (
    ASSERTION_ID_PATTERN,
    COVERAGE_TEMPLATE_NAME,
    COVERAGE_TEMPLATE_SCHEMA,
    KNOWN_SCHEMA_IDS,
    REGISTERED_TEMPLATES,
    SCHEMA_MATCH_TEMPLATE_NAME,
    SCHEMA_MATCH_TEMPLATE_SCHEMA,
    SIGNED_BUNDLED_MARKER,
    TOOL_ARG_TEMPLATE_NAME,
    TOOL_ARG_TEMPLATE_SCHEMA,
    CoverageTemplateResult,
    RelayManifestUnknownToolError,
    RelaySchemaNotFoundError,
    RelayTemplateInputError,
    RelayTemplateLoaderError,
    SchemaMatchTemplateResult,
    ToolArgTemplateResult,
    coverage_assertion_template,
    derive_assertion_id,
    get_template,
    invoke_template,
    list_template_names,
    load_template_from_path,
    schema_match_assertion_template,
    tool_arg_assertion_template,
)
from relay_schemas.error_codes import RelayErrorCode

pytestmark = pytest.mark.plumbing


SHA256_FIXTURE = "sha256-" + ("ab12" * 16)


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------


def _coverage_bundle(
    *,
    assertions: list[dict[str, Any]] | None = None,
    label: str = "BUNDLE-A",
) -> dict[str, Any]:
    if assertions is None:
        assertions = [
            {
                "assertion_id": "VAL-DEMO-001",
                "severity": "p0",
                "owner_email": "alice@example.com",
                "expression_digest": "digest-a",
                "lifecycle_state": "active",
            },
            {
                "assertion_id": "VAL-DEMO-002",
                "severity": "p2",
                "owner_email": None,
                "expression_digest": "digest-b",
                "lifecycle_state": "active",
            },
        ]
    return {
        "schema_version": COVERAGE_TEMPLATE_SCHEMA,
        "assertions": assertions,
        "input_label": label,
    }


def _tool_arg_input(
    *,
    tool_name: str = "fetch_url",
    tool_registry: dict[str, Any] | None = None,
    manifest_commit_hash: str = SHA256_FIXTURE,
) -> dict[str, Any]:
    if tool_registry is None:
        tool_registry = {
            "fetch_url": {"side_effect_class": "read_only"},
            "create_ticket": {"side_effect_class": "external_irreversible"},
        }
    return {
        "schema_version": TOOL_ARG_TEMPLATE_SCHEMA,
        "tool_name": tool_name,
        "args_schema": {"type": "object", "required": ["case_id"]},
        "manifest_commit_hash": manifest_commit_hash,
        "tool_registry": tool_registry,
    }


def _schema_match_input(*, schema_id: str = "relay.run_result.v1") -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_MATCH_TEMPLATE_SCHEMA,
        "schema_id": schema_id,
    }


# =============================================================================
# VAL-W9-009 -- three named templates registered + introspectable
# =============================================================================


@pytest.mark.fulfills("VAL-W9-009")
def test_three_templates_exist_at_public_api_surface() -> None:
    """VAL-W9-009: at least three named templates are exposed.

    Each template is importable by its canonical name from the package
    root. The registry's list_template_names() returns them sorted.
    """
    names = list_template_names()
    assert len(names) >= 3
    assert COVERAGE_TEMPLATE_NAME in names
    assert TOOL_ARG_TEMPLATE_NAME in names
    assert SCHEMA_MATCH_TEMPLATE_NAME in names
    # Sorted lex output is the contract.
    assert list(names) == sorted(names)


@pytest.mark.fulfills("VAL-W9-009")
def test_each_template_is_callable_via_registry() -> None:
    """Each registered template is invokable via the registry surface."""
    for name in (
        COVERAGE_TEMPLATE_NAME,
        TOOL_ARG_TEMPLATE_NAME,
        SCHEMA_MATCH_TEMPLATE_NAME,
    ):
        entry = get_template(name)
        assert entry.name == name
        assert entry.schema_id  # non-empty
        assert callable(entry.call)


# =============================================================================
# VAL-W9-010 -- structured input validation + RelayTemplateInputError
# =============================================================================


@pytest.mark.fulfills("VAL-W9-010")
def test_coverage_template_accepts_valid_input() -> None:
    result = coverage_assertion_template(_coverage_bundle())
    assert isinstance(result, CoverageTemplateResult)
    assert result.schema_id == COVERAGE_TEMPLATE_SCHEMA


@pytest.mark.fulfills("VAL-W9-010")
@pytest.mark.parametrize(
    "mutator, expected_path",
    [
        # Wrong top-level type
        (lambda b: "not-a-mapping", "$"),
        # Missing required field
        (lambda b: {k: v for k, v in b.items() if k != "schema_version"},
         "$.schema_version"),
        # Unknown field (additionalProperties: false)
        (lambda b: {**b, "evil": True}, "$.evil"),
    ],
)
def test_coverage_template_rejects_invalid_inputs(
    mutator: Any, expected_path: str
) -> None:
    bundle = _coverage_bundle()
    bad = mutator(bundle)
    with pytest.raises(RelayTemplateInputError) as ei:
        coverage_assertion_template(bad)
    assert ei.value.payload["json_path"] == expected_path


@pytest.mark.fulfills("VAL-W9-010")
def test_tool_arg_template_rejects_invalid_manifest_hash() -> None:
    payload = _tool_arg_input(manifest_commit_hash="not-a-sha256")
    with pytest.raises(RelayTemplateInputError) as ei:
        tool_arg_assertion_template(payload)
    assert ei.value.payload["json_path"] == "$.manifest_commit_hash"


@pytest.mark.fulfills("VAL-W9-010")
def test_schema_match_template_rejects_inline_schema_body() -> None:
    payload = _schema_match_input()
    payload["schema_body"] = {"type": "object"}  # forbidden in v0.1
    with pytest.raises(RelayTemplateInputError) as ei:
        schema_match_assertion_template(payload)
    assert ei.value.payload["json_path"] == "$.schema_body"


@pytest.mark.fulfills("VAL-W9-010")
def test_schema_match_template_rejects_unknown_top_level_field() -> None:
    payload = _schema_match_input()
    payload["extra"] = "x"
    with pytest.raises(RelayTemplateInputError) as ei:
        schema_match_assertion_template(payload)
    assert ei.value.payload["json_path"] == "$.extra"


# =============================================================================
# VAL-W9-011 -- canonical assertion id format + determinism
# =============================================================================


@pytest.mark.fulfills("VAL-W9-011")
def test_derive_assertion_id_matches_canonical_regex() -> None:
    pattern = re.compile(ASSERTION_ID_PATTERN)
    aid = derive_assertion_id(domain="TEST", slug="x", seed={"a": 1})
    assert pattern.match(aid), aid


@pytest.mark.fulfills("VAL-W9-011")
def test_each_template_returns_canonical_assertion_id() -> None:
    pattern = re.compile(ASSERTION_ID_PATTERN)
    r1 = coverage_assertion_template(_coverage_bundle())
    r2 = tool_arg_assertion_template(_tool_arg_input())
    r3 = schema_match_assertion_template(_schema_match_input())
    for r in (r1, r2, r3):
        assert pattern.match(r.assertion_id), r.assertion_id


@pytest.mark.fulfills("VAL-W9-011")
def test_coverage_template_id_is_deterministic_across_two_calls() -> None:
    """Same input twice -> same assertion_id."""
    bundle = _coverage_bundle()
    r1 = coverage_assertion_template(bundle)
    r2 = coverage_assertion_template(bundle)
    assert r1.assertion_id == r2.assertion_id
    assert r1.input_digest == r2.input_digest


@pytest.mark.fulfills("VAL-W9-011")
def test_coverage_template_id_changes_on_different_inputs() -> None:
    """Different inputs -> different assertion_ids."""
    r1 = coverage_assertion_template(_coverage_bundle(label="BUNDLE-A"))
    r2 = coverage_assertion_template(_coverage_bundle(label="BUNDLE-B"))
    assert r1.assertion_id != r2.assertion_id


@pytest.mark.fulfills("VAL-W9-011")
def test_tool_arg_template_id_is_deterministic() -> None:
    p = _tool_arg_input()
    r1 = tool_arg_assertion_template(p)
    r2 = tool_arg_assertion_template(p)
    assert r1.assertion_id == r2.assertion_id


@pytest.mark.fulfills("VAL-W9-011")
def test_schema_match_template_id_is_deterministic_and_distinguishes_ids() -> None:
    r1 = schema_match_assertion_template(_schema_match_input(schema_id="relay.run_result.v1"))
    r2 = schema_match_assertion_template(_schema_match_input(schema_id="relay.run_result.v1"))
    r3 = schema_match_assertion_template(_schema_match_input(schema_id="relay.gate_decision.v1"))
    assert r1.assertion_id == r2.assertion_id
    assert r1.assertion_id != r3.assertion_id


# =============================================================================
# VAL-W9-012 -- signed registry + loader refusal
# =============================================================================


@pytest.mark.fulfills("VAL-W9-012")
def test_load_template_from_path_always_raises() -> None:
    """v0.1 forbids loading templates from disk paths."""
    with pytest.raises(RelayTemplateLoaderError) as ei:
        load_template_from_path("/tmp/evil-template.py")
    assert ei.value.payload["disallowed_path"] == "/tmp/evil-template.py"
    assert set(ei.value.payload["permitted_names"]) == {
        COVERAGE_TEMPLATE_NAME,
        TOOL_ARG_TEMPLATE_NAME,
        SCHEMA_MATCH_TEMPLATE_NAME,
    }


@pytest.mark.fulfills("VAL-W9-012")
def test_get_template_rejects_unknown_name() -> None:
    with pytest.raises(RelayTemplateLoaderError) as ei:
        get_template("nope_not_real_template")
    assert ei.value.payload["requested_name"] == "nope_not_real_template"


@pytest.mark.fulfills("VAL-W9-012")
def test_invoke_template_uses_signed_bundled_marker() -> None:
    """invoke_template threads the signed-bundled marker."""
    result = invoke_template(COVERAGE_TEMPLATE_NAME, _coverage_bundle())
    assert result.signed_by == SIGNED_BUNDLED_MARKER


@pytest.mark.fulfills("VAL-W9-012")
def test_registry_is_a_closed_allow_list() -> None:
    """Three entries, no more (drift detection)."""
    assert set(REGISTERED_TEMPLATES.keys()) == {
        COVERAGE_TEMPLATE_NAME,
        TOOL_ARG_TEMPLATE_NAME,
        SCHEMA_MATCH_TEMPLATE_NAME,
    }


# =============================================================================
# VAL-W9-013 -- coverage template invariants
# =============================================================================


@pytest.mark.fulfills("VAL-W9-013")
def test_coverage_rejects_p0_without_owner() -> None:
    bundle = _coverage_bundle(
        assertions=[
            {
                "assertion_id": "VAL-DEMO-001",
                "severity": "p0",
                "owner_email": None,
                "expression_digest": "digest-a",
                "lifecycle_state": "active",
            },
        ]
    )
    with pytest.raises(RelayTemplateInputError) as ei:
        coverage_assertion_template(bundle)
    assert ei.value.code == RelayErrorCode.RELAY_COVERAGE_003


@pytest.mark.fulfills("VAL-W9-013")
def test_coverage_rejects_p1_with_empty_owner() -> None:
    bundle = _coverage_bundle(
        assertions=[
            {
                "assertion_id": "VAL-DEMO-001",
                "severity": "p1",
                "owner_email": "",
                "expression_digest": "digest-a",
                "lifecycle_state": "active",
            },
        ]
    )
    with pytest.raises(RelayTemplateInputError) as ei:
        coverage_assertion_template(bundle)
    assert ei.value.code == RelayErrorCode.RELAY_COVERAGE_003


@pytest.mark.fulfills("VAL-W9-013")
@pytest.mark.parametrize(
    "owner",
    [
        "team-platform@example.com",
        "group-sec@example.com",
        "dl-allhands@example.com",
        "all-staff@example.com",
        "eng@example.com",
        "support@example.com",
    ],
)
def test_coverage_rejects_group_alias_owner_emails(owner: str) -> None:
    bundle = _coverage_bundle(
        assertions=[
            {
                "assertion_id": "VAL-DEMO-001",
                "severity": "p0",
                "owner_email": owner,
                "expression_digest": "digest-a",
                "lifecycle_state": "active",
            },
        ]
    )
    with pytest.raises(RelayTemplateInputError) as ei:
        coverage_assertion_template(bundle)
    assert ei.value.code == RelayErrorCode.RELAY_COVERAGE_004


@pytest.mark.fulfills("VAL-W9-013")
def test_coverage_rejects_duplicate_expression_digest() -> None:
    bundle = _coverage_bundle(
        assertions=[
            {
                "assertion_id": "VAL-DEMO-001",
                "severity": "p0",
                "owner_email": "alice@example.com",
                "expression_digest": "digest-x",
                "lifecycle_state": "active",
            },
            {
                "assertion_id": "VAL-DEMO-002",
                "severity": "p0",
                "owner_email": "bob@example.com",
                "expression_digest": "digest-x",
                "lifecycle_state": "active",
            },
        ]
    )
    with pytest.raises(RelayTemplateInputError) as ei:
        coverage_assertion_template(bundle)
    assert ei.value.code == RelayErrorCode.RELAY_COVERAGE_002


@pytest.mark.fulfills("VAL-W9-013")
def test_coverage_rejects_duplicate_assertion_id() -> None:
    bundle = _coverage_bundle(
        assertions=[
            {
                "assertion_id": "VAL-DEMO-001",
                "severity": "p2",
                "owner_email": "alice@example.com",
                "expression_digest": "digest-a",
                "lifecycle_state": "active",
            },
            {
                "assertion_id": "VAL-DEMO-001",
                "severity": "p2",
                "owner_email": "bob@example.com",
                "expression_digest": "digest-b",
                "lifecycle_state": "active",
            },
        ]
    )
    with pytest.raises(RelayTemplateInputError) as ei:
        coverage_assertion_template(bundle)
    assert ei.value.code == RelayErrorCode.RELAY_COVERAGE_001


@pytest.mark.fulfills("VAL-W9-013")
def test_coverage_allows_deprecated_assertion_missing_owner() -> None:
    """Deprecated assertions may carry stale owners; only active is gated."""
    bundle = _coverage_bundle(
        assertions=[
            {
                "assertion_id": "VAL-DEMO-001",
                "severity": "p0",
                "owner_email": None,
                "expression_digest": "digest-a",
                "lifecycle_state": "deprecated",
            },
        ]
    )
    # Should NOT raise (active-only gating).
    result = coverage_assertion_template(bundle)
    assert result.checked_count == 1


# =============================================================================
# VAL-W9-014 -- tool_arg template validates against manifest tool registry
# =============================================================================


@pytest.mark.fulfills("VAL-W9-014")
def test_tool_arg_accepts_known_tool_name() -> None:
    result = tool_arg_assertion_template(_tool_arg_input(tool_name="fetch_url"))
    assert isinstance(result, ToolArgTemplateResult)
    assert result.tool_name == "fetch_url"
    assert result.side_effect_class == "read_only"
    assert result.manifest_commit_hash == SHA256_FIXTURE


@pytest.mark.fulfills("VAL-W9-014")
def test_tool_arg_rejects_unknown_tool_with_manifest_commit_hash() -> None:
    payload = _tool_arg_input(tool_name="unknown_tool")
    with pytest.raises(RelayManifestUnknownToolError) as ei:
        tool_arg_assertion_template(payload)
    assert ei.value.code == RelayErrorCode.RELAY_MANIFEST_021
    assert ei.value.payload["tool_name"] == "unknown_tool"
    # VAL-W9-014 explicit: manifest commit hash is in the error payload.
    assert ei.value.payload["manifest_commit_hash"] == SHA256_FIXTURE
    assert "fetch_url" in ei.value.payload["known_tool_names"]
    assert "create_ticket" in ei.value.payload["known_tool_names"]


@pytest.mark.fulfills("VAL-W9-014")
def test_tool_arg_does_not_fabricate_definitions_on_empty_registry() -> None:
    payload = _tool_arg_input(tool_name="fetch_url", tool_registry={})
    with pytest.raises(RelayManifestUnknownToolError) as ei:
        tool_arg_assertion_template(payload)
    assert ei.value.payload["known_tool_names"] == []


@pytest.mark.fulfills("VAL-W9-014")
def test_tool_arg_rejects_tool_with_invalid_side_effect_class() -> None:
    payload = _tool_arg_input(
        tool_name="fetch_url",
        tool_registry={"fetch_url": {"side_effect_class": "wat"}},
    )
    with pytest.raises(RelayTemplateInputError) as ei:
        tool_arg_assertion_template(payload)
    assert ei.value.payload["json_path"] == (
        "$.tool_registry.fetch_url.side_effect_class"
    )


# =============================================================================
# VAL-W9-015 -- schema_match resolves by canonical schema id
# =============================================================================


@pytest.mark.fulfills("VAL-W9-015")
def test_schema_match_resolves_known_canonical_ids() -> None:
    for sid in ("relay.run_result.v1", "relay.gate_decision.v1", "relay.manifest.v1"):
        result = schema_match_assertion_template(_schema_match_input(schema_id=sid))
        assert isinstance(result, SchemaMatchTemplateResult)
        assert result.resolved_schema_id == sid


@pytest.mark.fulfills("VAL-W9-015")
def test_schema_match_rejects_unknown_id_with_RelaySchemaNotFoundError() -> None:
    with pytest.raises(RelaySchemaNotFoundError) as ei:
        schema_match_assertion_template(_schema_match_input(schema_id="relay.does_not_exist.v1"))
    assert ei.value.code == RelayErrorCode.RELAY_SCHEMA_014
    assert ei.value.payload["missing_schema_id"] == "relay.does_not_exist.v1"
    assert "relay.run_result.v1" in ei.value.payload["known_schema_ids"]


@pytest.mark.fulfills("VAL-W9-015")
def test_schema_match_rejects_v2_schema_id_per_B7() -> None:
    """A v2 id is outside the supported set per spec B.7."""
    with pytest.raises(RelaySchemaNotFoundError):
        schema_match_assertion_template(_schema_match_input(schema_id="relay.run_result.v2"))


@pytest.mark.fulfills("VAL-W9-015")
def test_schema_match_known_ids_match_canonical_envelopes_yaml() -> None:
    """KNOWN_SCHEMA_IDS must stay in lockstep with the canonical YAML."""
    from pathlib import Path

    import yaml

    raw_yaml = (
        Path(__file__).resolve().parents[3]
        / "packages"
        / "schemas"
        / "raw"
        / "envelopes.yaml"
    )
    data = yaml.safe_load(raw_yaml.read_text(encoding="utf-8"))
    expected = {
        entry["schema_version"]
        for entry in data["schemas"].values()
        if isinstance(entry, dict) and "schema_version" in entry
    }
    assert set(KNOWN_SCHEMA_IDS) == expected, (
        f"KNOWN_SCHEMA_IDS drifted from envelopes.yaml; "
        f"add/remove: {expected ^ set(KNOWN_SCHEMA_IDS)}"
    )
