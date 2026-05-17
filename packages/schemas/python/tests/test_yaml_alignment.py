"""Cross-YAML alignment check for the two-layer schema architecture.

Locked post-W1.6 by orchestrator decision 2026-05-13 (SCR-W1-H002 resolution).

The two-layer architecture keeps `packages/schemas/raw/envelopes.yaml`
(rich-validation source for the hand-authored Pydantic/TS layer) and
`packages/schemas/raw/openapi.yaml` (OpenAPI 3.1 source for the W1.5
codegen layer) as independent files. This test asserts that the two
files describe the same shape for every shared envelope:

  1. Both YAMLs enumerate exactly the same envelope names (the OpenAPI
     file may carry additional primitive schemas like Sha256Hash and
     discriminated-union variant schemas; those are excluded from the
     shared-envelope set).
  2. Each shared envelope's schema_version literal is identical.
  3. Each shared envelope's closed enums carry identical member sets.

A failure here means a drift has been introduced and one of the two
YAMLs needs amendment to restore parity.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

# Repo-root anchored paths.
_THIS = Path(__file__).resolve()
_REPO_ROOT = _THIS.parents[4]
_ENVELOPES_YAML = _REPO_ROOT / "packages" / "schemas" / "raw" / "envelopes.yaml"
_OPENAPI_YAML = _REPO_ROOT / "packages" / "schemas" / "raw" / "openapi.yaml"

# The 15 envelopes that BOTH YAMLs MUST define. The OpenAPI file additionally
# defines primitive schemas (Sha256Hash, Ulid, RelayErrorCodeStr) and
# discriminated-union variant schemas (RunScopeState, ReplayCaseScopeState,
# GateRoundScopeState, EvidenceBundleScopeState, RedactionPolicyMatcherRegex,
# RedactionPolicyMatcherJsonPointer, RedactionPolicyMatcher) that have no
# counterpart in the rich-layer YAML; those are correctly excluded.
_SHARED_ENVELOPES: frozenset[str] = frozenset(
    {
        "RunResult",
        "GateDecision",
        "GateDecisionDraft",
        "GateRound",
        "Actor",
        "ManifestVersion",
        "ScopeState",
        "IdempotencyRecord",
        "EvidenceBundle",
        "EvidenceClaim",
        "ReplayCase",
        "ReplayFixture",
        "EventLogEntry",
        "RedactionPolicy",
        "ErrorEnvelope",
        # v0.2 OSS completeness, M01 w1-1 (added 2026-05-16): canonical
        # envelopes backing the 13 SQL tables in
        # packages/schemas/sql/0004_v2_canonical_tables.sql.
        "GatePolicy",
        "ContractResult",
        "AssertionDefinition",
        "ReplayResult",
        "Manifest",
        "Incident",
        "RootCauseHypothesis",
        "Span",
        "ModelCallSpan",
        "ToolCallSpan",
        "RetrievalSpan",
        "EmbeddingSpan",
        # v0.2 OSS completeness, M01 w1-4 (added 2026-05-16): legal holds +
        # mutable evidence_bundle_registry sibling to immutable signed
        # evidence_bundles. Backed by
        # packages/schemas/sql/0005_legal_holds.sql.
        "EvidenceLegalHold",
        "EvidenceBundleRegistry",
        # v0.2 OSS completeness, M01 w1-6 (added 2026-05-16): two
        # sectionAB trusted-timestamping + transparency-log envelopes
        # backing packages/schemas/sql/0007_evidence_timestamps_log.sql.
        "EvidenceTimestamp",
        "TransparencyLogEntry",
        # v0.2 OSS completeness, M01 w1-5 (added 2026-05-16): canonical
        # Postgres-table envelopes mirroring the ACEF x-relay JSON
        # payload models. Backed by packages/schemas/sql/0006_human_oversight.sql.
        "HumanOversightEvent",
        "DataQualityCheck",
        "DataProvenanceRecord",
    }
)


def _load_envelopes_yaml() -> dict:
    return yaml.safe_load(_ENVELOPES_YAML.read_text())


def _load_openapi_yaml() -> dict:
    return yaml.safe_load(_OPENAPI_YAML.read_text())


def _envelopes_field(envelope: dict, name: str) -> dict | None:
    return (envelope.get("fields") or {}).get(name)


def _openapi_field(envelope: dict, name: str) -> dict | None:
    return (envelope.get("properties") or {}).get(name)


def _envelopes_schema_version(envelope: dict) -> str | None:
    field = _envelopes_field(envelope, "schema_version")
    if not field:
        return None
    # envelopes.yaml encodes as {type: literal, value: 'relay.<x>.v1'}
    return field.get("value")


def _openapi_schema_version(envelope: dict) -> str | None:
    field = _openapi_field(envelope, "schema_version")
    if not field:
        return None
    # openapi.yaml encodes as {type: string, const: 'relay.<x>.v1'}
    return field.get("const")


def _envelopes_enum_members(envelope: dict, field_name: str) -> frozenset[str] | None:
    field = _envelopes_field(envelope, field_name)
    if not field or field.get("type") != "enum":
        return None
    values = field.get("values") or []
    return frozenset(values)


def _openapi_enum_members(envelope: dict, field_name: str) -> frozenset[str] | None:
    field = _openapi_field(envelope, field_name)
    if not field:
        return None
    # Direct enum: {type: string, enum: [...]}
    enum = field.get("enum")
    if enum is not None:
        return frozenset(enum)
    # Nullable enum: {oneOf: [{type: string, enum: [...]}, {type: "null"}]}
    # or any other oneOf/anyOf variant carrying the canonical enum list.
    for combinator in ("oneOf", "anyOf"):
        variants = field.get(combinator)
        if not isinstance(variants, list):
            continue
        for variant in variants:
            if isinstance(variant, dict) and "enum" in variant:
                return frozenset(variant["enum"])
    return None


@pytest.mark.plumbing
def test_envelope_name_sets_align() -> None:
    e_yaml = _load_envelopes_yaml()
    o_yaml = _load_openapi_yaml()
    e_names = set((e_yaml.get("schemas") or {}).keys())
    o_names = set(((o_yaml.get("components") or {}).get("schemas") or {}).keys())

    # envelopes.yaml MUST be exactly the shared set.
    assert e_names == _SHARED_ENVELOPES, (
        f"envelopes.yaml envelope set drift: "
        f"missing {_SHARED_ENVELOPES - e_names}, "
        f"extra {e_names - _SHARED_ENVELOPES}"
    )

    # openapi.yaml MUST contain every shared envelope (plus primitives/variants).
    missing_from_openapi = _SHARED_ENVELOPES - o_names
    assert not missing_from_openapi, (
        f"openapi.yaml is missing shared envelopes: {sorted(missing_from_openapi)}"
    )


@pytest.mark.plumbing
def test_schema_version_literals_align() -> None:
    e_schemas = (_load_envelopes_yaml().get("schemas") or {})
    o_schemas = ((_load_openapi_yaml().get("components") or {}).get("schemas") or {})

    mismatches: list[str] = []
    for name in sorted(_SHARED_ENVELOPES):
        e_val = _envelopes_schema_version(e_schemas[name])
        o_val = _openapi_schema_version(o_schemas[name])
        if e_val != o_val:
            mismatches.append(
                f"  {name}: envelopes.yaml={e_val!r}, openapi.yaml={o_val!r}"
            )

    assert not mismatches, (
        "schema_version literal drift between envelopes.yaml and openapi.yaml:\n"
        + "\n".join(mismatches)
    )


@pytest.mark.plumbing
def test_closed_enum_members_align() -> None:
    """For each shared envelope, every closed enum field present in BOTH
    YAMLs must carry an identical member set. If an enum is present in one
    YAML but not the other, that's a structural divergence and fails the
    first test (name set / shape). This test focuses on member-set drift
    for enums declared in both.
    """
    e_schemas = (_load_envelopes_yaml().get("schemas") or {})
    o_schemas = ((_load_openapi_yaml().get("components") or {}).get("schemas") or {})

    mismatches: list[str] = []
    for env_name in sorted(_SHARED_ENVELOPES):
        e_env = e_schemas[env_name]
        o_env = o_schemas[env_name]
        e_fields = (e_env.get("fields") or {}).keys()
        for field_name in sorted(e_fields):
            e_members = _envelopes_enum_members(e_env, field_name)
            if e_members is None:
                continue  # not an enum on rich-layer side
            o_members = _openapi_enum_members(o_env, field_name)
            if o_members is None:
                # openapi side lacks an enum constraint for this field;
                # if envelopes.yaml declares it as a closed enum the
                # codegen side should too.
                mismatches.append(
                    f"  {env_name}.{field_name}: envelopes.yaml declares closed enum "
                    f"{sorted(e_members)}; openapi.yaml has no enum constraint"
                )
                continue
            if e_members != o_members:
                only_e = sorted(e_members - o_members)
                only_o = sorted(o_members - e_members)
                mismatches.append(
                    f"  {env_name}.{field_name}: "
                    f"envelopes.yaml-only={only_e}, openapi.yaml-only={only_o}"
                )

    assert not mismatches, (
        "Closed enum member-set drift between envelopes.yaml and openapi.yaml:\n"
        + "\n".join(mismatches)
    )
