"""W11.2 x-relay/* extension namespace contract tests.

This module enforces the seven VAL-W11-009..015 assertions that
constitute the w11.2-acef-x-relay-extensions feature:

  * VAL-W11-009  All ten x-relay namespaces declared in
                 packages/acef/relay_extensions/.
  * VAL-W11-010  Each namespace has a JSON Schema (Draft 2020-12) and a
                 Python dataclass that round-trips through the schema.
  * VAL-W11-011  Relay-specific keys appear ONLY under
                 bundle.namespaces["x-relay"]; ACEF Core remains untouched.
  * VAL-W11-012  Unknown x-relay namespaces or undeclared sub-fields are
                 rejected on EmissionWriter.write_bundle() with
                 SchemaVersionError(error_code="RELAY-SCHEMA-011").
  * VAL-W11-013  Every emitted bundle carries the seven required
                 control-plane bindings; written_by must equal
                 "control_plane" (mutation -> RELAY-ING-031).
  * VAL-W11-014  Both bundle.schema_version (ACEF Core "v0.3") and
                 bundle.namespaces["x-relay"].schema_version (Relay "v1")
                 are present; mutation to an unknown value raises
                 SchemaVersionError(error_code="RELAY-SCHEMA-014").
  * VAL-W11-015  No SQL identifiers, no psycopg/asyncpg imports, no
                 db.execute / session.query calls under
                 packages/acef/relay_extensions/.

Plumbing tier (tier 1, <= 60s, offline). Reads schemas, models, and
golden fixtures from the on-disk relay_extensions package via stdlib
+ jsonschema only (no network, no database, no sidecar).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
from dataclasses import fields
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from relay_extensions import (
    ACEF_CORE_SCHEMA_VERSION_PIN,
    EXPECTED_TEN,
    RELAY_EXTENSION_NAMESPACES,
    RELAY_EXTENSIONS_SCHEMA_VERSION,
    REQUIRED_CONTROL_PLANE_BINDINGS,
    X_RELAY_NAMESPACE_KEY,
    load_namespace_schema,
    namespace_golden_path,
    namespace_model_path,
    namespace_schema_path,
    package_root,
)
from relay_extensions.bindings import ControlPlaneBindings
from relay_extensions.emission import EmissionWriter
from relay_extensions.errors import (
    RELAY_ING_031_CODE,
    RELAY_SCHEMA_011_CODE,
    RELAY_SCHEMA_014_CODE,
    RELAY_SCHEMA_023_CODE,
    ControlPlaneBindingError,
    SchemaVersionError,
)
from relay_extensions.models import all_dataclasses, get_dataclass

# -----------------------------------------------------------------------------
# Static expectations (load-bearing literals; spec lines 876-885)
# -----------------------------------------------------------------------------
# Duplicated here on purpose so the tests do not transitively read
# RELAY_EXTENSION_NAMESPACES to assert RELAY_EXTENSION_NAMESPACES.

EXPECTED_TEN_LITERAL: frozenset[str] = frozenset(
    {
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
    }
)

# The seven required control-plane binding fields per VAL-W11-013.
EXPECTED_BINDING_FIELDS: tuple[str, ...] = (
    "manifest_commit_hash",
    "scope_kind",
    "scope_id",
    "actor_kind",
    "actor_identity_hash",
    "written_by",
    "redaction_policy_version",
)


# -----------------------------------------------------------------------------
# Test fixtures
# -----------------------------------------------------------------------------


def _good_bindings() -> dict[str, Any]:
    """Return a dict of seven valid control-plane bindings."""
    return {
        "manifest_commit_hash": "a" * 64,
        "scope_kind": "run",
        "scope_id": "11111111-2222-3333-4444-555555555555",
        "actor_kind": "control_plane",
        "actor_identity_hash": "b" * 64,
        "written_by": "control_plane",
        "redaction_policy_version": "v1.0",
    }


def _good_bundle() -> dict[str, Any]:
    """Return a minimal-but-valid emitted ACEF bundle.

    Has both schema_version fields, a populated x-relay namespace block
    with all seven control-plane bindings and one declared namespace
    payload (agent-execution-trace), and ZERO Relay-specific root keys.
    """
    bundle: dict[str, Any] = {
        "schema_version": ACEF_CORE_SCHEMA_VERSION_PIN,
        "claims": [],
        "namespaces": {
            X_RELAY_NAMESPACE_KEY: {
                "schema_version": RELAY_EXTENSIONS_SCHEMA_VERSION,
                **_good_bindings(),
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
            }
        },
    }
    return bundle


# =============================================================================
# VAL-W11-009: all ten x-relay namespaces declared
# =============================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-009")
def test_relay_extension_namespaces_export_ten_identifiers() -> None:
    """relay_extensions.RELAY_EXTENSION_NAMESPACES is the canonical 10-tuple."""
    assert isinstance(RELAY_EXTENSION_NAMESPACES, tuple)
    assert len(RELAY_EXTENSION_NAMESPACES) == 10
    assert set(RELAY_EXTENSION_NAMESPACES) == EXPECTED_TEN_LITERAL


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-009")
def test_expected_ten_alias_matches_literal() -> None:
    """The package-level EXPECTED_TEN frozenset matches the literal expected ten."""
    assert isinstance(EXPECTED_TEN, frozenset)
    assert EXPECTED_TEN == EXPECTED_TEN_LITERAL


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-009")
def test_relay_extensions_schema_version_pinned() -> None:
    """The x-relay block schema_version is pinned to v1 at MVP."""
    assert RELAY_EXTENSIONS_SCHEMA_VERSION == "v1"


# =============================================================================
# VAL-W11-010: each namespace has a JSON Schema and a Python dataclass
# =============================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-010")
@pytest.mark.parametrize("namespace", sorted(EXPECTED_TEN_LITERAL))
def test_each_namespace_has_a_json_schema(namespace: str) -> None:
    """Every namespace has a Draft 2020-12 schema at schemas/<name>.v1.json."""
    schema_path = namespace_schema_path(namespace)
    assert schema_path.exists(), f"missing schema file: {schema_path}"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    # The schema_version property is present and pinned to the exact const.
    sv = schema["properties"]["schema_version"]
    assert sv["const"] == f"x-relay.{namespace}.v1"
    # The schema explicitly forbids additional properties so the emission
    # writer's sub-field check is reinforced by the schema itself.
    assert schema.get("additionalProperties") is False


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-010")
@pytest.mark.parametrize("namespace", sorted(EXPECTED_TEN_LITERAL))
def test_each_namespace_has_a_python_dataclass(namespace: str) -> None:
    """Every namespace has a Python dataclass at models/<name>.py."""
    model_path = namespace_model_path(namespace)
    # The on-disk file uses the hyphenated namespace name.
    assert model_path.exists(), f"missing model file: {model_path}"
    klass = get_dataclass(namespace)
    # Class is a dataclass with a schema_version field defaulting to const.
    field_names = {f.name for f in fields(klass)}
    assert "schema_version" in field_names


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-010")
@pytest.mark.parametrize("namespace", sorted(EXPECTED_TEN_LITERAL))
def test_golden_fixture_validates_against_schema(namespace: str) -> None:
    """Each golden fixture validates against its sibling JSON Schema."""
    schema = load_namespace_schema(namespace)
    fixture = json.loads(namespace_golden_path(namespace).read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(fixture)
    # Spot-check the schema_version literal for each namespace.
    assert fixture["schema_version"] == f"x-relay.{namespace}.v1"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-010")
@pytest.mark.parametrize("namespace", sorted(EXPECTED_TEN_LITERAL))
def test_dataclass_round_trips_through_schema(namespace: str) -> None:
    """dict -> dataclass -> dict round-trips and re-validates."""
    schema = load_namespace_schema(namespace)
    fixture = json.loads(namespace_golden_path(namespace).read_text(encoding="utf-8"))
    klass = get_dataclass(namespace)
    # Construct the dataclass from the fixture dict.
    instance = klass(**fixture)
    # Serialise back via to_dict + asdict and re-validate.
    re_emitted = instance.to_dict()
    Draft202012Validator(schema).validate(re_emitted)
    # The schema_version must survive the round-trip unchanged.
    assert re_emitted["schema_version"] == f"x-relay.{namespace}.v1"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-010")
def test_all_dataclasses_count() -> None:
    """The dataclass registry exposes exactly the ten declared classes."""
    classes = all_dataclasses()
    assert len(classes) == 10
    assert set(classes.keys()) == EXPECTED_TEN_LITERAL


# =============================================================================
# VAL-W11-011: x-relay fields appear only under x-relay/* namespace
# =============================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-011")
def test_emission_rejects_relay_root_key_with_relay_prefix() -> None:
    """A bundle with a 'relay_*' key at the root is rejected."""
    bundle = _good_bundle()
    bundle["relay_metadata"] = {"oops": "this should not be here"}
    with pytest.raises(SchemaVersionError) as excinfo:
        EmissionWriter().write_bundle(bundle)
    assert excinfo.value.error_code == RELAY_SCHEMA_011_CODE
    assert excinfo.value.details["violating_root_key"] == "relay_metadata"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-011")
def test_emission_rejects_relay_root_key_with_xrelay_prefix() -> None:
    """A bundle with an 'x-relay*' key at the root is rejected."""
    bundle = _good_bundle()
    bundle["x-relay-extra"] = {"oops": True}
    with pytest.raises(SchemaVersionError) as excinfo:
        EmissionWriter().write_bundle(bundle)
    assert excinfo.value.error_code == RELAY_SCHEMA_011_CODE


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-011")
def test_emission_accepts_well_formed_bundle() -> None:
    """The reference good-bundle fixture passes EmissionWriter.write_bundle."""
    bundle = _good_bundle()
    out = EmissionWriter().write_bundle(bundle)
    assert out is bundle  # writer returns the same dict on success


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-011")
def test_no_root_keys_have_relay_prefix_in_good_bundle() -> None:
    """Audit the reference bundle's root keys for accidental Relay leakage."""
    bundle = _good_bundle()
    for key in bundle:
        assert not key.startswith("relay_")
        assert not key.startswith("x-relay")


# =============================================================================
# VAL-W11-012: unknown x-relay extension fields rejected on write
# =============================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-012")
def test_emission_rejects_unknown_namespace() -> None:
    """An unknown namespace under bundle.namespaces['x-relay'] is rejected."""
    bundle = _good_bundle()
    bundle["namespaces"][X_RELAY_NAMESPACE_KEY]["unknown-namespace"] = {}
    with pytest.raises(SchemaVersionError) as excinfo:
        EmissionWriter().write_bundle(bundle)
    assert excinfo.value.error_code == RELAY_SCHEMA_011_CODE
    assert excinfo.value.details["violating_key"] == "unknown-namespace"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-012")
def test_emission_rejects_undeclared_subfield() -> None:
    """An undeclared sub-field inside a known namespace is rejected."""
    bundle = _good_bundle()
    bundle["namespaces"][X_RELAY_NAMESPACE_KEY]["agent-execution-trace"][
        "undeclared_field"
    ] = "oops"
    with pytest.raises(SchemaVersionError) as excinfo:
        EmissionWriter().write_bundle(bundle)
    assert excinfo.value.error_code == RELAY_SCHEMA_011_CODE
    assert excinfo.value.details["violating_subfield"] == "undeclared_field"
    assert excinfo.value.details["namespace"] == "agent-execution-trace"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-012")
def test_emission_writer_returns_no_persistence_handle() -> None:
    """Per VAL-W11-012, no bundle is persisted after rejection.

    The W11.2 emission writer is intentionally I/O-free; the contract
    enforces "no bundle persisted to object store after rejection" by
    decoupling validation from persistence. This test asserts the writer
    has no .persist / .commit / .store / .write_to_disk method that
    could leak side-effecting state.
    """
    writer = EmissionWriter()
    forbidden_methods = ("persist", "commit", "store", "write_to_disk", "flush")
    for name in forbidden_methods:
        assert not hasattr(writer, name), (
            f"EmissionWriter.{name} must not exist; W11.2 is validation-only "
            f"and persistence is the caller's responsibility via the four "
            f"atomic-persistence primitives."
        )


# =============================================================================
# VAL-W11-013: control-plane bindings present on every emitted bundle
# =============================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-013")
def test_required_control_plane_bindings_are_seven() -> None:
    """The required-binding tuple is exactly the seven VAL-W11-013 fields."""
    assert len(REQUIRED_CONTROL_PLANE_BINDINGS) == 7
    assert set(REQUIRED_CONTROL_PLANE_BINDINGS) == set(EXPECTED_BINDING_FIELDS)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-013")
def test_emission_accepts_all_seven_bindings() -> None:
    """A well-formed bundle with all seven bindings populated is accepted."""
    bundle = _good_bundle()
    EmissionWriter().write_bundle(bundle)
    # Confirm all seven bindings are present in the emitted x-relay block.
    x_relay = bundle["namespaces"][X_RELAY_NAMESPACE_KEY]
    for field in EXPECTED_BINDING_FIELDS:
        assert field in x_relay
        assert x_relay[field] not in (None, "")


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-013")
@pytest.mark.parametrize("missing_field", EXPECTED_BINDING_FIELDS)
def test_emission_rejects_missing_binding_with_schema_023(missing_field: str) -> None:
    """Removing any of the seven bindings raises RELAY-SCHEMA-023."""
    bundle = _good_bundle()
    del bundle["namespaces"][X_RELAY_NAMESPACE_KEY][missing_field]
    with pytest.raises(SchemaVersionError) as excinfo:
        EmissionWriter().write_bundle(bundle)
    assert excinfo.value.error_code == RELAY_SCHEMA_023_CODE
    assert excinfo.value.details["missing_field"] == missing_field


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-013")
def test_emission_rejects_written_by_mutation_with_ing_031() -> None:
    """Mutating written_by != 'control_plane' raises RELAY-ING-031."""
    bundle = _good_bundle()
    bundle["namespaces"][X_RELAY_NAMESPACE_KEY]["written_by"] = "agent"
    with pytest.raises(ControlPlaneBindingError) as excinfo:
        EmissionWriter().write_bundle(bundle)
    assert excinfo.value.error_code == RELAY_ING_031_CODE
    assert excinfo.value.details["field"] == "written_by"
    assert excinfo.value.details["observed"] == "agent"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-013")
def test_emission_rejects_actor_kind_mutation_with_ing_031() -> None:
    """Mutating actor_kind != 'control_plane' raises RELAY-ING-031."""
    bundle = _good_bundle()
    bundle["namespaces"][X_RELAY_NAMESPACE_KEY]["actor_kind"] = "eval_worker"
    with pytest.raises(ControlPlaneBindingError) as excinfo:
        EmissionWriter().write_bundle(bundle)
    assert excinfo.value.error_code == RELAY_ING_031_CODE
    assert excinfo.value.details["field"] == "actor_kind"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-013")
def test_control_plane_bindings_dataclass_serialises_seven_fields() -> None:
    """ControlPlaneBindings dataclass serialises exactly the seven fields."""
    bindings = ControlPlaneBindings(**_good_bindings())
    serialised = bindings.to_dict()
    assert set(serialised.keys()) == set(EXPECTED_BINDING_FIELDS)
    assert serialised["written_by"] == "control_plane"


# =============================================================================
# VAL-W11-014: x-relay schema_version travels alongside acef_core schema_version
# =============================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-014")
def test_good_bundle_has_both_schema_versions() -> None:
    """A well-formed bundle carries both ACEF Core v0.3 and x-relay v1."""
    bundle = _good_bundle()
    assert bundle["schema_version"] == ACEF_CORE_SCHEMA_VERSION_PIN == "v0.3"
    x = bundle["namespaces"][X_RELAY_NAMESPACE_KEY]
    assert x["schema_version"] == RELAY_EXTENSIONS_SCHEMA_VERSION == "v1"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-014")
@pytest.mark.parametrize("bad_version", ["v0.99", "v0.2", "v1.0", "alpha", "", "v99"])
def test_emission_rejects_unknown_acef_core_schema_version(bad_version: str) -> None:
    """Mutating bundle.schema_version to an unknown value raises RELAY-SCHEMA-014."""
    bundle = _good_bundle()
    bundle["schema_version"] = bad_version
    with pytest.raises(SchemaVersionError) as excinfo:
        EmissionWriter().write_bundle(bundle)
    assert excinfo.value.error_code == RELAY_SCHEMA_014_CODE
    assert excinfo.value.details["field"] == "bundle.schema_version"
    assert excinfo.value.details["expected"] == "v0.3"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-014")
@pytest.mark.parametrize("bad_version", ["v0", "v2", "v1.1", "", "x-relay.v1"])
def test_emission_rejects_unknown_x_relay_schema_version(bad_version: str) -> None:
    """Mutating x-relay schema_version to an unknown value raises RELAY-SCHEMA-014."""
    bundle = _good_bundle()
    bundle["namespaces"][X_RELAY_NAMESPACE_KEY]["schema_version"] = bad_version
    with pytest.raises(SchemaVersionError) as excinfo:
        EmissionWriter().write_bundle(bundle)
    assert excinfo.value.error_code == RELAY_SCHEMA_014_CODE
    assert excinfo.value.details["field"] == "namespaces.x-relay.schema_version"


# =============================================================================
# VAL-W11-015: x-relay extensions never reference Relay's internal DB schemas
# =============================================================================


_FORBIDDEN_DB_SCHEMA_TOKENS: tuple[str, ...] = (
    "run_results",
    "gate_decisions",
    "gate_decision_drafts",
    "gate_rounds",
    "replay_cases",
    "replay_fixtures",
    "evidence_bundles",
    "evidence_claims",
    "manifest_versions",
    "redaction_policies",
    "event_log_entries",
    "idempotency_records",
    "scope_state",
)

_FORBIDDEN_IMPORT_TOKENS: tuple[str, ...] = (
    "import psycopg",
    "import asyncpg",
    "from psycopg",
    "from asyncpg",
)

_FORBIDDEN_DB_CALL_TOKENS: tuple[str, ...] = (
    "db.execute(",
    "session.query(",
)


def _scan_relay_extensions_for_pattern(pattern: str) -> list[tuple[Path, int, str]]:
    """Return list of (file, line_number, line) hits for ``pattern``."""
    hits: list[tuple[Path, int, str]] = []
    root = package_root()
    for path in root.rglob("*.py"):
        # Don't scan __pycache__ or anything under tests/ (none here, but
        # defensive).
        if "__pycache__" in path.parts:
            continue
        for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if pattern in line:
                hits.append((path, i, line))
    return hits


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-015")
@pytest.mark.parametrize("token", _FORBIDDEN_DB_SCHEMA_TOKENS)
def test_no_sql_table_names_under_relay_extensions(token: str) -> None:
    """No SQL table identifier appears under packages/acef/relay_extensions/."""
    hits = _scan_relay_extensions_for_pattern(token)
    assert hits == [], (
        f"forbidden SQL identifier {token!r} found under "
        f"packages/acef/relay_extensions/: {hits!r}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-015")
@pytest.mark.parametrize("token", _FORBIDDEN_IMPORT_TOKENS)
def test_no_psycopg_or_asyncpg_imports(token: str) -> None:
    """No psycopg/asyncpg import under packages/acef/relay_extensions/."""
    hits = _scan_relay_extensions_for_pattern(token)
    assert hits == [], (
        f"forbidden DB driver import {token!r} found under "
        f"packages/acef/relay_extensions/: {hits!r}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-015")
@pytest.mark.parametrize("token", _FORBIDDEN_DB_CALL_TOKENS)
def test_no_db_execute_or_session_query(token: str) -> None:
    """No db.execute( or session.query( call under relay_extensions/."""
    hits = _scan_relay_extensions_for_pattern(token)
    assert hits == [], (
        f"forbidden DB call {token!r} found under "
        f"packages/acef/relay_extensions/: {hits!r}"
    )
