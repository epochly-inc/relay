"""V2 M01 W1.5 human-oversight + data-quality + data-provenance tests.

Covers contract assertions VAL-V2M01-030, VAL-V2M01-031, VAL-V2M01-032.

Each test is bound to its assertion via the ``pytest.mark.fulfills`` marker so
the gate engine can attribute pass/fail to the assertion's evidence
requirement.

The three new SQL tables (spec sectionAE lines 5494-5539) close the schema
gap that prevented evidence claims from binding to first-class oversight,
data-quality, and data-provenance rows. Per CLAUDE.md keystone invariant #10
each envelope pins ``schema_version`` via a Literal[...] on the Pydantic
model. Per CLAUDE.md "ASCII-Safe Source", no emoji or unicode glyphs.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

# Test lives at packages/schemas/python/tests/test_v2m01_human_oversight.py;
# parents[4] is the public relay repo root.
_THIS = Path(__file__).resolve()
_REPO_ROOT = _THIS.parents[4]
_SQL_DIR = _REPO_ROOT / "packages" / "schemas" / "sql"
_SIDECAR_MIGRATIONS = _REPO_ROOT / "apps" / "local-sidecar" / "migrations"
_NEW_DDL = _SQL_DIR / "0006_human_oversight.sql"
_NEW_SIDECAR = _SIDECAR_MIGRATIONS / "0014_human_oversight.sql"


def _read_new_ddl() -> str:
    return _NEW_DDL.read_text(encoding="utf-8")


def _read_sidecar_ddl() -> str:
    return _NEW_SIDECAR.read_text(encoding="utf-8")


def _table_block(text: str, table_name: str) -> str:
    """Return the ``CREATE TABLE`` block for ``table_name`` up to ``);``.

    Matches ``CREATE TABLE`` and ``CREATE TABLE IF NOT EXISTS``,
    case-insensitive. The returned string is suitable for per-column /
    per-constraint regex inspection.
    """
    pat = re.compile(
        r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?"
        + re.escape(table_name)
        + r"\b.*?\);",
        re.IGNORECASE | re.DOTALL,
    )
    m = pat.search(text)
    assert m, f"CREATE TABLE for {table_name!r} not found"
    return m.group(0)


# ---------------------------------------------------------------------------
# Migration files exist
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_human_oversight_ddl_file_exists() -> None:
    assert _NEW_DDL.is_file(), f"Missing canonical DDL file: {_NEW_DDL}"


@pytest.mark.plumbing
def test_human_oversight_sidecar_migration_file_exists() -> None:
    assert _NEW_SIDECAR.is_file(), f"Missing sidecar mirror: {_NEW_SIDECAR}"


# ---------------------------------------------------------------------------
# VAL-V2M01-030: human_oversight_events (spec AE lines 5494-5508)
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-030")
def test_human_oversight_events_postgres_ddl() -> None:
    text = _read_new_ddl()
    block = _table_block(text, "human_oversight_events")
    lowered = block.lower()
    assert "oversight_id uuid primary key" in lowered
    assert "project_id uuid not null" in lowered
    assert "references projects(project_id)" in lowered
    # Nullable references
    assert "run_id uuid" in lowered
    assert "references runs(run_id)" in lowered
    assert "ai_system_classification_id uuid" in lowered
    assert (
        "references ai_system_classifications(classification_id)" in lowered
    )
    assert "oversight_kind text not null" in lowered
    # Closed enum
    for member in (
        "'pre_action_review'",
        "'post_action_review'",
        "'escalation'",
        "'override'",
        "'manual_classification'",
        "'content_review'",
    ):
        assert member in lowered, f"oversight_kind enum missing {member}"
    assert "check (oversight_kind in" in lowered
    assert "actor_user_id uuid" in lowered
    assert "decision text" in lowered
    assert "rationale text" in lowered
    assert "evidence_refs jsonb not null default '[]'" in lowered
    assert "occurred_at timestamptz not null default now()" in lowered


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-030")
def test_human_oversight_events_sidecar_mirror_has_check() -> None:
    text = _read_sidecar_ddl()
    block = _table_block(text, "human_oversight_events")
    lowered = block.lower()
    # SQLite mirror MUST preserve the closed enum
    assert "oversight_kind" in lowered
    for member in (
        "'pre_action_review'",
        "'post_action_review'",
        "'escalation'",
        "'override'",
        "'manual_classification'",
        "'content_review'",
    ):
        assert member in lowered, f"sidecar oversight_kind missing {member}"


# ---------------------------------------------------------------------------
# VAL-V2M01-031: data_quality_checks (spec AE lines 5510-5525)
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-031")
def test_data_quality_checks_postgres_ddl() -> None:
    text = _read_new_ddl()
    block = _table_block(text, "data_quality_checks")
    lowered = block.lower()
    assert "data_quality_check_id uuid primary key" in lowered
    assert "project_id uuid not null" in lowered
    assert "references projects(project_id)" in lowered
    assert "dataset_id uuid" in lowered
    assert "check_kind text not null" in lowered
    for member in (
        "'lineage'",
        "'representativeness'",
        "'duplicate_detection'",
        "'schema_conformance'",
        "'pii_minimization'",
        "'licensing'",
        "'staleness'",
    ):
        assert member in lowered, f"check_kind enum missing {member}"
    assert "check (check_kind in" in lowered
    assert "check_name text not null" in lowered
    assert "inputs_ref text" in lowered
    assert "outcome text not null" in lowered
    for member in ("'pass'", "'fail'", "'warn'", "'skipped'", "'error'"):
        assert member in lowered, f"outcome enum missing {member}"
    assert "check (outcome in" in lowered
    assert "metric_value numeric" in lowered
    assert "threshold_value numeric" in lowered
    assert "evaluator text not null" in lowered
    assert "evidence_refs jsonb not null default '[]'" in lowered
    assert "performed_at timestamptz not null default now()" in lowered


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-031")
def test_data_quality_checks_sidecar_mirror_has_check() -> None:
    text = _read_sidecar_ddl()
    block = _table_block(text, "data_quality_checks")
    lowered = block.lower()
    # SQLite mirror MUST preserve both closed enums
    for member in (
        "'lineage'",
        "'representativeness'",
        "'duplicate_detection'",
        "'schema_conformance'",
        "'pii_minimization'",
        "'licensing'",
        "'staleness'",
    ):
        assert member in lowered, f"sidecar check_kind missing {member}"
    for member in ("'pass'", "'fail'", "'warn'", "'skipped'", "'error'"):
        assert member in lowered, f"sidecar outcome missing {member}"


# ---------------------------------------------------------------------------
# VAL-V2M01-032: data_provenance_records (spec AE lines 5527-5539)
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-032")
def test_data_provenance_records_postgres_ddl() -> None:
    text = _read_new_ddl()
    block = _table_block(text, "data_provenance_records")
    lowered = block.lower()
    assert "provenance_id uuid primary key" in lowered
    assert "project_id uuid not null" in lowered
    assert "references projects(project_id)" in lowered
    assert "dataset_id uuid not null" in lowered
    assert "source_kind text not null" in lowered
    for member in (
        "'first_party'",
        "'licensed'",
        "'public_domain'",
        "'web_scrape'",
        "'synthetic'",
        "'user_generated'",
    ):
        assert member in lowered, f"source_kind enum missing {member}"
    assert "check (source_kind in" in lowered
    assert "license_ref text" in lowered
    assert "acquired_at timestamptz" in lowered
    assert "acquired_by_user_id uuid" in lowered
    assert "notes text" in lowered
    assert "evidence_refs jsonb not null default '[]'" in lowered


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-032")
def test_data_provenance_records_sidecar_mirror_has_check() -> None:
    text = _read_sidecar_ddl()
    block = _table_block(text, "data_provenance_records")
    lowered = block.lower()
    for member in (
        "'first_party'",
        "'licensed'",
        "'public_domain'",
        "'web_scrape'",
        "'synthetic'",
        "'user_generated'",
    ):
        assert member in lowered, f"sidecar source_kind missing {member}"


# ---------------------------------------------------------------------------
# Pydantic envelopes: presence + schema_version pin + round-trip
# ---------------------------------------------------------------------------


_NEW_ENVELOPES: tuple[str, ...] = (
    "HumanOversightEvent",
    "DataQualityCheck",
    "DataProvenanceRecord",
)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-030")
def test_new_envelopes_pydantic_models_importable() -> None:
    """The hand-authored Pydantic layer exposes every new envelope class."""
    from relay_schemas import envelopes as env

    for name in _NEW_ENVELOPES:
        assert hasattr(env, name), f"relay_schemas.envelopes missing {name}"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-030")
def test_new_envelopes_schema_version_literal_pinned() -> None:
    """Each envelope class pins schema_version via Literal[...].

    CLAUDE.md keystone invariant #10. The wire-format literals differ from
    the existing ACEF ``x-relay.*.v1`` namespace literals (decoupled
    layers); the canonical Postgres-table envelopes use ``relay.*.v1``.
    """
    from typing import get_args

    from relay_schemas import envelopes as env

    expected_pin = {
        "HumanOversightEvent": "relay.human_oversight_event.v1",
        "DataQualityCheck": "relay.data_quality_check.v1",
        "DataProvenanceRecord": "relay.data_provenance_record.v1",
    }
    for name, version in expected_pin.items():
        cls = getattr(env, name)
        ann = cls.model_fields["schema_version"].annotation
        args = get_args(ann)
        assert args == (version,), (
            f"{name}.schema_version literal pin mismatch: expected "
            f"({version!r},) got {args!r}"
        )


def _new_uuid() -> str:
    return str(uuid.uuid4())


def _now_iso() -> str:
    return datetime.now(tz=UTC).isoformat()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-030")
def test_human_oversight_event_envelope_roundtrip() -> None:
    from relay_schemas.envelopes import HumanOversightEvent

    payload = {
        "schema_version": "relay.human_oversight_event.v1",
        "oversight_id": _new_uuid(),
        "project_id": _new_uuid(),
        "oversight_kind": "pre_action_review",
        "occurred_at": _now_iso(),
    }
    ev = HumanOversightEvent.model_validate(payload)
    assert ev.oversight_kind == "pre_action_review"
    assert ev.evidence_refs == []


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-030")
def test_human_oversight_event_rejects_invalid_oversight_kind() -> None:
    from relay_schemas.envelopes import HumanOversightEvent

    payload = {
        "schema_version": "relay.human_oversight_event.v1",
        "oversight_id": _new_uuid(),
        "project_id": _new_uuid(),
        "oversight_kind": "drive_by_audit",  # not in closed enum
        "occurred_at": _now_iso(),
    }
    with pytest.raises(ValidationError):
        HumanOversightEvent.model_validate(payload)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-031")
def test_data_quality_check_envelope_roundtrip() -> None:
    from relay_schemas.envelopes import DataQualityCheck

    payload = {
        "schema_version": "relay.data_quality_check.v1",
        "data_quality_check_id": _new_uuid(),
        "project_id": _new_uuid(),
        "check_kind": "representativeness",
        "check_name": "english-train-coverage",
        "outcome": "pass",
        "evaluator": "code:relay.data_quality.coverage:v1",
        "performed_at": _now_iso(),
    }
    dq = DataQualityCheck.model_validate(payload)
    assert dq.check_kind == "representativeness"
    assert dq.outcome == "pass"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-031")
def test_data_quality_check_rejects_invalid_outcome() -> None:
    from relay_schemas.envelopes import DataQualityCheck

    payload = {
        "schema_version": "relay.data_quality_check.v1",
        "data_quality_check_id": _new_uuid(),
        "project_id": _new_uuid(),
        "check_kind": "lineage",
        "check_name": "x",
        "outcome": "maybe",  # not in closed enum
        "evaluator": "human:auditor@example.com",
        "performed_at": _now_iso(),
    }
    with pytest.raises(ValidationError):
        DataQualityCheck.model_validate(payload)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-031")
def test_data_quality_check_rejects_invalid_check_kind() -> None:
    from relay_schemas.envelopes import DataQualityCheck

    payload = {
        "schema_version": "relay.data_quality_check.v1",
        "data_quality_check_id": _new_uuid(),
        "project_id": _new_uuid(),
        "check_kind": "vibe_check",  # not in closed enum
        "check_name": "x",
        "outcome": "pass",
        "evaluator": "code:x:v1",
        "performed_at": _now_iso(),
    }
    with pytest.raises(ValidationError):
        DataQualityCheck.model_validate(payload)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-032")
def test_data_provenance_record_envelope_roundtrip() -> None:
    from relay_schemas.envelopes import DataProvenanceRecord

    payload = {
        "schema_version": "relay.data_provenance_record.v1",
        "provenance_id": _new_uuid(),
        "project_id": _new_uuid(),
        "dataset_id": _new_uuid(),
        "source_kind": "licensed",
        "license_ref": "CC-BY-4.0",
    }
    dpr = DataProvenanceRecord.model_validate(payload)
    assert dpr.source_kind == "licensed"
    assert dpr.evidence_refs == []


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-032")
def test_data_provenance_record_rejects_invalid_source_kind() -> None:
    from relay_schemas.envelopes import DataProvenanceRecord

    payload = {
        "schema_version": "relay.data_provenance_record.v1",
        "provenance_id": _new_uuid(),
        "project_id": _new_uuid(),
        "dataset_id": _new_uuid(),
        "source_kind": "borrowed",  # not in closed enum
    }
    with pytest.raises(ValidationError):
        DataProvenanceRecord.model_validate(payload)


# ---------------------------------------------------------------------------
# Codegen + alignment surfaces
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-030")
def test_new_envelopes_present_in_envelopes_yaml() -> None:
    import yaml

    envelopes_path = _REPO_ROOT / "packages" / "schemas" / "raw" / "envelopes.yaml"
    doc = yaml.safe_load(envelopes_path.read_text(encoding="utf-8"))
    schemas = doc.get("schemas") or {}
    missing = [name for name in _NEW_ENVELOPES if name not in schemas]
    assert not missing, f"Missing envelopes.yaml schemas entries: {missing}"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-030")
def test_new_envelopes_present_in_openapi_yaml() -> None:
    import yaml

    openapi_path = _REPO_ROOT / "packages" / "schemas" / "raw" / "openapi.yaml"
    doc = yaml.safe_load(openapi_path.read_text(encoding="utf-8"))
    schemas = (doc.get("components") or {}).get("schemas") or {}
    missing = [name for name in _NEW_ENVELOPES if name not in schemas]
    assert not missing, f"Missing OpenAPI components.schemas entries: {missing}"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-030")
def test_new_envelopes_appear_in_codegen_canonical_list() -> None:
    codegen_path = _REPO_ROOT / "packages" / "schemas" / "scripts" / "codegen.py"
    text = codegen_path.read_text(encoding="utf-8")
    for name in _NEW_ENVELOPES:
        assert f'"{name}"' in text, (
            f"codegen.py missing {name!r} in CANONICAL_ENVELOPES"
        )


# ---------------------------------------------------------------------------
# ACEF model: data_provenance_record dataclass mirror
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-032")
def test_data_provenance_record_acef_model_importable() -> None:
    """The data_provenance_record ACEF dataclass module exists and exposes
    SCHEMA_VERSION + the frozen dataclass.

    This dataclass is intentionally NOT registered in
    ``relay_extensions.RELAY_EXTENSION_NAMESPACES`` (that 10-tuple is
    locked by VAL-W11-009). It is the canonical Postgres-table mirror
    dataclass that callers in the evidence-claim path use to construct
    typed payloads from rows in ``data_provenance_records``.
    """
    from relay_extensions.models.data_provenance_record import (
        SCHEMA_VERSION,
        DataProvenanceRecord,
    )

    assert SCHEMA_VERSION == "x-relay.data-provenance-record.v1"
    dpr = DataProvenanceRecord(
        provenance_id="00000000-0000-0000-0000-000000000001",
        project_id="00000000-0000-0000-0000-000000000002",
        dataset_id="00000000-0000-0000-0000-000000000003",
        source_kind="first_party",
    )
    d = dpr.to_dict()
    assert d["schema_version"] == SCHEMA_VERSION
    assert d["source_kind"] == "first_party"
    assert d["evidence_refs"] == []


# ---------------------------------------------------------------------------
# Sidecar mirror: each new table present
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-030")
def test_sidecar_mirror_declares_each_new_table() -> None:
    text = _read_sidecar_ddl().lower()
    for table in (
        "human_oversight_events",
        "data_quality_checks",
        "data_provenance_records",
    ):
        assert f"create table if not exists {table}" in text, (
            f"sidecar mirror missing CREATE TABLE IF NOT EXISTS {table}"
        )
