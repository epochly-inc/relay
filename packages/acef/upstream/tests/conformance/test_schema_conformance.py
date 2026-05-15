"""Conformance test: JSON Schema validation.

Verifies that the schema validation phase correctly validates
record envelopes, payloads, and manifests against their schemas.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from acef.schemas.registry import (
    validate_against_schema,
    validate_manifest,
    validate_record_envelope,
    validate_record_payload,
)
from acef.validation.engine import validate_bundle
from acef.validation.schema_validator import validate_manifest_schema, validate_record_schemas

from tests.conformance.conftest import build_minimal_package


def _build_schema_valid_manifest() -> dict[str, Any]:
    """Build a manifest dict that fully satisfies the manifest.schema.json."""
    return {
        "metadata": {
            "package_id": "urn:acef:pkg:00000000-0000-0000-0000-000000000001",
            "timestamp": "2025-06-01T00:00:00Z",
            "producer": {"name": "test-tool", "version": "1.0.0"},
        },
        "versioning": {
            "core_version": "1.0.0",
            "profiles_version": "1.0.0",
        },
        "subjects": [
            {
                "subject_id": "urn:acef:sub:00000000-0000-0000-0000-000000000001",
                "subject_type": "ai_system",
                "name": "Test System",
                "version": "1.0.0",
                "provider": "Test Corp",
                "risk_classification": "high-risk",
                "modalities": ["text"],
                "lifecycle_phase": "deployment",
            }
        ],
        "entities": {
            "components": [],
            "datasets": [],
            "actors": [],
            "relationships": [],
        },
        "profiles": [],
        "record_files": [
            {
                "path": "records/risk_register.jsonl",
                "record_type": "risk_register",
                "count": 1,
            }
        ],
        "audit_trail": [],
    }


def _build_schema_valid_record() -> dict[str, Any]:
    """Build a record dict that fully satisfies record-envelope.schema.json."""
    return {
        "record_id": "urn:acef:rec:00000000-0000-0000-0000-000000000001",
        "record_type": "risk_register",
        "provisions_addressed": ["article-9"],
        "timestamp": "2025-06-01T00:00:00Z",
        "lifecycle_phase": "deployment",
        "collector": {"name": "test-tool", "version": "1.0.0"},
        "obligation_role": "provider",
        "confidentiality": "public",
        "trust_level": "self-attested",
        "entity_refs": {
            "subject_refs": ["urn:acef:sub:00000000-0000-0000-0000-000000000001"],
            "component_refs": [],
            "dataset_refs": [],
            "actor_refs": [],
        },
        "payload": {
            "risk_id": "RISK-001",
            "description": "Test risk",
            "category": "safety",
            "likelihood": "possible",
            "severity": "moderate",
        },
    }


class TestSchemaConformance:
    """Schema conformance: manifest, envelope, and payload schema validation."""

    def test_valid_manifest_passes_schema(self) -> None:
        """A well-formed manifest passes manifest schema validation."""
        manifest = _build_schema_valid_manifest()
        diagnostics = validate_manifest_schema(manifest)
        assert len(diagnostics) == 0, (
            f"Valid manifest should pass schema, got: "
            f"{[(d.code, d.message) for d in diagnostics]}"
        )

    def test_valid_record_payloads_pass_schema(self) -> None:
        """A record with all required fields passes schema validation."""
        record = _build_schema_valid_record()
        diagnostics = validate_record_schemas([record])
        schema_errors = [d for d in diagnostics if d.code in ("ACEF-003", "ACEF-004")]
        assert len(schema_errors) == 0, (
            f"Valid record should pass schema, got: "
            f"{[(d.code, d.message) for d in schema_errors]}"
        )

    def test_invalid_payload_fails_with_acef_004(self) -> None:
        """A record payload violating its type schema produces ACEF-004.

        The payload is non-empty (has data) but missing required fields
        defined by the risk_register schema (risk_id, description, category).
        """
        invalid_record = _build_schema_valid_record()
        # Provide a non-empty payload that is missing required schema fields
        invalid_record["payload"] = {"irrelevant_field": "some_value"}

        diagnostics = validate_record_schemas([invalid_record])
        has_004 = any(d.code == "ACEF-004" for d in diagnostics)
        assert has_004, (
            "Payload missing required fields (risk_id, description, category) "
            "should produce ACEF-004"
        )

    def test_unknown_record_type_produces_acef_003(self) -> None:
        """A record with an unknown record_type (not x- extension) produces ACEF-003."""
        unknown_record = _build_schema_valid_record()
        unknown_record["record_type"] = "completely_unknown_type"

        diagnostics = validate_record_schemas([unknown_record])
        has_003 = any(d.code == "ACEF-003" for d in diagnostics)
        assert has_003, "Unknown record_type must produce ACEF-003"

    def test_manifest_missing_required_fields_produces_acef_002(self) -> None:
        """A manifest with missing required fields produces ACEF-002."""
        bad_manifest: dict[str, Any] = {}

        diagnostics = validate_manifest_schema(bad_manifest)
        has_002 = any(d.code == "ACEF-002" for d in diagnostics)
        assert has_002, (
            "Manifest missing required fields must produce ACEF-002"
        )

    def test_manifest_missing_metadata_produces_acef_002(self) -> None:
        """Manifest without metadata block produces ACEF-002."""
        bad_manifest = _build_schema_valid_manifest()
        del bad_manifest["metadata"]

        diagnostics = validate_manifest_schema(bad_manifest)
        has_002 = any(d.code == "ACEF-002" for d in diagnostics)
        assert has_002, (
            "Manifest without metadata block must produce ACEF-002"
        )

    def test_valid_record_envelope_passes_schema(self) -> None:
        """A well-formed record envelope passes envelope schema validation."""
        valid_record = _build_schema_valid_record()
        errors = validate_record_envelope(valid_record)
        assert len(errors) == 0, (
            f"Valid record envelope should pass schema, got: {[str(e) for e in errors]}"
        )

    def test_full_validation_reports_schema_errors(self, tmp_dir: Path) -> None:
        """validate_bundle reports schema-related structural errors when manifest is invalid."""
        pkg = build_minimal_package()
        bundle_dir = tmp_dir / "schema_check"
        pkg.export(str(bundle_dir))

        # Corrupt the manifest to remove metadata
        manifest_path = bundle_dir / "acef-manifest.json"
        manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
        del manifest_data["metadata"]
        manifest_path.write_text(json.dumps(manifest_data), encoding="utf-8")

        assessment = validate_bundle(bundle_dir)
        schema_errors = [
            e for e in assessment.structural_errors
            if e.get("code") == "ACEF-002"
        ]
        assert len(schema_errors) > 0, (
            "Corrupted manifest should produce ACEF-002 in structural_errors"
        )
