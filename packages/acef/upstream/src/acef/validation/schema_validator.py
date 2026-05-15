"""ACEF schema validation — manifest, envelope, and payload validation.

Phase 1 of the 4-phase validation pipeline.
Collects ALL errors within the phase before stopping.
"""

from __future__ import annotations

from typing import Any

from acef.errors import ValidationDiagnostic
from acef.schemas.registry import validate_against_schema


def validate_manifest_schema(manifest_data: dict[str, Any]) -> list[ValidationDiagnostic]:
    """Validate manifest against the manifest JSON Schema.

    Returns:
        List of diagnostics. Empty means valid.
    """
    diagnostics: list[ValidationDiagnostic] = []

    errors = validate_against_schema(manifest_data, "manifest")
    for error in errors:
        diagnostics.append(
            ValidationDiagnostic(
                "ACEF-002",
                f"Manifest schema violation: {error.message}",
                path=_json_path(error.absolute_path),
            )
        )

    return diagnostics


def validate_record_schemas(
    records: list[dict[str, Any]],
) -> list[ValidationDiagnostic]:
    """Validate all records against envelope and payload schemas.

    For each record:
    1. Validate against record-envelope.schema.json
    2. Validate payload against {record_type}.schema.json

    Returns:
        List of diagnostics. Collects all errors.
    """
    diagnostics: list[ValidationDiagnostic] = []

    for i, record in enumerate(records):
        # Validate envelope
        envelope_errors = validate_against_schema(record, "record-envelope")
        for error in envelope_errors:
            diagnostics.append(
                ValidationDiagnostic(
                    "ACEF-004",
                    f"Record envelope schema violation (record {i}): {error.message}",
                    path=f"/records/{i}" + _json_path(error.absolute_path),
                )
            )

        # Validate payload against type-specific schema
        record_type = record.get("record_type", "")
        payload = record.get("payload", {})
        if record_type and payload:
            payload_errors = validate_against_schema(payload, record_type)
            for error in payload_errors:
                # Don't report as error if schema not found (ACEF-003 instead)
                if "not found" in str(error.message):
                    diagnostics.append(
                        ValidationDiagnostic(
                            "ACEF-003",
                            f"Unknown record_type: {record_type!r}",
                            path=f"/records/{i}/record_type",
                        )
                    )
                else:
                    diagnostics.append(
                        ValidationDiagnostic(
                            "ACEF-004",
                            f"Payload schema violation for {record_type} (record {i}): {error.message}",
                            path=f"/records/{i}/payload" + _json_path(error.absolute_path),
                        )
                    )

    return diagnostics


def _json_path(path_deque: Any) -> str:
    """Convert a jsonschema path deque to a JSON Pointer string."""
    if not path_deque:
        return ""
    parts = list(path_deque)
    return "/" + "/".join(str(p) for p in parts)
