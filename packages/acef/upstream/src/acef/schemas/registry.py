"""ACEF schema registry — loading, validation, variant resolution.

Schemas are stored in acef-conventions/v{major}/ and discovered by convention:
- manifest.schema.json
- record-envelope.schema.json
- assessment-bundle.schema.json
- {record_type}.schema.json per record type
- variant-registry.json for payload variant lookup
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, ValidationError

from acef.errors import ACEFSchemaError

# Schema base directories — searched in order.
# First: relative to project root (development layout)
# Second: relative to the installed acef package (pip install layout)
_SCHEMA_DIRS: list[Path] = [
    Path(__file__).resolve().parents[3] / "acef-conventions",  # project root/acef-conventions
    Path(__file__).resolve().parent.parent / "acef-conventions",  # package-sibling fallback
]


def _find_schema_dir(version: str = "v1") -> Path:
    """Find the schema directory for a given version."""
    for base in _SCHEMA_DIRS:
        candidate = base / version
        if candidate.exists():
            return candidate
    raise ACEFSchemaError(
        f"Schema directory not found for version {version}. "
        f"Searched: {[str(b) for b in _SCHEMA_DIRS]}",
        code="ACEF-001",
    )


@lru_cache(maxsize=64)
def load_schema(schema_name: str, version: str = "v1") -> dict[str, Any]:
    """Load a JSON Schema by name from the registry.

    Args:
        schema_name: Schema filename without .schema.json suffix,
                     e.g., 'manifest', 'record-envelope', 'risk_register'.
        version: Schema version directory, e.g., 'v1'.

    Returns:
        The parsed JSON Schema dict.

    Raises:
        ACEFSchemaError: If the schema file is not found or invalid.
    """
    schema_dir = _find_schema_dir(version)
    schema_file = schema_dir / f"{schema_name}.schema.json"

    if not schema_file.exists():
        raise ACEFSchemaError(
            f"Schema not found: {schema_name} in {version}",
            code="ACEF-003",
        )

    try:
        with open(schema_file, "r", encoding="utf-8") as f:
            schema = json.load(f)
    except json.JSONDecodeError as e:
        raise ACEFSchemaError(
            f"Invalid JSON in schema {schema_name}: {e}",
            code="ACEF-002",
        ) from e

    return schema


def validate_against_schema(
    data: dict[str, Any],
    schema_name: str,
    version: str = "v1",
) -> list[ValidationError]:
    """Validate data against a named JSON Schema.

    Args:
        data: The data to validate.
        schema_name: The schema name (without .schema.json suffix).
        version: Schema version.

    Returns:
        List of validation errors. Empty list means valid.
    """
    try:
        schema = load_schema(schema_name, version)
    except ACEFSchemaError:
        return [ValidationError(f"Schema {schema_name} not found")]

    validator = Draft202012Validator(schema)
    return list(validator.iter_errors(data))


def validate_manifest(manifest_data: dict[str, Any], version: str = "v1") -> list[ValidationError]:
    """Validate an acef-manifest.json against the manifest schema."""
    return validate_against_schema(manifest_data, "manifest", version)


def validate_record_envelope(record_data: dict[str, Any], version: str = "v1") -> list[ValidationError]:
    """Validate a record against the record-envelope schema."""
    return validate_against_schema(record_data, "record-envelope", version)


def validate_record_payload(
    payload: dict[str, Any],
    record_type: str,
    version: str = "v1",
) -> list[ValidationError]:
    """Validate a record payload against its type-specific schema."""
    return validate_against_schema(payload, record_type, version)


@lru_cache(maxsize=1)
def load_variant_registry(version: str = "v1") -> list[dict[str, str]]:
    """Load the variant registry for bidirectional variant lookup.

    Returns:
        List of variant entries with artifact_name, record_type,
        discriminator_field, and discriminator_value.
    """
    schema_dir = _find_schema_dir(version)
    registry_file = schema_dir / "variant-registry.json"

    if not registry_file.exists():
        return []

    with open(registry_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    return data.get("variants", [])


def resolve_variant(artifact_name: str, version: str = "v1") -> dict[str, str] | None:
    """Resolve an artifact name to its parent record type and discriminator.

    Args:
        artifact_name: The artifact/variant name (e.g., 'management_review').
        version: Schema version.

    Returns:
        Dict with record_type, discriminator_field, discriminator_value,
        or None if not found.
    """
    for entry in load_variant_registry(version):
        if entry.get("artifact_name") == artifact_name:
            return entry
    return None


def resolve_record_type_for_variant(artifact_name: str, version: str = "v1") -> str | None:
    """Get the parent record type for a variant artifact name."""
    entry = resolve_variant(artifact_name, version)
    return entry["record_type"] if entry else None


def list_record_type_schemas(version: str = "v1") -> list[str]:
    """List all available record type schemas.

    Returns:
        List of record type names that have schemas available.
    """
    try:
        schema_dir = _find_schema_dir(version)
    except ACEFSchemaError:
        return []

    excluded = {"manifest", "record-envelope", "assessment-bundle", "template"}
    result: list[str] = []
    for f in sorted(schema_dir.glob("*.schema.json")):
        name = f.name.replace(".schema.json", "")
        if name not in excluded:
            result.append(name)
    return result
