"""ACEF redaction module — privacy-preserving redaction with hash commitments.

Supports:
- Hash-commitment redaction (replace payload with hash)
- Access policies (roles and organizations)
- Redacted package verification
"""

from __future__ import annotations

from typing import Any

from acef.integrity import canonicalize, sha256_hex
from acef.models.enums import Confidentiality
from acef.models.records import RecordEnvelope
from acef.package import Package


def redact_record(
    record: RecordEnvelope,
    *,
    method: str = "sha256-hash-commitment",
    access_policy: dict[str, Any] | None = None,
) -> RecordEnvelope:
    """Create a redacted copy of a record.

    The payload is replaced with a hash commitment. The original payload
    hash is stored in redaction_method for verification.

    Args:
        record: The record to redact.
        method: Redaction method (default: sha256-hash-commitment).
        access_policy: Who can see the full payload.

    Returns:
        A new RecordEnvelope with redacted payload.
    """
    # Compute hash of canonical payload
    payload_canonical = canonicalize(record.payload)
    payload_hash = sha256_hex(payload_canonical)

    # Create redacted copy
    redacted = record.model_copy(deep=True)
    redacted.confidentiality = Confidentiality.HASH_COMMITTED
    redacted.redaction_method = f"{method}:{payload_hash}"
    redacted.access_policy = access_policy
    redacted.payload = {"_redacted": True, "_commitment": f"sha256:{payload_hash}"}

    return redacted


def verify_redaction(
    redacted_record: RecordEnvelope,
    original_payload: dict[str, Any],
) -> bool:
    """Verify that a redacted record's hash commitment matches original payload.

    Args:
        redacted_record: The redacted record.
        original_payload: The original (unredacted) payload.

    Returns:
        True if the commitment matches.
    """
    if not redacted_record.redaction_method:
        return False

    # Extract expected hash from redaction method
    parts = redacted_record.redaction_method.split(":")
    if len(parts) < 2:
        return False
    expected_hash = parts[-1]

    # Compute hash of original payload
    payload_canonical = canonicalize(original_payload)
    actual_hash = sha256_hex(payload_canonical)

    return actual_hash == expected_hash


def redact_package(
    package: Package,
    *,
    record_filter: dict[str, Any] | None = None,
    method: str = "sha256-hash-commitment",
    access_policy: dict[str, Any] | None = None,
) -> Package:
    """Create a redacted copy of a package.

    Uses public properties to read package state and _init_from_parts()
    to construct the new package (M-R2-3).

    Args:
        package: The package to redact.
        record_filter: Filter criteria for which records to redact.
                      Keys: record_types (list), confidentiality_levels (list).
        method: Redaction method.
        access_policy: Default access policy for redacted records.

    Returns:
        A new Package with selected records redacted.
    """
    if record_filter is None:
        record_filter = {}

    redact_types = set(record_filter.get("record_types", []))
    redact_levels = set(record_filter.get("confidentiality_levels", []))

    # Process records (using public .records property)
    new_records = []
    for record in package.records:
        should_redact = False
        if redact_types and record.record_type in redact_types:
            should_redact = True
        if redact_levels and record.confidentiality.value in redact_levels:
            should_redact = True

        if should_redact:
            redacted = redact_record(record, method=method, access_policy=access_policy)
            new_records.append(redacted)
        else:
            new_records.append(record.model_copy(deep=True))

    # Build new package via _init_from_parts using public properties (M-R2-3)
    return Package._init_from_parts(
        metadata=package.metadata.model_copy(deep=True),
        versioning=package.versioning.model_copy(deep=True),
        subjects=[s.model_copy(deep=True) for s in package.subjects],
        entities=package.entities.model_copy(deep=True),
        profiles=[p.model_copy(deep=True) for p in package.profiles],
        records=new_records,
        audit_trail=[a.model_copy(deep=True) for a in package.audit_trail],
        attachments=dict(package.attachments),
    )
