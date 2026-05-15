"""ACEF record models — RecordEnvelope and supporting types."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field, ValidationError

from acef.models.enums import Confidentiality, LifecyclePhase, ObligationRole, TrustLevel
from acef.models.urns import URNType, generate_urn


class EntityRefs(BaseModel):
    """Links to entities this record concerns."""

    subject_refs: list[str] = Field(default_factory=list)
    component_refs: list[str] = Field(default_factory=list)
    dataset_refs: list[str] = Field(default_factory=list)
    actor_refs: list[str] = Field(default_factory=list)


class AttachmentRef(BaseModel):
    """Reference to a file in the artifacts/ directory."""

    path: str
    hash: str | None = None
    media_type: str = "application/octet-stream"
    attachment_type: str | None = None
    description: str = ""


class Attestation(BaseModel):
    """Cryptographic attestation of evidence authenticity."""

    method: str = "jws"
    signer: str = ""
    signed_fields: list[str] = Field(default_factory=lambda: ["/payload"])
    signature: str = ""


class RecordRetention(BaseModel):
    """Per-record retention requirements."""

    min_retention_days: int = Field(ge=0)
    retention_start_event: str = "record_creation"
    legal_basis: str = ""


class CollectorInfo(BaseModel):
    """Tool/person that collected this evidence."""

    name: str
    version: str = ""


class RecordEnvelope(BaseModel):
    """The common record envelope — identical structure for all record types.

    Contains all envelope fields plus the type-specific payload.
    """

    record_id: str = Field(default_factory=lambda: generate_urn(URNType.RECORD))
    record_type: str
    provisions_addressed: list[str] = Field(default_factory=list)
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    lifecycle_phase: LifecyclePhase | None = None
    collector: CollectorInfo | dict[str, str] | None = None
    obligation_role: ObligationRole | None = None
    confidentiality: Confidentiality = Confidentiality.PUBLIC
    redaction_method: str | None = None
    access_policy: dict[str, Any] | None = None
    trust_level: TrustLevel = TrustLevel.SELF_ATTESTED
    entity_refs: EntityRefs = Field(default_factory=EntityRefs)
    payload: dict[str, Any] = Field(default_factory=dict)
    attachments: list[AttachmentRef] = Field(default_factory=list)
    attestation: Attestation | None = None
    retention: RecordRetention | None = None

    @property
    def id(self) -> str:
        return self.record_id

    def to_jsonl_dict(self) -> dict[str, Any]:
        """Convert to a dict suitable for JSONL serialization.

        Excludes None values for clean output.
        """
        data = self.model_dump(mode="json", exclude_none=True)
        # Ensure entity_refs always present even if empty
        if "entity_refs" not in data:
            data["entity_refs"] = {
                "subject_refs": [],
                "component_refs": [],
                "dataset_refs": [],
                "actor_refs": [],
            }
        return data


def dict_to_record_envelope(data: dict[str, Any]) -> RecordEnvelope:
    """Convert a dict from JSONL deserialization to a RecordEnvelope.

    Handles nested structure conversion (entity_refs, attachments,
    attestation, retention, collector) and delegates final validation
    to Pydantic. Missing required fields will raise ACEFFormatError
    rather than silently fabricating blank defaults.

    Args:
        data: Parsed JSON dict from a JSONL record line.

    Returns:
        A validated RecordEnvelope.

    Raises:
        ACEFFormatError: If the data is missing required fields or fails
            Pydantic validation.
    """
    # Import here to avoid circular import (errors.py -> models -> errors)
    from acef.errors import ACEFFormatError

    # Handle entity_refs
    entity_refs_data = data.get("entity_refs", {})
    entity_refs = EntityRefs(
        subject_refs=entity_refs_data.get("subject_refs", []),
        component_refs=entity_refs_data.get("component_refs", []),
        dataset_refs=entity_refs_data.get("dataset_refs", []),
        actor_refs=entity_refs_data.get("actor_refs", []),
    )

    # Handle attachments
    attachments = []
    for att_data in data.get("attachments", []):
        attachments.append(AttachmentRef(**att_data))

    # Handle attestation
    attestation = None
    if data.get("attestation"):
        attestation = Attestation(**data["attestation"])

    # Handle retention
    retention = None
    if data.get("retention"):
        retention = RecordRetention(**data["retention"])

    # Handle collector
    collector = None
    if data.get("collector"):
        collector_data = data["collector"]
        if isinstance(collector_data, dict):
            collector = CollectorInfo(**collector_data)

    # Build kwargs from the data dict, letting Pydantic validate
    # required fields rather than using empty-string defaults
    kwargs: dict[str, Any] = {
        "entity_refs": entity_refs,
        "attachments": attachments,
        "payload": data.get("payload", {}),
    }

    # Required fields — pass through from data without defaults
    for field_name in ("record_id", "record_type", "timestamp"):
        if field_name in data:
            kwargs[field_name] = data[field_name]

    # Optional fields with non-None data
    for field_name in (
        "provisions_addressed",
        "lifecycle_phase",
        "obligation_role",
        "confidentiality",
        "redaction_method",
        "access_policy",
        "trust_level",
    ):
        if field_name in data:
            kwargs[field_name] = data[field_name]

    if collector is not None:
        kwargs["collector"] = collector
    if attestation is not None:
        kwargs["attestation"] = attestation
    if retention is not None:
        kwargs["retention"] = retention

    try:
        return RecordEnvelope(**kwargs)
    except ValidationError as e:
        raise ACEFFormatError(
            f"Invalid record data: {e}",
            code="ACEF-004",
        ) from e
