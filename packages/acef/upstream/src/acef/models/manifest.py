"""ACEF manifest models — the acef-manifest.json structure."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from acef.models.entities import EntitiesBlock
from acef.models.enums import AuditEventType
from acef.models.metadata import PackageMetadata, Versioning
from acef.models.subjects import Subject


class RecordFileEntry(BaseModel):
    """A reference to a record file in records/."""

    path: str
    record_type: str
    count: int = 0


class ProfileEntry(BaseModel):
    """A regulation profile declaration."""

    profile_id: str
    template_version: str = "1.0.0"
    applicable_provisions: list[str] = Field(default_factory=list)


class AuditTrailEntry(BaseModel):
    """A package-level audit trail event."""

    event_type: AuditEventType
    timestamp: str
    actor_ref: str = ""
    description: str = ""


class Manifest(BaseModel):
    """The complete acef-manifest.json structure."""

    metadata: PackageMetadata
    versioning: Versioning = Field(default_factory=Versioning)
    subjects: list[Subject] = Field(default_factory=list)
    entities: EntitiesBlock = Field(default_factory=EntitiesBlock)
    profiles: list[ProfileEntry] = Field(default_factory=list)
    record_files: list[RecordFileEntry] = Field(default_factory=list)
    audit_trail: list[AuditTrailEntry] = Field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict for JSON output."""
        return self.model_dump(mode="json", exclude_none=True)
