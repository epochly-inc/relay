"""ACEF metadata models — ProducerInfo, RetentionPolicy, PackageMetadata."""

from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, Field

from acef.models.urns import URNType, generate_urn


class ProducerInfo(BaseModel):
    """Organization/tool that created this package."""

    name: str
    version: str


class RetentionPolicy(BaseModel):
    """Package-level retention requirements."""

    min_retention_days: int = Field(ge=0)
    personal_data_interplay: str | None = None


class Versioning(BaseModel):
    """Module version declarations."""

    core_version: str = "1.0.0"
    profiles_version: str = "1.0.0"


class PackageMetadata(BaseModel):
    """Package-level metadata for an ACEF Evidence Bundle."""

    package_id: str = Field(default_factory=lambda: generate_urn(URNType.PACKAGE))
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    producer: ProducerInfo
    prior_package_ref: str | None = None
    retention_policy: RetentionPolicy | None = None
