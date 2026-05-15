"""ACEF subject models — AI systems and models being documented."""

from __future__ import annotations

from pydantic import BaseModel, Field

from acef.models.enums import LifecyclePhase, RiskClassification, SubjectType
from acef.models.urns import URNType, generate_urn


class LifecycleEntry(BaseModel):
    """A lifecycle phase transition entry."""

    phase: LifecyclePhase
    start_date: str
    end_date: str | None = None


class Subject(BaseModel):
    """An AI system or model being documented."""

    subject_id: str = Field(default_factory=lambda: generate_urn(URNType.SUBJECT))
    subject_type: SubjectType
    name: str
    version: str = "1.0.0"
    provider: str = ""
    risk_classification: RiskClassification = RiskClassification.MINIMAL_RISK
    modalities: list[str] = Field(default_factory=list)
    lifecycle_phase: LifecyclePhase = LifecyclePhase.DEVELOPMENT
    lifecycle_timeline: list[LifecycleEntry] = Field(default_factory=list)

    @property
    def id(self) -> str:
        """Shortcut for subject_id."""
        return self.subject_id
