"""ACEF assessment models — Assessment Bundle data structures."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from acef.models.enums import ProvisionOutcome, RuleOutcome, RuleSeverity
from acef.models.urns import URNType, generate_urn


class Assessor(BaseModel):
    """The tool/organization that performed the assessment."""

    name: str = "acef-validator"
    version: str = "1.0.0"
    organization: str = "AI Commons"


class EvidenceBundleRef(BaseModel):
    """Reference to the Evidence Bundle being assessed."""

    content_hash: str = ""
    package_id: str = ""


class RuleResult(BaseModel):
    """Result of evaluating a single DSL rule."""

    rule_id: str
    provision_id: str
    profile_id: str
    rule_severity: RuleSeverity
    outcome: RuleOutcome
    message: str | None = None
    evidence_refs: list[str] = Field(default_factory=list)
    subject_scope: list[str] = Field(default_factory=list)


class ProvisionSummary(BaseModel):
    """Roll-up summary for a single provision."""

    provision_id: str
    profile_id: str
    provision_outcome: ProvisionOutcome
    subject_scope: list[str] = Field(default_factory=list)
    fail_count: int = 0
    warning_count: int = 0
    skipped_count: int = 0
    evidence_refs: list[str] = Field(default_factory=list)


class AssessmentVersioning(BaseModel):
    """Assessment Bundle versioning — uses assessment_version, NOT profiles_version.

    Per spec Section 3.7: Assessment Bundles declare core_version and
    assessment_version. The profiles_version is only in Evidence Bundles.
    """

    core_version: str = "1.0.0"
    assessment_version: str = "1.0.0"


class AssessmentIntegrity(BaseModel):
    """Assessment Bundle integrity (signature) block."""

    signature: dict[str, str] | None = None


class AssessmentBundle(BaseModel):
    """ACEF Assessment Bundle — validation results for an Evidence Bundle."""

    versioning: AssessmentVersioning = Field(default_factory=AssessmentVersioning)
    assessment_id: str = Field(default_factory=lambda: generate_urn(URNType.ASSESSMENT))
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    evaluation_instant: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    )
    assessor: Assessor = Field(default_factory=Assessor)
    evidence_bundle_ref: EvidenceBundleRef = Field(default_factory=EvidenceBundleRef)
    profiles_evaluated: list[str] = Field(default_factory=list)
    template_digests: dict[str, str] = Field(default_factory=dict)
    results: list[RuleResult] = Field(default_factory=list)
    provision_summary: list[ProvisionSummary] = Field(default_factory=list)
    structural_errors: list[dict[str, Any]] = Field(default_factory=list)
    integrity: AssessmentIntegrity | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict for JSON output."""
        return self.model_dump(mode="json")

    def summary(self) -> str:
        """Human-readable summary of assessment results."""
        parts: list[str] = []
        by_profile: dict[str, list[ProvisionSummary]] = {}
        for ps in self.provision_summary:
            by_profile.setdefault(ps.profile_id, []).append(ps)

        for profile_id, summaries in by_profile.items():
            total = len(summaries)
            passed = sum(1 for s in summaries if s.provision_outcome == ProvisionOutcome.SATISFIED)
            gaps = sum(1 for s in summaries if s.provision_outcome == ProvisionOutcome.GAP_ACKNOWLEDGED)
            part = f"{profile_id}: {passed}/{total} provisions passed"
            if gaps:
                part += f", {gaps} gap acknowledged"
            parts.append(part)

        return " | ".join(parts) if parts else "No provisions evaluated"

    def errors(self) -> list[dict[str, Any]]:
        """Return all structural errors and failed rule results."""
        result: list[dict[str, Any]] = list(self.structural_errors)
        for r in self.results:
            if r.outcome == RuleOutcome.FAILED:
                result.append({
                    "rule_id": r.rule_id,
                    "provision_id": r.provision_id,
                    "severity": r.rule_severity.value,
                    "outcome": r.outcome.value,
                    "message": r.message,
                })
        return result
