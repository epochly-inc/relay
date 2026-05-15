"""ACEF template data models — Template, Provision, EvaluationRule, Scope, Condition."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class RuleScope(BaseModel):
    """Scope filter for DSL rules."""

    risk_classifications: list[str] = Field(default_factory=list)
    obligation_roles: list[str] = Field(default_factory=list)
    lifecycle_phases: list[str] = Field(default_factory=list)
    modalities: list[str] = Field(default_factory=list)


class RuleCondition(BaseModel):
    """Condition for when a DSL rule applies."""

    if_provision_effective: bool | None = None
    if_system_type: list[str] = Field(default_factory=list)


class EvaluationRule(BaseModel):
    """A single DSL evaluation rule within a provision."""

    rule_id: str
    rule: str  # operator name
    params: dict[str, Any] = Field(default_factory=dict)
    severity: str = "fail"  # fail | warning | info
    message: str = ""
    scope: RuleScope | None = None
    condition: RuleCondition | None = None


class SubProvision(BaseModel):
    """A sub-provision within a parent provision."""

    provision_id: str
    normative_text_ref: str = ""
    description: str = ""


class Provision(BaseModel):
    """A regulatory provision within a template."""

    provision_id: str
    provision_name: str = ""
    normative_text_ref: str = ""
    description: str = ""
    effective_date: str | None = None
    applicable_to: list[str] = Field(default_factory=list)
    sub_provisions: list[SubProvision] = Field(default_factory=list)
    required_evidence_types: list[str] = Field(default_factory=list)
    minimum_evidence_count: dict[str, int] = Field(default_factory=dict)
    evidence_freshness_max_days: int | None = None
    retention_years: int | None = None
    evaluation: list[EvaluationRule] = Field(default_factory=list)
    tiered_requirements: dict[str, Any] | None = None
    evaluation_scope: str | None = None  # "package" or None (per-subject default)


class Template(BaseModel):
    """A regulation mapping template."""

    template_id: str
    template_name: str = ""
    version: str = "1.0.0"
    jurisdiction: str = ""
    source_legislation: str = ""
    instrument_type: str = ""  # law | standard | code_of_practice | guidance | parliamentary_report
    legal_force: str = ""  # binding | voluntary | advisory
    instrument_status: str = "final"  # final | draft
    default_effective_date: str | None = None
    superseded_by: str | None = None
    applicable_system_types: list[str] = Field(default_factory=list)
    provisions: list[Provision] = Field(default_factory=list)
    test_vectors: list[str] = Field(default_factory=list)
