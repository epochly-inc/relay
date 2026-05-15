"""ACEF rule engine — DSL evaluation, scope filtering, conditions.

Evaluates template rules against evidence records per subject.
"""

from __future__ import annotations

from typing import Any

from acef.models.enums import RuleOutcome, RuleSeverity
from acef.models.assessment import RuleResult
from acef.models.records import RecordEnvelope
from acef.templates.models import EvaluationRule, Provision
from acef.validation.operators import OPERATOR_REGISTRY


def _matches_scope(
    record: RecordEnvelope,
    scope: dict[str, Any] | None,
    subject_modalities: list[str] | None = None,
) -> bool:
    """Check if a record matches a rule's scope filter.

    If scope is None, the record matches (rule applies to all records).
    If scope is present, ALL criteria must match.
    """
    if scope is None:
        return True

    # Check obligation_role
    if scope.get("obligation_roles"):
        role = record.obligation_role.value if record.obligation_role else ""
        if role not in scope["obligation_roles"]:
            return False

    # Check lifecycle_phase
    if scope.get("lifecycle_phases"):
        phase = record.lifecycle_phase.value if record.lifecycle_phase else ""
        if phase not in scope["lifecycle_phases"]:
            return False

    # Check modalities (matched against subject modalities passed in)
    if scope.get("modalities") and subject_modalities is not None:
        if not any(m in scope["modalities"] for m in subject_modalities):
            return False

    # Check risk_classifications (matched against subject, not record)
    # This is handled at the subject level in evaluate_rules_for_subject

    return True


def _check_condition(
    condition: dict[str, Any] | None,
    *,
    provision_effective: bool = True,
    subject_type: str = "",
) -> bool:
    """Evaluate a rule's condition.

    If condition is None, the rule applies.
    If condition evaluates to false, the rule is SKIPPED.
    """
    if condition is None:
        return True

    if condition.get("if_provision_effective") is True and not provision_effective:
        return False

    if condition.get("if_system_type"):
        if subject_type and subject_type not in condition["if_system_type"]:
            return False

    return True


def evaluate_rules_for_subject(
    provisions: list[Provision],
    records: list[RecordEnvelope],
    *,
    subject_id: str = "",
    subject_risk_classification: str = "",
    subject_modalities: list[str] | None = None,
    profile_id: str = "",
    evaluation_instant: str = "",
    package_timestamp: str = "",
    signature_count: int = 0,
    signature_algorithms: list[str] | None = None,
) -> list[RuleResult]:
    """Evaluate all rules from provisions against records for a single subject.

    Args:
        provisions: Template provisions to evaluate.
        records: All evidence records (will be filtered by scope).
        subject_id: The subject URN being evaluated.
        subject_risk_classification: The subject's risk classification.
        profile_id: The template/profile ID.
        evaluation_instant: ISO 8601 evaluation timestamp.
        package_timestamp: ISO 8601 package creation timestamp.
        signature_count: Number of valid signatures on the bundle.
        signature_algorithms: Algorithms of valid signatures.

    Returns:
        List of RuleResult objects.
    """
    results: list[RuleResult] = []

    for provision in provisions:
        # Check if provision applies to this subject's risk classification
        if provision.applicable_to:
            if subject_risk_classification and subject_risk_classification not in provision.applicable_to:
                continue

        # Check provision effective date
        provision_effective = True
        if provision.effective_date and evaluation_instant:
            provision_effective = evaluation_instant >= provision.effective_date

        # Expand required_evidence_types to has_record_type rules if no evaluation rules exist
        rules = list(provision.evaluation)
        if not rules and provision.required_evidence_types:
            for rt in provision.required_evidence_types:
                min_count = provision.minimum_evidence_count.get(rt, 1)
                rules.append(
                    EvaluationRule(
                        rule_id=f"{provision.provision_id}-{rt}-exists",
                        rule="has_record_type",
                        params={"type": rt, "min_count": min_count},
                        severity="fail",
                        message=f"At least {min_count} {rt} record(s) required",
                    )
                )

        for rule in rules:
            result = _evaluate_single_rule(
                rule,
                records,
                provision_id=provision.provision_id,
                profile_id=profile_id,
                subject_id=subject_id,
                subject_risk_classification=subject_risk_classification,
                subject_modalities=subject_modalities,
                provision_effective=provision_effective,
                evaluation_instant=evaluation_instant,
                package_timestamp=package_timestamp,
                provision_effective_date=provision.effective_date or "",
                signature_count=signature_count,
                signature_algorithms=signature_algorithms,
            )
            results.append(result)

    return results


def _evaluate_single_rule(
    rule: EvaluationRule,
    records: list[RecordEnvelope],
    *,
    provision_id: str,
    profile_id: str,
    subject_id: str = "",
    subject_risk_classification: str = "",
    subject_modalities: list[str] | None = None,
    provision_effective: bool = True,
    evaluation_instant: str = "",
    package_timestamp: str = "",
    provision_effective_date: str = "",
    signature_count: int = 0,
    signature_algorithms: list[str] | None = None,
) -> RuleResult:
    """Evaluate a single DSL rule."""
    severity = RuleSeverity(rule.severity)

    # Check condition
    condition_dict = rule.condition.model_dump() if rule.condition else None
    if not _check_condition(
        condition_dict,
        provision_effective=provision_effective,
        subject_type=subject_risk_classification,
    ):
        return RuleResult(
            rule_id=rule.rule_id,
            provision_id=provision_id,
            profile_id=profile_id,
            rule_severity=severity,
            outcome=RuleOutcome.SKIPPED,
            message="Rule condition not met (skipped)",
            subject_scope=[subject_id] if subject_id else [],
        )

    # Filter records by scope
    scope_dict = rule.scope.model_dump() if rule.scope else None
    if scope_dict:
        # Filter by risk classification at subject level
        risk_classes = scope_dict.get("risk_classifications", [])
        if risk_classes and subject_risk_classification not in risk_classes:
            return RuleResult(
                rule_id=rule.rule_id,
                provision_id=provision_id,
                profile_id=profile_id,
                rule_severity=severity,
                outcome=RuleOutcome.SKIPPED,
                message=f"Subject risk classification {subject_risk_classification!r} not in scope",
                subject_scope=[subject_id] if subject_id else [],
            )

    filtered_records = [
        r for r in records
        if _matches_scope(r, scope_dict, subject_modalities=subject_modalities)
    ]

    # If subject_id is specified, further filter to records referencing this subject
    if subject_id:
        subject_filtered = [
            r for r in filtered_records
            if not r.entity_refs.subject_refs or subject_id in r.entity_refs.subject_refs
        ]
        filtered_records = subject_filtered

    # Look up operator
    operator_name = rule.rule
    operator_func = OPERATOR_REGISTRY.get(operator_name)

    if operator_func is None:
        return RuleResult(
            rule_id=rule.rule_id,
            provision_id=provision_id,
            profile_id=profile_id,
            rule_severity=severity,
            outcome=RuleOutcome.ERROR,
            message=f"Unknown operator: {operator_name!r}",
            subject_scope=[subject_id] if subject_id else [],
        )

    try:
        # Special handling for operators that need extra context
        if operator_name == "evidence_freshness":
            # M6 (Implementer R2): Thread provision_effective_date through
            passed, evidence_refs = operator_func(
                rule.params,
                filtered_records,
                evaluation_instant=evaluation_instant,
                package_timestamp=package_timestamp,
                provision_effective_date=provision_effective_date,
            )
        elif operator_name == "bundle_signed":
            passed, evidence_refs = operator_func(
                rule.params,
                filtered_records,
                signature_count=signature_count,
                signature_algorithms=signature_algorithms,
            )
        else:
            passed, evidence_refs = operator_func(rule.params, filtered_records)

        outcome = RuleOutcome.PASSED if passed else RuleOutcome.FAILED
        message = None if passed else rule.message

        return RuleResult(
            rule_id=rule.rule_id,
            provision_id=provision_id,
            profile_id=profile_id,
            rule_severity=severity,
            outcome=outcome,
            message=message,
            evidence_refs=evidence_refs,
            subject_scope=[subject_id] if subject_id else [],
        )

    except Exception as e:
        return RuleResult(
            rule_id=rule.rule_id,
            provision_id=provision_id,
            profile_id=profile_id,
            rule_severity=severity,
            outcome=RuleOutcome.ERROR,
            message=f"Rule evaluation error: {e}",
            subject_scope=[subject_id] if subject_id else [],
        )
