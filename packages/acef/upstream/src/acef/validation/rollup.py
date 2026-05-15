"""ACEF provision rollup — 7-step deterministic precedence algorithm.

Per spec Section 3.7:
1. Any fail-severity rule failed → NOT_SATISFIED
2. Any rule errored → NOT_ASSESSED
3. All rules skipped → SKIPPED
4. Evidence gap exists, no fails failed → GAP_ACKNOWLEDGED
5. All fails passed, some warnings failed → PARTIALLY_SATISFIED
6. All rules passed (or all non-skipped rules passed) → SATISFIED
7. No rules for provision → NOT_ASSESSED
"""

from __future__ import annotations

from acef.models.assessment import ProvisionSummary, RuleResult
from acef.models.enums import ProvisionOutcome, RuleOutcome, RuleSeverity
from acef.models.records import RecordEnvelope


def compute_provision_outcome(
    provision_id: str,
    profile_id: str,
    rule_results: list[RuleResult],
    records: list[RecordEnvelope],
    *,
    subject_scope: list[str] | None = None,
) -> ProvisionSummary:
    """Compute the provision outcome using the 7-step precedence algorithm.

    Args:
        provision_id: The provision being assessed.
        profile_id: The profile/template ID.
        rule_results: All rule results for this provision.
        records: All evidence records (for checking evidence_gap).
        subject_scope: Subject URNs this summary covers.

    Returns:
        A ProvisionSummary with the computed outcome.
    """
    if subject_scope is None:
        subject_scope = []

    # Filter results for this provision
    provision_results = [r for r in rule_results if r.provision_id == provision_id]

    # Count by outcome and severity
    fail_count = 0
    warning_count = 0
    skipped_count = 0
    total = len(provision_results)

    all_evidence_refs: list[str] = []

    has_fail_severity_failed = False
    has_error = False
    all_skipped = True
    has_warning_failed = False

    for result in provision_results:
        all_evidence_refs.extend(result.evidence_refs)

        if result.outcome == RuleOutcome.SKIPPED:
            skipped_count += 1
        else:
            all_skipped = False

        if result.outcome == RuleOutcome.ERROR:
            has_error = True

        if result.outcome == RuleOutcome.FAILED:
            if result.rule_severity == RuleSeverity.FAIL:
                fail_count += 1
                has_fail_severity_failed = True
            elif result.rule_severity == RuleSeverity.WARNING:
                warning_count += 1
                has_warning_failed = True

    # Check for evidence gaps for this provision
    has_evidence_gap = any(
        r.record_type == "evidence_gap"
        and provision_id in r.provisions_addressed
        for r in records
    )

    # 7-step precedence algorithm (first match wins)
    if total == 0:
        # Step 7: No rules for provision
        outcome = ProvisionOutcome.NOT_ASSESSED
    elif has_fail_severity_failed:
        # Step 1: Any fail-severity rule failed
        outcome = ProvisionOutcome.NOT_SATISFIED
    elif has_error:
        # Step 2: Any rule errored
        outcome = ProvisionOutcome.NOT_ASSESSED
    elif all_skipped:
        # Step 3: All rules skipped
        outcome = ProvisionOutcome.SKIPPED
    elif has_evidence_gap:
        # Step 4: Evidence gap acknowledged (no fail-severity failures since step 1 didn't match)
        outcome = ProvisionOutcome.GAP_ACKNOWLEDGED
    elif has_warning_failed:
        # Step 5: All fail-severity rules passed (step 1 didn't match), some warnings failed
        outcome = ProvisionOutcome.PARTIALLY_SATISFIED
    elif not has_fail_severity_failed and not has_error and not has_warning_failed:
        # Step 6: All evaluated rules passed (skipped rules are not-applicable,
        # so a mix of passed + skipped with no failures/errors = satisfied)
        outcome = ProvisionOutcome.SATISFIED
    else:
        # Fallback: should not be reached given the above conditions are exhaustive
        outcome = ProvisionOutcome.NOT_ASSESSED

    # Deduplicate evidence refs
    unique_refs = list(dict.fromkeys(all_evidence_refs))

    return ProvisionSummary(
        provision_id=provision_id,
        profile_id=profile_id,
        provision_outcome=outcome,
        subject_scope=subject_scope,
        fail_count=fail_count,
        warning_count=warning_count,
        skipped_count=skipped_count,
        evidence_refs=unique_refs,
    )
