"""Tests for acef.validation.rollup — 7-step provision outcome precedence algorithm."""

from __future__ import annotations

from acef.models.assessment import RuleResult
from acef.models.enums import ProvisionOutcome, RuleOutcome, RuleSeverity
from acef.models.records import RecordEnvelope
from acef.validation.rollup import compute_provision_outcome


def _rule_result(
    outcome: RuleOutcome,
    severity: RuleSeverity = RuleSeverity.FAIL,
    provision_id: str = "prov-1",
    rule_id: str = "rule-1",
    evidence_refs: list[str] | None = None,
) -> RuleResult:
    """Helper to create rule results."""
    return RuleResult(
        rule_id=rule_id,
        provision_id=provision_id,
        profile_id="test-profile",
        rule_severity=severity,
        outcome=outcome,
        evidence_refs=evidence_refs or [],
    )


class TestProvisionRollup:
    """Test all 7 cases of the provision outcome precedence algorithm."""

    def test_step1_fail_severity_failed_gives_not_satisfied(self):
        """Step 1: Any fail-severity rule failed -> NOT_SATISFIED."""
        results = [
            _rule_result(RuleOutcome.PASSED, RuleSeverity.FAIL, rule_id="r1"),
            _rule_result(RuleOutcome.FAILED, RuleSeverity.FAIL, rule_id="r2"),
        ]
        summary = compute_provision_outcome("prov-1", "test-profile", results, [])
        assert summary.provision_outcome == ProvisionOutcome.NOT_SATISFIED
        assert summary.fail_count == 1

    def test_step2_rule_errored_gives_not_assessed(self):
        """Step 2: Any rule errored -> NOT_ASSESSED."""
        results = [
            _rule_result(RuleOutcome.PASSED, RuleSeverity.FAIL, rule_id="r1"),
            _rule_result(RuleOutcome.ERROR, RuleSeverity.FAIL, rule_id="r2"),
        ]
        summary = compute_provision_outcome("prov-1", "test-profile", results, [])
        assert summary.provision_outcome == ProvisionOutcome.NOT_ASSESSED

    def test_step3_all_skipped_gives_skipped(self):
        """Step 3: All rules skipped -> SKIPPED."""
        results = [
            _rule_result(RuleOutcome.SKIPPED, RuleSeverity.FAIL, rule_id="r1"),
            _rule_result(RuleOutcome.SKIPPED, RuleSeverity.WARNING, rule_id="r2"),
        ]
        summary = compute_provision_outcome("prov-1", "test-profile", results, [])
        assert summary.provision_outcome == ProvisionOutcome.SKIPPED
        assert summary.skipped_count == 2

    def test_step4_evidence_gap_no_fails_gives_gap_acknowledged(self):
        """Step 4: Evidence gap exists + no fail-severity failures -> GAP_ACKNOWLEDGED."""
        results = [
            _rule_result(RuleOutcome.PASSED, RuleSeverity.FAIL, rule_id="r1"),
        ]
        # Create an evidence_gap record for this provision
        gap_record = RecordEnvelope(
            record_type="evidence_gap",
            provisions_addressed=["prov-1"],
            payload={"reason": "Data not yet available"},
        )
        summary = compute_provision_outcome("prov-1", "test-profile", results, [gap_record])
        assert summary.provision_outcome == ProvisionOutcome.GAP_ACKNOWLEDGED

    def test_step5_warning_failed_gives_partially_satisfied(self):
        """Step 5: All fails passed, some warnings failed -> PARTIALLY_SATISFIED."""
        results = [
            _rule_result(RuleOutcome.PASSED, RuleSeverity.FAIL, rule_id="r1"),
            _rule_result(RuleOutcome.FAILED, RuleSeverity.WARNING, rule_id="r2"),
        ]
        summary = compute_provision_outcome("prov-1", "test-profile", results, [])
        assert summary.provision_outcome == ProvisionOutcome.PARTIALLY_SATISFIED
        assert summary.warning_count == 1

    def test_step6_all_passed_gives_satisfied(self):
        """Step 6: All rules passed -> SATISFIED."""
        results = [
            _rule_result(RuleOutcome.PASSED, RuleSeverity.FAIL, rule_id="r1"),
            _rule_result(RuleOutcome.PASSED, RuleSeverity.WARNING, rule_id="r2"),
            _rule_result(RuleOutcome.PASSED, RuleSeverity.INFO, rule_id="r3"),
        ]
        summary = compute_provision_outcome("prov-1", "test-profile", results, [])
        assert summary.provision_outcome == ProvisionOutcome.SATISFIED

    def test_step7_no_rules_gives_not_assessed(self):
        """Step 7: No rules for provision -> NOT_ASSESSED."""
        summary = compute_provision_outcome("prov-1", "test-profile", [], [])
        assert summary.provision_outcome == ProvisionOutcome.NOT_ASSESSED

    def test_evidence_refs_collected(self):
        """Evidence refs from all rules are collected and deduplicated."""
        results = [
            _rule_result(
                RuleOutcome.PASSED, RuleSeverity.FAIL, rule_id="r1",
                evidence_refs=["rec-1", "rec-2"],
            ),
            _rule_result(
                RuleOutcome.PASSED, RuleSeverity.FAIL, rule_id="r2",
                evidence_refs=["rec-2", "rec-3"],
            ),
        ]
        summary = compute_provision_outcome("prov-1", "test-profile", results, [])
        assert summary.evidence_refs == ["rec-1", "rec-2", "rec-3"]

    def test_subject_scope_passed_through(self):
        """Subject scope is passed through to the summary."""
        results = [_rule_result(RuleOutcome.PASSED)]
        summary = compute_provision_outcome(
            "prov-1", "test-profile", results, [],
            subject_scope=["urn:acef:sub:00000000-0000-0000-0000-000000000001"],
        )
        assert summary.subject_scope == ["urn:acef:sub:00000000-0000-0000-0000-000000000001"]

    def test_fail_severity_takes_precedence_over_error(self):
        """Step 1 takes precedence over Step 2."""
        results = [
            _rule_result(RuleOutcome.FAILED, RuleSeverity.FAIL, rule_id="r1"),
            _rule_result(RuleOutcome.ERROR, RuleSeverity.FAIL, rule_id="r2"),
        ]
        summary = compute_provision_outcome("prov-1", "test-profile", results, [])
        assert summary.provision_outcome == ProvisionOutcome.NOT_SATISFIED
