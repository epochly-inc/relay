"""Conformance test: provision rollup — 7-step deterministic precedence algorithm.

Tests all 7 cases in the provision outcome algorithm:
1. Any fail-severity rule failed -> NOT_SATISFIED
2. Any rule errored -> NOT_ASSESSED
3. All rules skipped -> SKIPPED
4. Evidence gap exists, no fails failed -> GAP_ACKNOWLEDGED
5. All fails passed, some warnings failed -> PARTIALLY_SATISFIED
6. All rules passed -> SATISFIED
7. No rules for provision -> NOT_ASSESSED
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from acef.models.assessment import ProvisionSummary, RuleResult
from acef.models.enums import ProvisionOutcome, RuleOutcome, RuleSeverity
from acef.models.records import RecordEnvelope
from acef.validation.rollup import compute_provision_outcome


def _make_rule_result(
    provision_id: str = "test-provision",
    profile_id: str = "test-profile",
    outcome: RuleOutcome = RuleOutcome.PASSED,
    severity: RuleSeverity = RuleSeverity.FAIL,
    rule_id: str = "rule-1",
    evidence_refs: list[str] | None = None,
) -> RuleResult:
    """Create a RuleResult for testing."""
    return RuleResult(
        rule_id=rule_id,
        provision_id=provision_id,
        profile_id=profile_id,
        rule_severity=severity,
        outcome=outcome,
        evidence_refs=evidence_refs or [],
    )


class TestProvisionRollup:
    """7-step deterministic precedence algorithm conformance."""

    def test_step1_fail_severity_failed_produces_not_satisfied(self) -> None:
        """Step 1: Any fail-severity rule failed -> NOT_SATISFIED."""
        results = [
            _make_rule_result(outcome=RuleOutcome.PASSED, severity=RuleSeverity.FAIL, rule_id="r1"),
            _make_rule_result(outcome=RuleOutcome.FAILED, severity=RuleSeverity.FAIL, rule_id="r2"),
        ]
        summary = compute_provision_outcome("test-provision", "test-profile", results, [])
        assert summary.provision_outcome == ProvisionOutcome.NOT_SATISFIED
        assert summary.fail_count == 1

    def test_step2_rule_error_produces_not_assessed(self) -> None:
        """Step 2: Any rule errored (and no fail-severity failures) -> NOT_ASSESSED."""
        results = [
            _make_rule_result(outcome=RuleOutcome.PASSED, severity=RuleSeverity.FAIL, rule_id="r1"),
            _make_rule_result(outcome=RuleOutcome.ERROR, severity=RuleSeverity.FAIL, rule_id="r2"),
        ]
        summary = compute_provision_outcome("test-provision", "test-profile", results, [])
        assert summary.provision_outcome == ProvisionOutcome.NOT_ASSESSED

    def test_step3_all_skipped_produces_skipped(self) -> None:
        """Step 3: All rules skipped -> SKIPPED."""
        results = [
            _make_rule_result(outcome=RuleOutcome.SKIPPED, severity=RuleSeverity.FAIL, rule_id="r1"),
            _make_rule_result(outcome=RuleOutcome.SKIPPED, severity=RuleSeverity.WARNING, rule_id="r2"),
        ]
        summary = compute_provision_outcome("test-provision", "test-profile", results, [])
        assert summary.provision_outcome == ProvisionOutcome.SKIPPED
        assert summary.skipped_count == 2

    def test_step4_evidence_gap_produces_gap_acknowledged(self) -> None:
        """Step 4: Evidence gap exists, no fail-severity failures -> GAP_ACKNOWLEDGED."""
        results = [
            _make_rule_result(outcome=RuleOutcome.PASSED, severity=RuleSeverity.FAIL, rule_id="r1"),
        ]
        # Create an evidence_gap record for this provision
        gap_record = RecordEnvelope(
            record_type="evidence_gap",
            provisions_addressed=["test-provision"],
            payload={"gap_type": "missing_evidence", "description": "test gap"},
        )
        summary = compute_provision_outcome(
            "test-provision", "test-profile", results, [gap_record]
        )
        assert summary.provision_outcome == ProvisionOutcome.GAP_ACKNOWLEDGED

    def test_step5_warnings_failed_produces_partially_satisfied(self) -> None:
        """Step 5: All fail-severity rules passed, some warnings failed -> PARTIALLY_SATISFIED."""
        results = [
            _make_rule_result(outcome=RuleOutcome.PASSED, severity=RuleSeverity.FAIL, rule_id="r1"),
            _make_rule_result(outcome=RuleOutcome.FAILED, severity=RuleSeverity.WARNING, rule_id="r2"),
        ]
        summary = compute_provision_outcome("test-provision", "test-profile", results, [])
        assert summary.provision_outcome == ProvisionOutcome.PARTIALLY_SATISFIED
        assert summary.warning_count == 1

    def test_step6_all_passed_produces_satisfied(self) -> None:
        """Step 6: All rules passed -> SATISFIED."""
        results = [
            _make_rule_result(outcome=RuleOutcome.PASSED, severity=RuleSeverity.FAIL, rule_id="r1"),
            _make_rule_result(outcome=RuleOutcome.PASSED, severity=RuleSeverity.WARNING, rule_id="r2"),
        ]
        summary = compute_provision_outcome("test-provision", "test-profile", results, [])
        assert summary.provision_outcome == ProvisionOutcome.SATISFIED

    def test_step7_no_rules_produces_not_assessed(self) -> None:
        """Step 7: No rules for provision -> NOT_ASSESSED."""
        summary = compute_provision_outcome("test-provision", "test-profile", [], [])
        assert summary.provision_outcome == ProvisionOutcome.NOT_ASSESSED

    def test_multi_subject_separate_provision_summaries(self, tmp_dir: Path) -> None:
        """Multi-subject evaluation produces separate provision_summary per subject."""
        from acef.package import Package as Pkg
        from acef.validation.engine import validate_bundle

        # Build a package with two subjects
        pkg = Pkg(producer={"name": "multi-subj", "version": "1.0.0"})
        sys1 = pkg.add_subject(
            "ai_system", name="System Alpha",
            risk_classification="high-risk", modalities=["text"],
        )
        sys2 = pkg.add_subject(
            "ai_system", name="System Beta",
            risk_classification="high-risk", modalities=["text"],
        )
        pkg.add_profile("eu-ai-act-2024", provisions=["article-9"])

        # Add records only for sys1
        pkg.record(
            "risk_register",
            provisions=["article-9"],
            payload={"description": "Risk for Alpha", "likelihood": "high", "severity": "high"},
            obligation_role="provider",
            entity_refs={"subject_refs": [sys1.id]},
        )
        pkg.record(
            "risk_treatment",
            provisions=["article-9"],
            payload={"treatment_type": "mitigate", "description": "Treatment Alpha"},
            obligation_role="provider",
            entity_refs={"subject_refs": [sys1.id]},
        )

        bundle_dir = tmp_dir / "multi_subject"
        pkg.export(str(bundle_dir))

        assessment = validate_bundle(
            bundle_dir,
            profiles=["eu-ai-act-2024"],
            evaluation_instant="2027-01-01T00:00:00Z",
        )

        # Should have provision summaries for both subjects
        art9_summaries = [
            s for s in assessment.provision_summary
            if s.provision_id == "article-9"
        ]
        subjects_in_summaries = set()
        for s in art9_summaries:
            for subj in s.subject_scope:
                subjects_in_summaries.add(subj)

        assert sys1.id in subjects_in_summaries, (
            "Subject Alpha should have a provision summary"
        )
        assert sys2.id in subjects_in_summaries, (
            "Subject Beta should have a provision summary"
        )

    def test_step6_mix_passed_and_skipped_produces_satisfied(self) -> None:
        """Passed + skipped (no failures/errors) produces SATISFIED."""
        results = [
            _make_rule_result(outcome=RuleOutcome.PASSED, severity=RuleSeverity.FAIL, rule_id="r1"),
            _make_rule_result(outcome=RuleOutcome.SKIPPED, severity=RuleSeverity.FAIL, rule_id="r2"),
        ]
        summary = compute_provision_outcome("test-provision", "test-profile", results, [])
        assert summary.provision_outcome == ProvisionOutcome.SATISFIED


class TestPackageScopedEvaluation:
    """Verifier M3: Package-scoped evaluation conformance test.

    evaluation_scope: "package" should produce a single provision_summary
    for the entire package, not per-subject.
    """

    def test_package_scoped_evaluation_produces_single_summary(self, tmp_dir: Path) -> None:
        """A package-scoped provision produces exactly one provision_summary (no per-subject split)."""
        from acef.package import Package as Pkg
        from acef.templates.models import EvaluationRule, Provision, Template
        from acef.templates.registry import load_template
        from acef.validation.engine import validate_bundle

        # Use a unique template ID to avoid cache collisions with other tests
        tid = "conformance-pkg-scope-single"

        template = Template(
            template_id=tid,
            template_name="Conformance Package Scope Test",
            version="1.0.0",
            provisions=[
                Provision(
                    provision_id="pkg-gov-01",
                    provision_name="Governance Policy Required",
                    evaluation_scope="package",
                    evaluation=[
                        EvaluationRule(
                            rule_id="pkg-gov-01-check",
                            rule="has_record_type",
                            params={"type": "governance_policy", "min_count": 1},
                            severity="fail",
                            message="At least one governance_policy record required",
                        ),
                    ],
                ),
            ],
        )

        template_path = (
            Path(__file__).parent.parent.parent
            / "src" / "acef" / "templates" / f"{tid}.json"
        )
        template_path.write_text(template.model_dump_json(indent=2), encoding="utf-8")

        try:
            load_template.cache_clear()

            pkg = Pkg(producer={"name": "pkg-scope-test", "version": "1.0.0"})
            pkg.add_subject(
                "ai_system", name="System A",
                risk_classification="high-risk", modalities=["text"],
            )
            pkg.add_subject(
                "ai_system", name="System B",
                risk_classification="high-risk", modalities=["text"],
            )
            pkg.add_profile(tid, provisions=["pkg-gov-01"])

            pkg.record(
                "governance_policy",
                provisions=["pkg-gov-01"],
                payload={
                    "policy_type": "quality_management",
                    "description": "Organization-level QMS policy",
                },
                obligation_role="provider",
            )

            bundle_dir = tmp_dir / "pkg_scope_conformance"
            pkg.export(str(bundle_dir))

            assessment = validate_bundle(
                bundle_dir,
                profiles=[tid],
                evaluation_instant="2026-01-15T00:00:00Z",
            )

            # Should produce exactly 1 provision_summary for pkg-gov-01
            pkg_gov_summaries = [
                s for s in assessment.provision_summary
                if s.provision_id == "pkg-gov-01"
            ]
            assert len(pkg_gov_summaries) == 1, (
                f"Package-scoped provision should produce exactly 1 summary, "
                f"got {len(pkg_gov_summaries)}"
            )

            summary = pkg_gov_summaries[0]
            assert len(summary.subject_scope) == 0, (
                "Package-scoped summary should not have subject_scope"
            )

            assert summary.provision_outcome == ProvisionOutcome.SATISFIED, (
                f"Expected SATISFIED, got {summary.provision_outcome}"
            )
        finally:
            if template_path.exists():
                template_path.unlink()
            load_template.cache_clear()

    def test_package_scoped_not_per_subject(self, tmp_dir: Path) -> None:
        """Package-scoped provisions do NOT create per-subject summaries."""
        from acef.package import Package as Pkg
        from acef.templates.models import EvaluationRule, Provision, Template
        from acef.templates.registry import load_template
        from acef.validation.engine import validate_bundle

        tid = "conformance-pkg-scope-dual"

        template = Template(
            template_id=tid,
            template_name="Conformance Package Scope Dual Test",
            version="1.0.0",
            provisions=[
                Provision(
                    provision_id="pkg-check-02",
                    evaluation_scope="package",
                    evaluation=[
                        EvaluationRule(
                            rule_id="pkg-check-02-rule",
                            rule="has_record_type",
                            params={"type": "governance_policy", "min_count": 1},
                            severity="fail",
                            message="Need governance policy",
                        ),
                    ],
                ),
                Provision(
                    provision_id="subj-check-02",
                    evaluation=[
                        EvaluationRule(
                            rule_id="subj-check-02-rule",
                            rule="has_record_type",
                            params={"type": "risk_register", "min_count": 1},
                            severity="fail",
                            message="Need risk register",
                        ),
                    ],
                ),
            ],
        )

        template_path = (
            Path(__file__).parent.parent.parent
            / "src" / "acef" / "templates" / f"{tid}.json"
        )
        template_path.write_text(template.model_dump_json(indent=2), encoding="utf-8")

        try:
            load_template.cache_clear()

            pkg = Pkg(producer={"name": "dual-scope", "version": "1.0.0"})
            sys1 = pkg.add_subject(
                "ai_system", name="System X",
                risk_classification="high-risk", modalities=["text"],
            )
            pkg.add_subject(
                "ai_system", name="System Y",
                risk_classification="high-risk", modalities=["text"],
            )
            pkg.add_profile(tid, provisions=["pkg-check-02", "subj-check-02"])

            pkg.record(
                "governance_policy",
                provisions=["pkg-check-02"],
                payload={"policy_type": "quality_management", "description": "QMS"},
            )
            pkg.record(
                "risk_register",
                provisions=["subj-check-02"],
                payload={"description": "Risk", "likelihood": "low", "severity": "low"},
                entity_refs={"subject_refs": [sys1.id]},
            )

            bundle_dir = tmp_dir / "dual_scope"
            pkg.export(str(bundle_dir))

            assessment = validate_bundle(
                bundle_dir,
                profiles=[tid],
                evaluation_instant="2026-01-15T00:00:00Z",
            )

            # Package-scoped: exactly 1 summary
            pkg_summaries = [
                s for s in assessment.provision_summary
                if s.provision_id == "pkg-check-02"
            ]
            assert len(pkg_summaries) == 1, (
                f"Package-scoped should have 1 summary, got {len(pkg_summaries)}"
            )

            # Per-subject: 2 summaries (one per subject)
            subj_summaries = [
                s for s in assessment.provision_summary
                if s.provision_id == "subj-check-02"
            ]
            assert len(subj_summaries) == 2, (
                f"Per-subject should have 2 summaries, got {len(subj_summaries)}"
            )
        finally:
            if template_path.exists():
                template_path.unlink()
            load_template.cache_clear()
