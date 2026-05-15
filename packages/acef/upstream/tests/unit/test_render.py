"""Tests for acef.render — human-readable compliance report generation."""

from __future__ import annotations

from acef.models.assessment import (
    AssessmentBundle,
    Assessor,
    EvidenceBundleRef,
    ProvisionSummary,
    RuleResult,
)
from acef.models.enums import ProvisionOutcome, RuleOutcome, RuleSeverity
from acef.render import render_console, render_markdown


def _make_assessment(
    provision_summaries: list[ProvisionSummary] | None = None,
    results: list[RuleResult] | None = None,
    structural_errors: list[dict] | None = None,
    profiles_evaluated: list[str] | None = None,
) -> AssessmentBundle:
    """Build an AssessmentBundle for testing."""
    return AssessmentBundle(
        assessor=Assessor(name="acef-validator", version="1.0.0"),
        evidence_bundle_ref=EvidenceBundleRef(
            package_id="urn:acef:pkg:00000000-0000-0000-0000-000000000001",
            content_hash="sha256:abc123",
        ),
        evaluation_instant="2025-06-01T00:00:00Z",
        profiles_evaluated=profiles_evaluated or [],
        provision_summary=provision_summaries or [],
        results=results or [],
        structural_errors=structural_errors or [],
    )


class TestRenderMarkdown:
    """Test render_markdown produces correct Markdown output."""

    def test_renders_header_with_assessment_id(self) -> None:
        assessment = _make_assessment()
        md = render_markdown(assessment)
        assert "# ACEF Compliance Assessment Report" in md
        assert assessment.assessment_id in md

    def test_renders_timestamp_and_evaluator(self) -> None:
        assessment = _make_assessment()
        md = render_markdown(assessment)
        assert "2025-06-01T00:00:00Z" in md
        assert "acef-validator" in md

    def test_renders_evidence_bundle_ref(self) -> None:
        assessment = _make_assessment()
        md = render_markdown(assessment)
        assert "urn:acef:pkg:00000000-0000-0000-0000-000000000001" in md
        assert "sha256:abc123" in md

    def test_renders_profiles_evaluated(self) -> None:
        assessment = _make_assessment(profiles_evaluated=["eu-ai-act-2024", "nist-ai-rmf-1.0"])
        md = render_markdown(assessment)
        assert "## Profiles Evaluated" in md
        assert "eu-ai-act-2024" in md
        assert "nist-ai-rmf-1.0" in md

    def test_renders_executive_summary(self) -> None:
        assessment = _make_assessment()
        md = render_markdown(assessment)
        assert "## Executive Summary" in md
        assert "No provisions evaluated" in md

    def test_renders_provision_results_table(self) -> None:
        summaries = [
            ProvisionSummary(
                provision_id="article-9",
                profile_id="eu-ai-act",
                provision_outcome=ProvisionOutcome.SATISFIED,
                fail_count=0,
                warning_count=0,
                skipped_count=0,
            ),
            ProvisionSummary(
                provision_id="article-10",
                profile_id="eu-ai-act",
                provision_outcome=ProvisionOutcome.NOT_SATISFIED,
                fail_count=2,
                warning_count=1,
                skipped_count=0,
            ),
        ]
        assessment = _make_assessment(provision_summaries=summaries)
        md = render_markdown(assessment)
        assert "## Provision Results" in md
        assert "article-9" in md
        assert "[PASS]" in md
        assert "article-10" in md
        assert "[FAIL]" in md

    def test_renders_all_provision_outcome_symbols(self) -> None:
        outcomes = [
            (ProvisionOutcome.SATISFIED, "[PASS]"),
            (ProvisionOutcome.NOT_SATISFIED, "[FAIL]"),
            (ProvisionOutcome.PARTIALLY_SATISFIED, "[PARTIAL]"),
            (ProvisionOutcome.GAP_ACKNOWLEDGED, "[GAP]"),
            (ProvisionOutcome.SKIPPED, "[SKIP]"),
            (ProvisionOutcome.NOT_ASSESSED, "[N/A]"),
        ]
        for outcome, symbol in outcomes:
            summaries = [
                ProvisionSummary(
                    provision_id=f"prov-{outcome.value}",
                    profile_id="test",
                    provision_outcome=outcome,
                ),
            ]
            md = render_markdown(_make_assessment(provision_summaries=summaries))
            assert symbol in md, f"Expected {symbol} for {outcome.value}"

    def test_renders_rule_details(self) -> None:
        results = [
            RuleResult(
                rule_id="rule-1",
                provision_id="article-9",
                profile_id="eu-ai-act",
                rule_severity=RuleSeverity.FAIL,
                outcome=RuleOutcome.FAILED,
                message="Missing risk register",
                evidence_refs=["urn:acef:rec:00000000-0000-0000-0000-000000000001"],
            ),
        ]
        assessment = _make_assessment(results=results)
        md = render_markdown(assessment)
        assert "## Rule Details" in md
        assert "rule-1" in md
        assert "article-9" in md
        assert "[FAIL]" in md
        assert "Missing risk register" in md
        assert "urn:acef:rec:00000000-0000-0000-0000-000000000001" in md

    def test_renders_structural_errors(self) -> None:
        errors = [
            {"code": "ACEF-002", "message": "Schema violation", "severity": "fatal", "path": "/metadata"},
            {"code": "ACEF-010", "message": "Hash mismatch", "severity": "fatal"},
        ]
        assessment = _make_assessment(structural_errors=errors)
        md = render_markdown(assessment)
        assert "## Structural Errors" in md
        assert "ACEF-002" in md
        assert "Schema violation" in md
        assert "/metadata" in md
        assert "ACEF-010" in md

    def test_renders_footer(self) -> None:
        assessment = _make_assessment()
        md = render_markdown(assessment)
        assert "Generated by ACEF Reference Validator" in md

    def test_no_provision_results_section_when_empty(self) -> None:
        assessment = _make_assessment(provision_summaries=[])
        md = render_markdown(assessment)
        assert "## Provision Results" not in md

    def test_no_rule_details_section_when_empty(self) -> None:
        assessment = _make_assessment(results=[])
        md = render_markdown(assessment)
        assert "## Rule Details" not in md

    def test_no_structural_errors_section_when_empty(self) -> None:
        assessment = _make_assessment(structural_errors=[])
        md = render_markdown(assessment)
        assert "## Structural Errors" not in md

    def test_no_profiles_section_when_empty(self) -> None:
        assessment = _make_assessment(profiles_evaluated=[])
        md = render_markdown(assessment)
        assert "## Profiles Evaluated" not in md


class TestRenderConsole:
    """Test render_console produces correct console-formatted output."""

    def test_renders_header(self) -> None:
        assessment = _make_assessment()
        output = render_console(assessment)
        assert "ACEF Compliance Assessment" in output
        assert "=" * 40 in output

    def test_renders_bundle_id(self) -> None:
        assessment = _make_assessment()
        output = render_console(assessment)
        assert "urn:acef:pkg:00000000-0000-0000-0000-000000000001" in output

    def test_renders_evaluation_instant(self) -> None:
        assessment = _make_assessment()
        output = render_console(assessment)
        assert "2025-06-01T00:00:00Z" in output

    def test_renders_summary(self) -> None:
        assessment = _make_assessment()
        output = render_console(assessment)
        assert "No provisions evaluated" in output

    def test_renders_provision_list(self) -> None:
        summaries = [
            ProvisionSummary(
                provision_id="article-9",
                profile_id="eu-ai-act",
                provision_outcome=ProvisionOutcome.SATISFIED,
            ),
        ]
        assessment = _make_assessment(provision_summaries=summaries)
        output = render_console(assessment)
        assert "Provisions:" in output
        assert "[PASS]" in output
        assert "article-9" in output

    def test_renders_failed_rules(self) -> None:
        results = [
            RuleResult(
                rule_id="rule-1",
                provision_id="article-9",
                profile_id="eu-ai-act",
                rule_severity=RuleSeverity.FAIL,
                outcome=RuleOutcome.FAILED,
                message="Missing evidence",
            ),
            RuleResult(
                rule_id="rule-2",
                provision_id="article-9",
                profile_id="eu-ai-act",
                rule_severity=RuleSeverity.WARNING,
                outcome=RuleOutcome.PASSED,
            ),
        ]
        assessment = _make_assessment(results=results)
        output = render_console(assessment)
        assert "Failed Rules (1):" in output
        assert "rule-1" in output
        assert "Missing evidence" in output
        # rule-2 passed, should not appear in failed rules
        assert "rule-2" not in output

    def test_renders_structural_errors(self) -> None:
        errors = [{"code": "ACEF-010", "message": "Hash mismatch"}]
        assessment = _make_assessment(structural_errors=errors)
        output = render_console(assessment)
        assert "Structural Errors (1):" in output
        assert "ACEF-010" in output

    def test_structural_errors_truncated_at_10(self) -> None:
        errors = [{"code": f"ACEF-{i:03d}", "message": f"Error {i}"} for i in range(15)]
        assessment = _make_assessment(structural_errors=errors)
        output = render_console(assessment)
        assert "... and 5 more" in output

    def test_no_failed_rules_section_when_all_pass(self) -> None:
        results = [
            RuleResult(
                rule_id="rule-1",
                provision_id="article-9",
                profile_id="eu-ai-act",
                rule_severity=RuleSeverity.FAIL,
                outcome=RuleOutcome.PASSED,
            ),
        ]
        assessment = _make_assessment(results=results)
        output = render_console(assessment)
        assert "Failed Rules" not in output

    def test_failed_rule_with_no_message(self) -> None:
        results = [
            RuleResult(
                rule_id="rule-no-msg",
                provision_id="article-9",
                profile_id="eu-ai-act",
                rule_severity=RuleSeverity.FAIL,
                outcome=RuleOutcome.FAILED,
                message=None,
            ),
        ]
        assessment = _make_assessment(results=results)
        output = render_console(assessment)
        assert "No message" in output
