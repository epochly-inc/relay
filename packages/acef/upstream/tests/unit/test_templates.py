"""Unit tests for ACEF regulation mapping templates.

Validates all three templates (eu-ai-act-2024, nist-ai-rmf-1.0,
china-cac-labeling-2025) against:
- Pydantic model conformance
- JSON structural integrity
- Rule operator validity
- Rule ID uniqueness
- Required field presence
- Specification-mandated content
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from acef.templates.models import (
    EvaluationRule,
    Provision,
    RuleCondition,
    RuleScope,
    SubProvision,
    Template,
)
from acef.templates.registry import (
    compute_template_digest,
    get_template_provisions,
    list_templates,
    load_template,
)

VALID_OPERATORS = frozenset(
    {
        "has_record_type",
        "field_present",
        "field_value",
        "evidence_freshness",
        "attachment_exists",
        "entity_linked",
        "exists_where",
        "attachment_kind_exists",
        "bundle_signed",
        "record_attested",
    }
)

VALID_SEVERITIES = frozenset({"fail", "warning", "info"})

VALID_INSTRUMENT_TYPES = frozenset(
    {"law", "standard", "code_of_practice", "guidance", "parliamentary_report"}
)

VALID_LEGAL_FORCES = frozenset({"binding", "voluntary", "advisory"})

VALID_INSTRUMENT_STATUSES = frozenset({"final", "draft"})

TEMPLATE_IDS = ["eu-ai-act-2024", "nist-ai-rmf-1.0", "china-cac-labeling-2025"]


# ── Discovery Tests ──


class TestTemplateDiscovery:
    """Test template listing and discovery."""

    def test_list_templates_returns_all_three(self) -> None:
        available = list_templates()
        for tid in TEMPLATE_IDS:
            assert tid in available, f"Template {tid} not found in registry"

    def test_list_templates_returns_sorted(self) -> None:
        available = list_templates()
        assert available == sorted(available)


# ── Loading and Pydantic Validation Tests ──


class TestTemplateLoading:
    """Test loading and Pydantic deserialization."""

    @pytest.mark.parametrize("template_id", TEMPLATE_IDS)
    def test_load_template_succeeds(self, template_id: str) -> None:
        template = load_template(template_id)
        assert isinstance(template, Template)
        assert template.template_id == template_id

    @pytest.mark.parametrize("template_id", TEMPLATE_IDS)
    def test_template_has_provisions(self, template_id: str) -> None:
        template = load_template(template_id)
        assert len(template.provisions) > 0

    @pytest.mark.parametrize("template_id", TEMPLATE_IDS)
    def test_template_has_test_vectors(self, template_id: str) -> None:
        template = load_template(template_id)
        assert len(template.test_vectors) > 0

    @pytest.mark.parametrize("template_id", TEMPLATE_IDS)
    def test_get_template_provisions(self, template_id: str) -> None:
        provision_ids = get_template_provisions(template_id)
        assert len(provision_ids) > 0
        template = load_template(template_id)
        expected = [p.provision_id for p in template.provisions]
        assert provision_ids == expected

    @pytest.mark.parametrize("template_id", TEMPLATE_IDS)
    def test_compute_template_digest(self, template_id: str) -> None:
        digest = compute_template_digest(template_id)
        assert digest.startswith("sha256:")
        hex_part = digest.split(":")[1]
        assert len(hex_part) == 64
        # Digest is deterministic
        assert compute_template_digest(template_id) == digest

    def test_load_nonexistent_template_raises(self) -> None:
        from acef.errors import ACEFProfileError

        with pytest.raises(ACEFProfileError) as exc_info:
            load_template("nonexistent-template-999")
        assert exc_info.value.code == "ACEF-030"


# ── Structural Validation Tests ──


class TestTemplateStructure:
    """Test structural requirements per spec Section 3.4."""

    @pytest.mark.parametrize("template_id", TEMPLATE_IDS)
    def test_template_fields_present(self, template_id: str) -> None:
        template = load_template(template_id)
        assert template.template_id
        assert template.template_name
        assert template.version
        assert template.jurisdiction
        assert template.source_legislation
        assert template.instrument_type in VALID_INSTRUMENT_TYPES
        assert template.legal_force in VALID_LEGAL_FORCES
        assert template.instrument_status in VALID_INSTRUMENT_STATUSES

    @pytest.mark.parametrize("template_id", TEMPLATE_IDS)
    def test_applicable_system_types_nonempty(self, template_id: str) -> None:
        template = load_template(template_id)
        assert len(template.applicable_system_types) > 0

    @pytest.mark.parametrize("template_id", TEMPLATE_IDS)
    def test_all_provisions_have_required_fields(self, template_id: str) -> None:
        template = load_template(template_id)
        for prov in template.provisions:
            assert prov.provision_id, "Provision must have provision_id"
            assert prov.provision_name, "Provision must have provision_name"
            assert prov.normative_text_ref, "Provision must have normative_text_ref"
            assert prov.description, "Provision must have description"

    @pytest.mark.parametrize("template_id", TEMPLATE_IDS)
    def test_all_provisions_have_evaluation_rules(self, template_id: str) -> None:
        template = load_template(template_id)
        for prov in template.provisions:
            assert len(prov.evaluation) > 0, (
                f"Provision {prov.provision_id} has no evaluation rules"
            )

    @pytest.mark.parametrize("template_id", TEMPLATE_IDS)
    def test_provision_ids_unique(self, template_id: str) -> None:
        template = load_template(template_id)
        ids = [p.provision_id for p in template.provisions]
        assert len(ids) == len(set(ids)), f"Duplicate provision IDs: {ids}"


# ── Rule Validation Tests ──


class TestRuleValidation:
    """Test that all evaluation rules conform to DSL spec Section 3.5."""

    @pytest.mark.parametrize("template_id", TEMPLATE_IDS)
    def test_all_rule_operators_valid(self, template_id: str) -> None:
        template = load_template(template_id)
        for prov in template.provisions:
            for rule in prov.evaluation:
                assert rule.rule in VALID_OPERATORS, (
                    f"Invalid operator '{rule.rule}' in rule '{rule.rule_id}' "
                    f"of provision '{prov.provision_id}'"
                )

    @pytest.mark.parametrize("template_id", TEMPLATE_IDS)
    def test_all_rule_severities_valid(self, template_id: str) -> None:
        template = load_template(template_id)
        for prov in template.provisions:
            for rule in prov.evaluation:
                assert rule.severity in VALID_SEVERITIES, (
                    f"Invalid severity '{rule.severity}' in rule '{rule.rule_id}'"
                )

    @pytest.mark.parametrize("template_id", TEMPLATE_IDS)
    def test_all_rules_have_messages(self, template_id: str) -> None:
        template = load_template(template_id)
        for prov in template.provisions:
            for rule in prov.evaluation:
                assert rule.message, (
                    f"Rule '{rule.rule_id}' in provision "
                    f"'{prov.provision_id}' has empty message"
                )

    @pytest.mark.parametrize("template_id", TEMPLATE_IDS)
    def test_rule_ids_globally_unique(self, template_id: str) -> None:
        template = load_template(template_id)
        all_ids: list[str] = []
        for prov in template.provisions:
            for rule in prov.evaluation:
                all_ids.append(rule.rule_id)
        assert len(all_ids) == len(set(all_ids)), (
            f"Duplicate rule IDs in {template_id}: "
            f"{[x for x in all_ids if all_ids.count(x) > 1]}"
        )

    @pytest.mark.parametrize("template_id", TEMPLATE_IDS)
    def test_has_record_type_rules_have_type_param(self, template_id: str) -> None:
        template = load_template(template_id)
        for prov in template.provisions:
            for rule in prov.evaluation:
                if rule.rule == "has_record_type":
                    assert "type" in rule.params, (
                        f"has_record_type rule '{rule.rule_id}' missing 'type' param"
                    )
                    assert "min_count" in rule.params, (
                        f"has_record_type rule '{rule.rule_id}' missing 'min_count' param"
                    )

    @pytest.mark.parametrize("template_id", TEMPLATE_IDS)
    def test_field_present_rules_have_required_params(
        self, template_id: str
    ) -> None:
        template = load_template(template_id)
        for prov in template.provisions:
            for rule in prov.evaluation:
                if rule.rule == "field_present":
                    assert "record_type" in rule.params, (
                        f"field_present rule '{rule.rule_id}' missing 'record_type'"
                    )
                    assert "field" in rule.params, (
                        f"field_present rule '{rule.rule_id}' missing 'field'"
                    )
                    # Spec mandates JSON Pointer format (starts with /)
                    assert rule.params["field"].startswith("/"), (
                        f"field_present rule '{rule.rule_id}' field "
                        f"'{rule.params['field']}' must use JSON Pointer (RFC 6901)"
                    )

    @pytest.mark.parametrize("template_id", TEMPLATE_IDS)
    def test_field_value_rules_have_required_params(
        self, template_id: str
    ) -> None:
        template = load_template(template_id)
        valid_ops = {"eq", "ne", "gt", "gte", "lt", "lte", "in", "regex"}
        for prov in template.provisions:
            for rule in prov.evaluation:
                if rule.rule == "field_value":
                    assert "record_type" in rule.params
                    assert "field" in rule.params
                    assert "op" in rule.params
                    assert "value" in rule.params
                    assert rule.params["op"] in valid_ops, (
                        f"field_value rule '{rule.rule_id}' uses invalid op "
                        f"'{rule.params['op']}'"
                    )
                    assert rule.params["field"].startswith("/")

    @pytest.mark.parametrize("template_id", TEMPLATE_IDS)
    def test_evidence_freshness_rules_have_required_params(
        self, template_id: str
    ) -> None:
        template = load_template(template_id)
        valid_refs = {"validation_time", "package_time", "obligation_effective_date"}
        for prov in template.provisions:
            for rule in prov.evaluation:
                if rule.rule == "evidence_freshness":
                    assert "max_days" in rule.params
                    assert isinstance(rule.params["max_days"], int)
                    assert rule.params["max_days"] > 0
                    assert "reference_date" in rule.params
                    assert rule.params["reference_date"] in valid_refs

    @pytest.mark.parametrize("template_id", TEMPLATE_IDS)
    def test_exists_where_rules_have_required_params(
        self, template_id: str
    ) -> None:
        template = load_template(template_id)
        for prov in template.provisions:
            for rule in prov.evaluation:
                if rule.rule == "exists_where":
                    assert "record_type" in rule.params
                    assert "field" in rule.params
                    assert "op" in rule.params
                    assert "value" in rule.params
                    assert "min_count" in rule.params
                    assert rule.params["field"].startswith("/")

    @pytest.mark.parametrize("template_id", TEMPLATE_IDS)
    def test_entity_linked_rules_have_required_params(
        self, template_id: str
    ) -> None:
        template = load_template(template_id)
        valid_entity_types = {"subject", "component", "dataset", "actor"}
        for prov in template.provisions:
            for rule in prov.evaluation:
                if rule.rule == "entity_linked":
                    assert "record_type" in rule.params
                    assert "entity_type" in rule.params
                    assert rule.params["entity_type"] in valid_entity_types

    @pytest.mark.parametrize("template_id", TEMPLATE_IDS)
    def test_attachment_kind_exists_rules_have_required_params(
        self, template_id: str
    ) -> None:
        template = load_template(template_id)
        for prov in template.provisions:
            for rule in prov.evaluation:
                if rule.rule == "attachment_kind_exists":
                    assert "record_type" in rule.params
                    assert "attachment_type" in rule.params
                    assert "min_count" in rule.params

    @pytest.mark.parametrize("template_id", TEMPLATE_IDS)
    def test_attachment_exists_rules_have_required_params(
        self, template_id: str
    ) -> None:
        template = load_template(template_id)
        for prov in template.provisions:
            for rule in prov.evaluation:
                if rule.rule == "attachment_exists":
                    assert "record_type" in rule.params


# ── EU AI Act Specific Tests ──


class TestEUAIActTemplate:
    """Tests specific to eu-ai-act-2024 template content."""

    @pytest.fixture()
    def template(self) -> Template:
        return load_template("eu-ai-act-2024")

    def test_template_metadata(self, template: Template) -> None:
        assert template.template_id == "eu-ai-act-2024"
        assert template.template_name == "EU Artificial Intelligence Act"
        assert template.jurisdiction == "EU"
        assert template.instrument_type == "law"
        assert template.legal_force == "binding"
        assert template.instrument_status == "final"
        assert template.default_effective_date == "2026-08-02"
        assert template.superseded_by is None

    def test_applicable_system_types(self, template: Template) -> None:
        expected = {"high-risk", "gpai", "gpai-systemic", "limited-risk"}
        assert set(template.applicable_system_types) == expected

    def test_has_article_9_provision(self, template: Template) -> None:
        prov = self._find_provision(template, "article-9")
        assert prov.provision_name == "Risk Management System"
        assert prov.effective_date == "2026-08-02"
        assert "high-risk" in prov.applicable_to
        assert "risk_register" in prov.required_evidence_types
        assert "risk_treatment" in prov.required_evidence_types
        assert prov.evidence_freshness_max_days == 365
        assert prov.retention_years == 10

    def test_article_9_sub_provisions(self, template: Template) -> None:
        prov = self._find_provision(template, "article-9")
        sub_ids = [s.provision_id for s in prov.sub_provisions]
        assert "article-9.1" in sub_ids
        assert "article-9.2.a" in sub_ids

    def test_article_9_management_review_rule(self, template: Template) -> None:
        prov = self._find_provision(template, "article-9")
        rule = self._find_rule(prov, "art9-management-review")
        assert rule.rule == "exists_where"
        assert rule.params["record_type"] == "risk_register"
        assert rule.params["field"] == "/payload/review_type"
        assert rule.params["value"] == "management_review"

    def test_article_9_post_market_monitoring_rule(self, template: Template) -> None:
        prov = self._find_provision(template, "article-9")
        rule = self._find_rule(prov, "art9-post-market-monitoring")
        assert rule.rule == "attachment_kind_exists"
        assert rule.params["attachment_type"] == "post_market_monitoring_plan"

    def test_article_9_freshness_rule(self, template: Template) -> None:
        prov = self._find_provision(template, "article-9")
        rule = self._find_rule(prov, "art9-freshness")
        assert rule.rule == "evidence_freshness"
        assert rule.params["max_days"] == 365

    def test_has_article_10_provision(self, template: Template) -> None:
        prov = self._find_provision(template, "article-10")
        assert "data_provenance" in prov.required_evidence_types
        assert "dataset_card" in prov.required_evidence_types

    def test_has_article_11_provision(self, template: Template) -> None:
        prov = self._find_provision(template, "article-11")
        assert "evaluation_report" in prov.required_evidence_types

    def test_has_article_12_provision(self, template: Template) -> None:
        prov = self._find_provision(template, "article-12")
        assert "event_log" in prov.required_evidence_types

    def test_article_12_field_checks(self, template: Template) -> None:
        prov = self._find_provision(template, "article-12")
        rule_ids = [r.rule_id for r in prov.evaluation]
        assert "art12-event-type-present" in rule_ids
        assert "art12-correlation-id-present" in rule_ids

    def test_has_article_13_provision(self, template: Template) -> None:
        prov = self._find_provision(template, "article-13")
        assert "transparency_disclosure" in prov.required_evidence_types

    def test_has_article_14_provision(self, template: Template) -> None:
        prov = self._find_provision(template, "article-14")
        assert "human_oversight_action" in prov.required_evidence_types

    def test_has_article_15_provision(self, template: Template) -> None:
        prov = self._find_provision(template, "article-15")
        assert "evaluation_report" in prov.required_evidence_types

    def test_has_article_17_provision(self, template: Template) -> None:
        prov = self._find_provision(template, "article-17")
        assert "governance_policy" in prov.required_evidence_types

    def test_has_article_50_2_provision(self, template: Template) -> None:
        prov = self._find_provision(template, "article-50.2")
        assert "transparency_marking" in prov.required_evidence_types
        rule_ids = [r.rule_id for r in prov.evaluation]
        assert "art50-marking-scheme-id" in rule_ids
        assert "art50-modality" in rule_ids

    def test_article_50_2_applies_broadly(self, template: Template) -> None:
        prov = self._find_provision(template, "article-50.2")
        expected_types = {"high-risk", "gpai", "gpai-systemic", "limited-risk"}
        assert set(prov.applicable_to) == expected_types

    def test_has_article_53_provision(self, template: Template) -> None:
        prov = self._find_provision(template, "article-53")
        assert "data_provenance" in prov.required_evidence_types
        assert "copyright_rights_reservation" in prov.required_evidence_types
        assert set(prov.applicable_to) == {"gpai", "gpai-systemic"}

    def test_article_53_gpai_effective_date(self, template: Template) -> None:
        prov = self._find_provision(template, "article-53")
        assert prov.effective_date == "2025-08-02"

    def test_article_53_condition_on_rules(self, template: Template) -> None:
        prov = self._find_provision(template, "article-53")
        for rule in prov.evaluation:
            if rule.condition is not None:
                assert "gpai" in rule.condition.if_system_type or (
                    "gpai-systemic" in rule.condition.if_system_type
                )

    def test_total_provision_count(self, template: Template) -> None:
        assert len(template.provisions) == 10

    def test_total_test_vectors(self, template: Template) -> None:
        assert len(template.test_vectors) == 10

    @staticmethod
    def _find_provision(template: Template, provision_id: str) -> Provision:
        for p in template.provisions:
            if p.provision_id == provision_id:
                return p
        raise AssertionError(f"Provision {provision_id} not found")

    @staticmethod
    def _find_rule(provision: Provision, rule_id: str) -> EvaluationRule:
        for r in provision.evaluation:
            if r.rule_id == rule_id:
                return r
        raise AssertionError(f"Rule {rule_id} not found in {provision.provision_id}")


# ── NIST AI RMF Specific Tests ──


class TestNISTAIRMFTemplate:
    """Tests specific to nist-ai-rmf-1.0 template content."""

    @pytest.fixture()
    def template(self) -> Template:
        return load_template("nist-ai-rmf-1.0")

    def test_template_metadata(self, template: Template) -> None:
        assert template.template_id == "nist-ai-rmf-1.0"
        assert template.jurisdiction == "US"
        assert template.instrument_type == "standard"
        assert template.legal_force == "voluntary"
        assert template.instrument_status == "final"
        assert template.default_effective_date is None

    def test_has_govern_1(self, template: Template) -> None:
        prov = self._find_provision(template, "govern-1")
        assert "governance_policy" in prov.required_evidence_types

    def test_has_map_1(self, template: Template) -> None:
        prov = self._find_provision(template, "map-1")
        assert "risk_register" in prov.required_evidence_types

    def test_has_map_2(self, template: Template) -> None:
        prov = self._find_provision(template, "map-2")
        assert "dataset_card" in prov.required_evidence_types
        assert "data_provenance" in prov.required_evidence_types

    def test_has_measure_1(self, template: Template) -> None:
        prov = self._find_provision(template, "measure-1")
        assert "evaluation_report" in prov.required_evidence_types

    def test_has_manage_1(self, template: Template) -> None:
        prov = self._find_provision(template, "manage-1")
        assert "risk_treatment" in prov.required_evidence_types

    def test_has_manage_4(self, template: Template) -> None:
        prov = self._find_provision(template, "manage-4")
        assert "incident_report" in prov.required_evidence_types

    def test_total_provision_count(self, template: Template) -> None:
        assert len(template.provisions) == 6

    def test_no_effective_dates(self, template: Template) -> None:
        for prov in template.provisions:
            assert prov.effective_date is None, (
                f"NIST provisions should not have effective_date "
                f"(voluntary standard), but {prov.provision_id} has "
                f"{prov.effective_date}"
            )

    def test_applicable_to_empty_or_broad(self, template: Template) -> None:
        for prov in template.provisions:
            assert prov.applicable_to == [], (
                f"NIST provisions should have empty applicable_to "
                f"(applies to all system types), but {prov.provision_id} "
                f"has {prov.applicable_to}"
            )

    def test_govern_functions_covered(self, template: Template) -> None:
        provision_ids = [p.provision_id for p in template.provisions]
        assert "govern-1" in provision_ids

    def test_map_functions_covered(self, template: Template) -> None:
        provision_ids = [p.provision_id for p in template.provisions]
        assert "map-1" in provision_ids
        assert "map-2" in provision_ids

    def test_measure_functions_covered(self, template: Template) -> None:
        provision_ids = [p.provision_id for p in template.provisions]
        assert "measure-1" in provision_ids

    def test_manage_functions_covered(self, template: Template) -> None:
        provision_ids = [p.provision_id for p in template.provisions]
        assert "manage-1" in provision_ids
        assert "manage-4" in provision_ids

    @staticmethod
    def _find_provision(template: Template, provision_id: str) -> Provision:
        for p in template.provisions:
            if p.provision_id == provision_id:
                return p
        raise AssertionError(f"Provision {provision_id} not found")


# ── China CAC Specific Tests ──


class TestChinaCACTemplate:
    """Tests specific to china-cac-labeling-2025 template content."""

    @pytest.fixture()
    def template(self) -> Template:
        return load_template("china-cac-labeling-2025")

    def test_template_metadata(self, template: Template) -> None:
        assert template.template_id == "china-cac-labeling-2025"
        assert template.jurisdiction == "CN"
        assert template.instrument_type == "law"
        assert template.legal_force == "binding"
        assert template.instrument_status == "final"
        assert template.default_effective_date == "2025-09-01"

    def test_has_explicit_label_provision(self, template: Template) -> None:
        prov = self._find_provision(template, "cac-explicit-label")
        assert "disclosure_labeling" in prov.required_evidence_types

    def test_explicit_label_presentation_check(self, template: Template) -> None:
        prov = self._find_provision(template, "cac-explicit-label")
        rule = self._find_rule(prov, "cac-explicit-presentation")
        assert rule.rule == "field_present"
        assert rule.params["field"] == "/payload/presentation"
        assert rule.severity == "fail"

    def test_has_implicit_metadata_provision(self, template: Template) -> None:
        prov = self._find_provision(template, "cac-implicit-metadata")
        assert "transparency_marking" in prov.required_evidence_types

    def test_implicit_marking_scheme_id_check(self, template: Template) -> None:
        prov = self._find_provision(template, "cac-implicit-metadata")
        rule = self._find_rule(prov, "cac-implicit-marking-scheme-id")
        assert rule.rule == "field_present"
        assert rule.params["field"] == "/payload/marking_scheme_id"

    def test_implicit_jurisdiction_check(self, template: Template) -> None:
        prov = self._find_provision(template, "cac-implicit-metadata")
        rule = self._find_rule(prov, "cac-implicit-jurisdiction")
        assert rule.rule == "field_value"
        assert rule.params["field"] == "/payload/jurisdiction"
        assert rule.params["op"] == "eq"
        assert rule.params["value"] == "CN"
        assert rule.severity == "fail"

    def test_has_watermark_provision(self, template: Template) -> None:
        prov = self._find_provision(template, "cac-watermark")
        rule = self._find_rule(prov, "cac-watermark-applied")
        assert rule.rule == "field_value"
        assert rule.params["field"] == "/payload/watermark_applied"
        assert rule.params["value"] is True

    def test_watermark_is_encouraged_not_mandatory(self, template: Template) -> None:
        prov = self._find_provision(template, "cac-watermark")
        rule = self._find_rule(prov, "cac-watermark-applied")
        assert rule.severity == "warning"

    def test_has_log_retention_provision(self, template: Template) -> None:
        prov = self._find_provision(template, "cac-log-retention")
        assert "event_log" in prov.required_evidence_types
        assert prov.evidence_freshness_max_days == 180

    def test_log_retention_freshness_rule(self, template: Template) -> None:
        prov = self._find_provision(template, "cac-log-retention")
        rule = self._find_rule(prov, "cac-log-freshness")
        assert rule.rule == "evidence_freshness"
        assert rule.params["max_days"] == 180
        assert rule.severity == "fail"

    def test_total_provision_count(self, template: Template) -> None:
        assert len(template.provisions) == 4

    def test_all_provisions_effective_sept_2025(self, template: Template) -> None:
        for prov in template.provisions:
            assert prov.effective_date == "2025-09-01"

    def test_total_test_vectors(self, template: Template) -> None:
        assert len(template.test_vectors) == 3

    @staticmethod
    def _find_provision(template: Template, provision_id: str) -> Provision:
        for p in template.provisions:
            if p.provision_id == provision_id:
                return p
        raise AssertionError(f"Provision {provision_id} not found")

    @staticmethod
    def _find_rule(provision: Provision, rule_id: str) -> EvaluationRule:
        for r in provision.evaluation:
            if r.rule_id == rule_id:
                return r
        raise AssertionError(f"Rule {rule_id} not found in {provision.provision_id}")


# ── Round-Trip Serialization Tests ──


class TestTemplateRoundTrip:
    """Test that templates survive Pydantic round-trip serialization."""

    @pytest.mark.parametrize("template_id", TEMPLATE_IDS)
    def test_round_trip_preserves_data(self, template_id: str) -> None:
        template = load_template(template_id)
        serialized = template.model_dump(mode="json")
        restored = Template.model_validate(serialized)

        assert restored.template_id == template.template_id
        assert restored.template_name == template.template_name
        assert restored.version == template.version
        assert restored.jurisdiction == template.jurisdiction
        assert len(restored.provisions) == len(template.provisions)

        for orig, rest in zip(template.provisions, restored.provisions):
            assert orig.provision_id == rest.provision_id
            assert len(orig.evaluation) == len(rest.evaluation)
            for orig_rule, rest_rule in zip(orig.evaluation, rest.evaluation):
                assert orig_rule.rule_id == rest_rule.rule_id
                assert orig_rule.rule == rest_rule.rule
                assert orig_rule.params == rest_rule.params
                assert orig_rule.severity == rest_rule.severity

    @pytest.mark.parametrize("template_id", TEMPLATE_IDS)
    def test_json_file_matches_model(self, template_id: str) -> None:
        template_dir = Path(__file__).parent.parent.parent / "src" / "acef" / "templates"
        with open(template_dir / f"{template_id}.json") as f:
            raw = json.load(f)

        template = load_template(template_id)
        model_dump = template.model_dump(mode="json")

        assert raw["template_id"] == model_dump["template_id"]
        assert len(raw["provisions"]) == len(model_dump["provisions"])
