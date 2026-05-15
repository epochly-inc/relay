"""Tests for acef.models.enums — all enum values, string conversions, RECORD_TYPES."""

from __future__ import annotations

from acef.models.enums import (
    ActorRole,
    AuditEventType,
    ComponentType,
    Confidentiality,
    DatasetModality,
    DatasetSourceType,
    EventType,
    LifecyclePhase,
    MANDATORY_RECORD_TYPES,
    ObligationRole,
    ProvisionOutcome,
    RECORD_TYPES,
    RelationshipType,
    RiskClassification,
    RuleOutcome,
    RuleSeverity,
    SubjectType,
    TrustLevel,
)


class TestSubjectType:
    def test_values(self):
        assert SubjectType.AI_SYSTEM.value == "ai_system"
        assert SubjectType.AI_MODEL.value == "ai_model"

    def test_string_conversion(self):
        assert SubjectType.AI_SYSTEM.value == "ai_system"
        assert SubjectType("ai_system") == SubjectType.AI_SYSTEM


class TestRiskClassification:
    def test_all_values(self):
        expected = {"high-risk", "gpai", "gpai-systemic", "limited-risk", "minimal-risk"}
        actual = {rc.value for rc in RiskClassification}
        assert actual == expected


class TestLifecyclePhase:
    def test_all_values(self):
        expected = {"design", "development", "testing", "deployment", "monitoring", "decommission"}
        actual = {lp.value for lp in LifecyclePhase}
        assert actual == expected


class TestComponentType:
    def test_all_values(self):
        expected = {"model", "retriever", "guardrail", "orchestrator", "tool", "database", "api"}
        actual = {ct.value for ct in ComponentType}
        assert actual == expected


class TestDatasetSourceType:
    def test_all_values(self):
        expected = {"licensed", "scraped", "public_domain", "synthetic", "user_generated"}
        actual = {dst.value for dst in DatasetSourceType}
        assert actual == expected


class TestDatasetModality:
    def test_all_values(self):
        expected = {"text", "image", "audio", "video", "tabular", "multimodal"}
        actual = {dm.value for dm in DatasetModality}
        assert actual == expected


class TestActorRole:
    def test_all_values(self):
        expected = {"provider", "deployer", "importer", "distributor",
                    "auditor", "regulator", "data_subject"}
        actual = {ar.value for ar in ActorRole}
        assert actual == expected


class TestRelationshipType:
    def test_all_values(self):
        expected = {"wraps", "calls", "fine_tunes", "deploys",
                    "trains_on", "evaluates_with", "oversees"}
        actual = {rt.value for rt in RelationshipType}
        assert actual == expected


class TestObligationRole:
    def test_all_values(self):
        expected = {"provider", "deployer", "importer", "distributor",
                    "authorised_representative", "notified_body", "platform"}
        actual = {o.value for o in ObligationRole}
        assert actual == expected


class TestConfidentiality:
    def test_all_values(self):
        expected = {"public", "redacted", "hash-committed", "regulator-only", "under-nda"}
        actual = {c.value for c in Confidentiality}
        assert actual == expected


class TestRuleOutcome:
    def test_all_values(self):
        expected = {"passed", "failed", "skipped", "error"}
        actual = {ro.value for ro in RuleOutcome}
        assert actual == expected


class TestProvisionOutcome:
    def test_all_values(self):
        expected = {"satisfied", "not-satisfied", "partially-satisfied",
                    "gap-acknowledged", "skipped", "not-assessed"}
        actual = {po.value for po in ProvisionOutcome}
        assert actual == expected


class TestRecordTypes:
    def test_is_frozenset(self):
        assert isinstance(RECORD_TYPES, frozenset)

    def test_contains_16_types(self):
        assert len(RECORD_TYPES) == 16

    def test_all_expected_types_present(self):
        expected = {
            "risk_register", "risk_treatment", "dataset_card",
            "data_provenance", "evaluation_report", "event_log",
            "human_oversight_action", "transparency_disclosure",
            "transparency_marking", "disclosure_labeling",
            "copyright_rights_reservation", "license_record",
            "incident_report", "governance_policy",
            "conformity_declaration", "evidence_gap",
        }
        assert RECORD_TYPES == expected

    def test_mandatory_subset(self):
        assert MANDATORY_RECORD_TYPES.issubset(RECORD_TYPES)
        expected_mandatory = {
            "risk_register", "risk_treatment", "dataset_card",
            "data_provenance", "evaluation_report",
        }
        assert MANDATORY_RECORD_TYPES == expected_mandatory


class TestEnumStringBehavior:
    """Verify that all str-based enums behave as strings."""

    def test_subject_type_is_str(self):
        assert isinstance(SubjectType.AI_SYSTEM, str)

    def test_rule_severity_values(self):
        assert RuleSeverity.FAIL.value == "fail"
        assert RuleSeverity.WARNING.value == "warning"
        assert RuleSeverity.INFO.value == "info"

    def test_audit_event_type_values(self):
        expected = {"created", "updated", "reviewed", "submitted", "certified"}
        actual = {aet.value for aet in AuditEventType}
        assert actual == expected

    def test_event_type_values(self):
        expected = {"inference", "training", "evaluation", "deployment",
                    "override", "error", "marking", "disclosure", "logging_spec"}
        actual = {et.value for et in EventType}
        assert actual == expected

    def test_trust_level_values(self):
        expected = {"self-attested", "peer-reviewed",
                    "independently-verified", "notified-body-certified"}
        actual = {tl.value for tl in TrustLevel}
        assert actual == expected
