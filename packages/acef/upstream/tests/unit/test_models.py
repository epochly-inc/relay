"""Tests for ACEF models — metadata, subjects, entities, records, manifest, assessment."""

from __future__ import annotations

from acef.models.assessment import (
    AssessmentBundle,
    Assessor,
    EvidenceBundleRef,
    ProvisionSummary,
    RuleResult,
)
from acef.models.entities import Actor, Component, Dataset, DatasetSize, EntitiesBlock, Relationship
from acef.models.enums import (
    ActorRole,
    ComponentType,
    Confidentiality,
    DatasetModality,
    DatasetSourceType,
    LifecyclePhase,
    ObligationRole,
    ProvisionOutcome,
    RelationshipType,
    RiskClassification,
    RuleOutcome,
    RuleSeverity,
    SubjectType,
    TrustLevel,
)
from acef.models.manifest import AuditTrailEntry, Manifest, ProfileEntry, RecordFileEntry
from acef.models.metadata import PackageMetadata, ProducerInfo, RetentionPolicy, Versioning
from acef.models.records import AttachmentRef, Attestation, CollectorInfo, EntityRefs, RecordEnvelope
from acef.models.subjects import LifecycleEntry, Subject
from acef.models.urns import validate_urn


class TestProducerInfo:
    def test_creation(self):
        p = ProducerInfo(name="my-tool", version="1.0.0")
        assert p.name == "my-tool"
        assert p.version == "1.0.0"


class TestRetentionPolicy:
    def test_creation(self):
        rp = RetentionPolicy(min_retention_days=365)
        assert rp.min_retention_days == 365
        assert rp.personal_data_interplay is None

    def test_with_interplay(self):
        rp = RetentionPolicy(min_retention_days=365, personal_data_interplay="GDPR Article 17")
        assert rp.personal_data_interplay == "GDPR Article 17"


class TestPackageMetadata:
    def test_defaults(self):
        pm = PackageMetadata(producer=ProducerInfo(name="test", version="1.0"))
        assert validate_urn(pm.package_id)
        assert pm.timestamp.endswith("Z")
        assert pm.prior_package_ref is None
        assert pm.retention_policy is None

    def test_with_all_fields(self):
        pm = PackageMetadata(
            producer=ProducerInfo(name="test", version="1.0"),
            prior_package_ref="urn:acef:pkg:00000000-0000-0000-0000-000000000001",
            retention_policy=RetentionPolicy(min_retention_days=3650),
        )
        assert pm.prior_package_ref is not None
        assert pm.retention_policy.min_retention_days == 3650


class TestSubject:
    def test_creation_with_defaults(self):
        s = Subject(subject_type=SubjectType.AI_SYSTEM, name="Test System")
        assert validate_urn(s.subject_id)
        assert s.subject_type == SubjectType.AI_SYSTEM
        assert s.name == "Test System"
        assert s.version == "1.0.0"
        assert s.risk_classification == RiskClassification.MINIMAL_RISK
        assert s.lifecycle_phase == LifecyclePhase.DEVELOPMENT
        assert s.modalities == []
        assert s.lifecycle_timeline == []

    def test_id_property(self):
        s = Subject(subject_type=SubjectType.AI_MODEL, name="My Model")
        assert s.id == s.subject_id

    def test_with_lifecycle(self):
        s = Subject(
            subject_type=SubjectType.AI_SYSTEM,
            name="System",
            lifecycle_timeline=[
                LifecycleEntry(phase=LifecyclePhase.DESIGN, start_date="2025-01-01"),
                LifecycleEntry(phase=LifecyclePhase.DEVELOPMENT, start_date="2025-06-01"),
            ],
        )
        assert len(s.lifecycle_timeline) == 2
        assert s.lifecycle_timeline[0].phase == LifecyclePhase.DESIGN
        assert s.lifecycle_timeline[0].end_date is None


class TestComponent:
    def test_creation(self):
        c = Component(name="Retriever", type=ComponentType.RETRIEVER)
        assert validate_urn(c.component_id)
        assert c.name == "Retriever"
        assert c.type == ComponentType.RETRIEVER
        assert c.version == "1.0.0"
        assert c.subject_refs == []

    def test_id_property(self):
        c = Component(name="Guard", type=ComponentType.GUARDRAIL)
        assert c.id == c.component_id


class TestDataset:
    def test_creation(self):
        d = Dataset(name="Training Data")
        assert validate_urn(d.dataset_id)
        assert d.source_type == DatasetSourceType.LICENSED
        assert d.modality == DatasetModality.TEXT
        assert d.id == d.dataset_id

    def test_with_size(self):
        d = Dataset(name="Large Dataset", size=DatasetSize(records=1000000, size_gb=100.0))
        assert d.size.records == 1000000
        assert d.size.size_gb == 100.0


class TestActor:
    def test_creation(self):
        a = Actor(name="Jane Smith", role=ActorRole.PROVIDER, organization="Acme Corp")
        assert validate_urn(a.actor_id)
        assert a.name == "Jane Smith"
        assert a.role == ActorRole.PROVIDER
        assert a.organization == "Acme Corp"
        assert a.id == a.actor_id


class TestEntityRefs:
    def test_defaults(self):
        er = EntityRefs()
        assert er.subject_refs == []
        assert er.component_refs == []
        assert er.dataset_refs == []
        assert er.actor_refs == []

    def test_with_refs(self):
        er = EntityRefs(
            subject_refs=["urn:acef:sub:00000000-0000-0000-0000-000000000001"],
            component_refs=["urn:acef:cmp:00000000-0000-0000-0000-000000000002"],
        )
        assert len(er.subject_refs) == 1
        assert len(er.component_refs) == 1


class TestRecordEnvelope:
    def test_creation_defaults(self):
        r = RecordEnvelope(record_type="risk_register")
        assert validate_urn(r.record_id)
        assert r.record_type == "risk_register"
        assert r.confidentiality == Confidentiality.PUBLIC
        assert r.trust_level == TrustLevel.SELF_ATTESTED
        assert r.payload == {}
        assert r.id == r.record_id

    def test_to_jsonl_dict_excludes_none(self):
        r = RecordEnvelope(
            record_type="risk_register",
            payload={"description": "Test"},
            obligation_role=ObligationRole.PROVIDER,
        )
        d = r.to_jsonl_dict()
        assert d["record_type"] == "risk_register"
        assert d["payload"] == {"description": "Test"}
        assert d["obligation_role"] == "provider"
        # entity_refs always present
        assert "entity_refs" in d
        assert "subject_refs" in d["entity_refs"]
        # None fields excluded
        assert "lifecycle_phase" not in d or d.get("lifecycle_phase") is not None

    def test_to_jsonl_dict_entity_refs_always_present(self):
        r = RecordEnvelope(record_type="risk_register")
        d = r.to_jsonl_dict()
        assert "entity_refs" in d
        assert isinstance(d["entity_refs"]["subject_refs"], list)


class TestManifest:
    def test_to_dict(self):
        pm = PackageMetadata(producer=ProducerInfo(name="test", version="1.0"))
        m = Manifest(
            metadata=pm,
            subjects=[Subject(subject_type=SubjectType.AI_SYSTEM, name="Test")],
            record_files=[RecordFileEntry(path="records/risk_register.jsonl",
                                          record_type="risk_register", count=1)],
        )
        d = m.to_dict()
        assert "metadata" in d
        assert "subjects" in d
        assert len(d["subjects"]) == 1
        assert "record_files" in d
        assert d["record_files"][0]["path"] == "records/risk_register.jsonl"
        assert "versioning" in d

    def test_defaults(self):
        pm = PackageMetadata(producer=ProducerInfo(name="t", version="1"))
        m = Manifest(metadata=pm)
        assert m.subjects == []
        assert m.profiles == []
        assert m.record_files == []


class TestAssessmentBundle:
    def test_creation(self):
        ab = AssessmentBundle()
        assert validate_urn(ab.assessment_id)
        assert ab.timestamp.endswith("Z")
        assert ab.results == []
        assert ab.provision_summary == []
        assert ab.structural_errors == []

    def test_summary_no_provisions(self):
        ab = AssessmentBundle()
        assert ab.summary() == "No provisions evaluated"

    def test_summary_with_provisions(self):
        ab = AssessmentBundle(
            provision_summary=[
                ProvisionSummary(
                    provision_id="art-9", profile_id="eu-ai-act",
                    provision_outcome=ProvisionOutcome.SATISFIED,
                ),
                ProvisionSummary(
                    provision_id="art-10", profile_id="eu-ai-act",
                    provision_outcome=ProvisionOutcome.NOT_SATISFIED,
                ),
                ProvisionSummary(
                    provision_id="art-11", profile_id="eu-ai-act",
                    provision_outcome=ProvisionOutcome.GAP_ACKNOWLEDGED,
                ),
            ],
        )
        s = ab.summary()
        assert "eu-ai-act" in s
        assert "1/3 provisions passed" in s
        assert "1 gap acknowledged" in s

    def test_errors_method(self):
        ab = AssessmentBundle(
            structural_errors=[{"code": "ACEF-002", "message": "Schema fail"}],
            results=[
                RuleResult(
                    rule_id="r1", provision_id="p1", profile_id="pr1",
                    rule_severity=RuleSeverity.FAIL,
                    outcome=RuleOutcome.FAILED,
                    message="Missing evidence",
                ),
                RuleResult(
                    rule_id="r2", provision_id="p1", profile_id="pr1",
                    rule_severity=RuleSeverity.WARNING,
                    outcome=RuleOutcome.PASSED,
                ),
            ],
        )
        errors = ab.errors()
        assert len(errors) == 2  # 1 structural + 1 failed rule
        assert errors[0]["code"] == "ACEF-002"
        assert errors[1]["rule_id"] == "r1"
        assert errors[1]["severity"] == "fail"

    def test_to_dict(self):
        ab = AssessmentBundle()
        d = ab.to_dict()
        assert "assessment_id" in d
        assert "versioning" in d
        assert "results" in d
        assert "provision_summary" in d
