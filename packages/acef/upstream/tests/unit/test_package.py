"""Tests for acef.package — Package builder API."""

from __future__ import annotations

import pytest

from acef.errors import ACEFSchemaError
from acef.models.entities import Component, Dataset, Actor, Relationship
from acef.models.enums import (
    ActorRole,
    ComponentType,
    Confidentiality,
    DatasetModality,
    DatasetSourceType,
    LifecyclePhase,
    ObligationRole,
    RECORD_TYPES,
    RelationshipType,
    RiskClassification,
    SubjectType,
    TrustLevel,
)
from acef.models.manifest import Manifest, ProfileEntry
from acef.models.records import EntityRefs, RecordEnvelope
from acef.models.subjects import Subject
from acef.models.urns import validate_urn
from acef.package import Package


class TestPackageCreation:
    """Test Package initialization."""

    def test_default_producer(self):
        pkg = Package()
        assert pkg.metadata.producer.name == "acef-sdk"
        assert pkg.metadata.producer.version == "0.1.0"

    def test_dict_producer(self):
        pkg = Package(producer={"name": "my-tool", "version": "2.0"})
        assert pkg.metadata.producer.name == "my-tool"
        assert pkg.metadata.producer.version == "2.0"

    def test_package_has_valid_urn(self):
        pkg = Package()
        assert validate_urn(pkg.metadata.package_id)

    def test_package_has_timestamp(self):
        pkg = Package()
        assert pkg.metadata.timestamp.endswith("Z")

    def test_package_with_retention_policy(self):
        pkg = Package(retention_policy={"min_retention_days": 365})
        assert pkg.metadata.retention_policy is not None
        assert pkg.metadata.retention_policy.min_retention_days == 365

    def test_package_with_prior_ref(self):
        pkg = Package(prior_package_ref="urn:acef:pkg:00000000-0000-0000-0000-000000000001")
        assert pkg.metadata.prior_package_ref is not None

    def test_initial_audit_trail(self):
        pkg = Package()
        manifest = pkg.build_manifest()
        assert len(manifest.audit_trail) >= 1
        assert manifest.audit_trail[0].event_type.value == "created"


class TestAddSubject:
    """Test Package.add_subject."""

    def test_add_with_string_type(self):
        pkg = Package()
        sub = pkg.add_subject("ai_system", name="My System")
        assert isinstance(sub, Subject)
        assert sub.subject_type == SubjectType.AI_SYSTEM
        assert sub.name == "My System"
        assert validate_urn(sub.subject_id)

    def test_add_with_enum_type(self):
        pkg = Package()
        sub = pkg.add_subject(SubjectType.AI_MODEL, name="My Model")
        assert sub.subject_type == SubjectType.AI_MODEL

    def test_add_with_all_fields(self):
        pkg = Package()
        sub = pkg.add_subject(
            "ai_system",
            name="System",
            version="2.0",
            provider="Acme",
            risk_classification="high-risk",
            modalities=["text", "image"],
            lifecycle_phase="deployment",
            lifecycle_timeline=[
                {"phase": "design", "start_date": "2025-01-01"},
                {"phase": "development", "start_date": "2025-06-01"},
            ],
        )
        assert sub.version == "2.0"
        assert sub.provider == "Acme"
        assert sub.risk_classification == RiskClassification.HIGH_RISK
        assert sub.modalities == ["text", "image"]
        assert sub.lifecycle_phase == LifecyclePhase.DEPLOYMENT
        assert len(sub.lifecycle_timeline) == 2

    def test_add_multiple_subjects(self):
        pkg = Package()
        s1 = pkg.add_subject("ai_system", name="System A")
        s2 = pkg.add_subject("ai_model", name="Model B")
        assert len(pkg.subjects) == 2
        assert s1.id != s2.id


class TestAddComponent:
    """Test Package.add_component."""

    def test_add_component_string_type(self):
        pkg = Package()
        comp = pkg.add_component(name="Retriever", type="retriever")
        assert isinstance(comp, Component)
        assert comp.type == ComponentType.RETRIEVER
        assert validate_urn(comp.component_id)

    def test_add_component_enum_type(self):
        pkg = Package()
        comp = pkg.add_component(name="Guard", type=ComponentType.GUARDRAIL)
        assert comp.type == ComponentType.GUARDRAIL

    def test_component_with_subject_refs(self):
        pkg = Package()
        sub = pkg.add_subject("ai_system", name="System")
        comp = pkg.add_component(name="Model", type="model", subject_refs=[sub.id])
        assert sub.id in comp.subject_refs

    def test_component_in_entities(self):
        pkg = Package()
        pkg.add_component(name="API", type="api")
        assert len(pkg.entities.components) == 1


class TestAddDataset:
    """Test Package.add_dataset."""

    def test_add_dataset(self):
        pkg = Package()
        ds = pkg.add_dataset(name="Training Data")
        assert isinstance(ds, Dataset)
        assert ds.source_type == DatasetSourceType.LICENSED
        assert ds.modality == DatasetModality.TEXT
        assert validate_urn(ds.dataset_id)

    def test_dataset_with_options(self):
        pkg = Package()
        ds = pkg.add_dataset(
            name="Images",
            source_type="scraped",
            modality="image",
            size={"records": 50000, "size_gb": 10},
        )
        assert ds.source_type == DatasetSourceType.SCRAPED
        assert ds.modality == DatasetModality.IMAGE

    def test_dataset_in_entities(self):
        pkg = Package()
        pkg.add_dataset(name="Data")
        assert len(pkg.entities.datasets) == 1


class TestAddActor:
    """Test Package.add_actor."""

    def test_add_actor(self):
        pkg = Package()
        actor = pkg.add_actor(name="Jane", role="provider", organization="Acme")
        assert isinstance(actor, Actor)
        assert actor.role == ActorRole.PROVIDER
        assert actor.organization == "Acme"
        assert validate_urn(actor.actor_id)

    def test_actor_in_entities(self):
        pkg = Package()
        pkg.add_actor(name="Bob", role=ActorRole.AUDITOR)
        assert len(pkg.entities.actors) == 1


class TestAddRelationship:
    """Test Package.add_relationship."""

    def test_add_relationship_string_type(self):
        pkg = Package()
        s1 = pkg.add_subject("ai_system", name="System")
        s2 = pkg.add_subject("ai_model", name="Model")
        rel = pkg.add_relationship(s1.id, s2.id, "wraps")
        assert isinstance(rel, Relationship)
        assert rel.relationship_type == RelationshipType.WRAPS
        assert rel.source_ref == s1.id
        assert rel.target_ref == s2.id

    def test_add_relationship_enum_type(self):
        pkg = Package()
        s = pkg.add_subject("ai_system", name="Sys")
        m = pkg.add_subject("ai_model", name="Mod")
        rel = pkg.add_relationship(s.id, m.id, RelationshipType.CALLS)
        assert rel.relationship_type == RelationshipType.CALLS

    def test_relationship_in_entities(self):
        pkg = Package()
        s = pkg.add_subject("ai_system", name="S")
        m = pkg.add_subject("ai_model", name="M")
        pkg.add_relationship(s.id, m.id, "deploys")
        assert len(pkg.entities.relationships) == 1


class TestAddProfile:
    """Test Package.add_profile."""

    def test_add_profile(self):
        pkg = Package()
        profile = pkg.add_profile("eu-ai-act-2024", provisions=["article-9", "article-10"])
        assert isinstance(profile, ProfileEntry)
        assert profile.profile_id == "eu-ai-act-2024"
        assert "article-9" in profile.applicable_provisions

    def test_profiles_list(self):
        pkg = Package()
        pkg.add_profile("eu-ai-act")
        pkg.add_profile("nist-rmf")
        assert len(pkg.profiles) == 2


class TestRecord:
    """Test Package.record — evidence recording."""

    def test_record_basic(self):
        pkg = Package()
        rec = pkg.record("risk_register", payload={"description": "Risk 1"})
        assert isinstance(rec, RecordEnvelope)
        assert rec.record_type == "risk_register"
        assert rec.payload == {"description": "Risk 1"}
        assert validate_urn(rec.record_id)

    def test_record_all_fields(self):
        pkg = Package()
        sub = pkg.add_subject("ai_system", name="S")
        rec = pkg.record(
            "risk_register",
            provisions=["article-9"],
            payload={"description": "Test"},
            obligation_role="provider",
            entity_refs={"subject_refs": [sub.id]},
            confidentiality="regulator-only",
            trust_level="peer-reviewed",
            lifecycle_phase="deployment",
            collector={"name": "scanner", "version": "1.0"},
            timestamp="2025-01-01T00:00:00Z",
        )
        assert rec.provisions_addressed == ["article-9"]
        assert rec.obligation_role == ObligationRole.PROVIDER
        assert sub.id in rec.entity_refs.subject_refs
        assert rec.confidentiality == Confidentiality.REGULATOR_ONLY
        assert rec.trust_level == TrustLevel.PEER_REVIEWED
        assert rec.lifecycle_phase == LifecyclePhase.DEPLOYMENT
        assert rec.timestamp == "2025-01-01T00:00:00Z"

    def test_record_rejects_unknown_type(self):
        pkg = Package()
        with pytest.raises(ACEFSchemaError, match="Unknown record_type"):
            pkg.record("nonexistent_type", payload={})

    def test_record_accepts_extension_type(self):
        pkg = Package()
        rec = pkg.record("x-custom-record", payload={"custom": True})
        assert rec.record_type == "x-custom-record"

    def test_record_all_16_types(self):
        pkg = Package()
        for rt in RECORD_TYPES:
            rec = pkg.record(rt, payload={"test": True})
            assert rec.record_type == rt
        assert len(pkg.records) == 16

    def test_records_list_is_copy(self):
        pkg = Package()
        pkg.record("risk_register", payload={})
        records = pkg.records
        records.clear()
        assert len(pkg.records) == 1


class TestBuildManifest:
    """Test Package.build_manifest."""

    def test_generates_manifest(self, minimal_package: Package):
        manifest = minimal_package.build_manifest()
        assert isinstance(manifest, Manifest)
        assert manifest.metadata == minimal_package.metadata
        assert len(manifest.subjects) == 1
        assert len(manifest.record_files) == 1

    def test_record_files_by_type(self):
        pkg = Package()
        pkg.record("risk_register", payload={"a": 1})
        pkg.record("risk_register", payload={"b": 2})
        pkg.record("dataset_card", payload={"c": 3})
        manifest = pkg.build_manifest()
        rf_types = {rf.record_type for rf in manifest.record_files}
        assert rf_types == {"risk_register", "dataset_card"}

    def test_record_file_counts(self):
        pkg = Package()
        pkg.record("risk_register", payload={"a": 1})
        pkg.record("risk_register", payload={"b": 2})
        manifest = pkg.build_manifest()
        rr_entry = next(rf for rf in manifest.record_files if rf.record_type == "risk_register")
        assert rr_entry.count == 2

    def test_record_file_path_format(self):
        pkg = Package()
        pkg.record("risk_register", payload={})
        manifest = pkg.build_manifest()
        assert manifest.record_files[0].path == "records/risk_register.jsonl"


class TestPublicProperties:
    """Test public read-only properties added for M-R2-3, M-R2-4."""

    def test_versioning_property(self):
        pkg = Package()
        versioning = pkg.versioning
        assert versioning.core_version == "1.0.0"

    def test_audit_trail_property(self):
        pkg = Package()
        trail = pkg.audit_trail
        assert len(trail) >= 1
        assert trail[0].event_type.value == "created"

    def test_audit_trail_is_copy(self):
        pkg = Package()
        trail = pkg.audit_trail
        trail.clear()
        assert len(pkg.audit_trail) >= 1

    def test_is_signed_default_false(self):
        pkg = Package()
        assert pkg.is_signed is False

    def test_signing_key_default_none(self):
        pkg = Package()
        assert pkg.signing_key is None

    def test_sign_sets_properties(self):
        pkg = Package()
        pkg.sign("/path/to/key.pem")
        assert pkg.is_signed is True
        assert pkg.signing_key == "/path/to/key.pem"


class TestBackslashPathRejection:
    """Test M4 (Implementer R2): add_attachment rejects backslash paths."""

    def test_rejects_backslash_in_path(self):
        from acef.errors import ACEFError

        pkg = Package()
        with pytest.raises(ACEFError, match="Backslash"):
            pkg.add_attachment("folder\\file.txt", b"content")

    def test_rejects_backslash_after_prefix(self):
        from acef.errors import ACEFError

        pkg = Package()
        with pytest.raises(ACEFError, match="Backslash"):
            pkg.add_attachment("sub\\dir\\file.txt", b"content")
