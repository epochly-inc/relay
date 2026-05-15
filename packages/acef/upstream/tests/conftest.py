"""ACEF test fixtures and shared configuration."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

import pytest

from acef.models.entities import Actor, Component, Dataset, EntitiesBlock
from acef.models.enums import (
    ActorRole,
    ComponentType,
    DatasetModality,
    DatasetSourceType,
    LifecyclePhase,
    ObligationRole,
    RiskClassification,
    SubjectType,
)
from acef.models.records import EntityRefs, RecordEnvelope
from acef.models.subjects import Subject
from acef.package import Package


@pytest.fixture
def tmp_dir():
    """Provide a temporary directory for test output."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def minimal_package() -> Package:
    """Create a minimal valid package with one subject and one record."""
    pkg = Package(producer={"name": "test-tool", "version": "1.0.0"})
    system = pkg.add_subject(
        "ai_system",
        name="Test System",
        risk_classification="high-risk",
        modalities=["text"],
        lifecycle_phase="deployment",
    )
    pkg.record(
        "risk_register",
        provisions=["article-9"],
        payload={"description": "Test risk", "likelihood": "medium", "severity": "high"},
        obligation_role="provider",
        entity_refs={"subject_refs": [system.id]},
    )
    return pkg


@pytest.fixture
def full_package() -> Package:
    """Create a fully-featured package with multiple subjects, entities, and records."""
    pkg = Package(
        producer={"name": "acme-tool", "version": "2.0.0"},
        retention_policy={"min_retention_days": 3650},
    )

    # Subjects
    system = pkg.add_subject(
        "ai_system",
        name="Acme RAG Assistant",
        version="2.1.0",
        provider="Acme AI Corp",
        risk_classification="high-risk",
        modalities=["text"],
        lifecycle_phase="deployment",
    )
    model = pkg.add_subject(
        "ai_model",
        name="Acme LLM",
        version="3.0.0",
        provider="Acme AI Corp",
        risk_classification="gpai",
        modalities=["text"],
    )

    # Components
    retriever = pkg.add_component(
        name="Vector Retriever",
        type="retriever",
        version="3.1.0",
        subject_refs=[system.id],
    )
    guardrail = pkg.add_component(
        name="Safety Filter",
        type="guardrail",
        version="1.4.0",
        subject_refs=[system.id],
    )

    # Datasets
    training_data = pkg.add_dataset(
        name="Training Data",
        source_type="licensed",
        modality="text",
        size={"records": 1000000, "size_gb": 100},
        subject_refs=[model.id],
    )

    # Actors
    actor = pkg.add_actor(name="Jane Smith", role="provider", organization="Acme AI Corp")

    # Relationships
    pkg.add_relationship(system.id, model.id, "wraps")
    pkg.add_relationship(system.id, retriever.id, "calls")
    pkg.add_relationship(model.id, training_data.id, "trains_on")

    # Profiles
    pkg.add_profile("eu-ai-act-2024", provisions=["article-9", "article-10", "article-50.2"])

    # Records
    pkg.record(
        "risk_register",
        provisions=["article-9"],
        payload={"description": "Risk 1", "likelihood": "high", "severity": "high"},
        obligation_role="provider",
        entity_refs={"subject_refs": [system.id]},
    )
    pkg.record(
        "risk_treatment",
        provisions=["article-9"],
        payload={"treatment_type": "mitigate", "description": "Treatment 1"},
        obligation_role="provider",
        entity_refs={"subject_refs": [system.id]},
    )
    pkg.record(
        "data_provenance",
        provisions=["article-10"],
        payload={"acquisition_method": "licensed", "acquisition_date": "2025-09-01"},
        obligation_role="provider",
        entity_refs={"dataset_refs": [training_data.id]},
    )
    pkg.record(
        "transparency_marking",
        provisions=["article-50.2"],
        payload={
            "modality": "text",
            "marking_scheme_id": "c2pa-content-credentials",
            "scheme_version": "2.3",
            "metadata_container": "xmp/c2pa-manifest-store",
            "watermark_applied": True,
        },
        obligation_role="provider",
        entity_refs={"subject_refs": [system.id]},
    )
    pkg.record(
        "dataset_card",
        provisions=["article-10"],
        payload={"name": "Training Data", "description": "Licensed dataset"},
        obligation_role="provider",
        entity_refs={"dataset_refs": [training_data.id]},
    )
    pkg.record(
        "evaluation_report",
        provisions=["article-11"],
        payload={"methodology": "benchmark", "results": {"accuracy": 0.95}},
        obligation_role="provider",
        entity_refs={"subject_refs": [system.id]},
    )

    return pkg


@pytest.fixture
def sample_record() -> RecordEnvelope:
    """Create a sample RecordEnvelope."""
    return RecordEnvelope(
        record_type="risk_register",
        provisions_addressed=["article-9"],
        payload={"description": "Test risk"},
        obligation_role=ObligationRole.PROVIDER,
        entity_refs=EntityRefs(subject_refs=["urn:acef:sub:00000000-0000-0000-0000-000000000001"]),
    )
