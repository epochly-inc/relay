"""Conformance test suite fixtures — keys, helper builders, shared utilities."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from acef.models.enums import ObligationRole
from acef.package import Package


@pytest.fixture
def tmp_dir():
    """Provide a temporary directory for test output."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def rsa_key_pair(tmp_dir: Path) -> tuple[Path, Path]:
    """Generate an RSA 2048-bit key pair and write PEM files.

    Returns:
        Tuple of (private_key_path, public_key_path).
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    priv_path = tmp_dir / "rsa_private.pem"
    pub_path = tmp_dir / "rsa_public.pem"
    priv_path.write_bytes(private_pem)
    pub_path.write_bytes(public_pem)
    return priv_path, pub_path


@pytest.fixture
def ec_key_pair(tmp_dir: Path) -> tuple[Path, Path]:
    """Generate an EC P-256 key pair and write PEM files.

    Returns:
        Tuple of (private_key_path, public_key_path).
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    priv_path = tmp_dir / "ec_private.pem"
    pub_path = tmp_dir / "ec_public.pem"
    priv_path.write_bytes(private_pem)
    pub_path.write_bytes(public_pem)
    return priv_path, pub_path


def build_minimal_package(
    *,
    record_types: list[str] | None = None,
    provisions: list[str] | None = None,
    with_profile: str | None = None,
    with_attachment: bool = False,
    with_extension_record: bool = False,
) -> Package:
    """Build a minimal but valid ACEF package for conformance testing.

    Args:
        record_types: List of record types to include (defaults to risk_register).
        provisions: Provisions to address on records.
        with_profile: Profile ID to declare.
        with_attachment: Whether to add an attachment file.
        with_extension_record: Whether to add an x- extension record.

    Returns:
        A fully constructed Package.
    """
    if record_types is None:
        record_types = ["risk_register"]
    if provisions is None:
        provisions = ["article-9"]

    pkg = Package(producer={"name": "conformance-test", "version": "1.0.0"})
    system = pkg.add_subject(
        "ai_system",
        name="Conformance Test System",
        risk_classification="high-risk",
        modalities=["text"],
        lifecycle_phase="deployment",
    )

    if with_profile:
        pkg.add_profile(with_profile, provisions=provisions)

    for rt in record_types:
        pkg.record(
            rt,
            provisions=provisions,
            payload=_default_payload(rt),
            obligation_role="provider",
            entity_refs={"subject_refs": [system.id]},
        )

    if with_attachment:
        pkg.add_attachment("eval-report.pdf", b"PDF CONTENT FOR TESTING")
        # Add a record referencing the attachment
        from acef.models.records import AttachmentRef

        pkg.record(
            "evaluation_report",
            provisions=["article-11"],
            payload={"methodology": "benchmark", "results": {"accuracy": 0.95}},
            obligation_role="provider",
            entity_refs={"subject_refs": [system.id]},
            attachments=[
                {
                    "path": "artifacts/eval-report.pdf",
                    "media_type": "application/pdf",
                    "description": "Evaluation report",
                }
            ],
        )

    if with_extension_record:
        pkg.record(
            "x-custom-audit",
            provisions=[],
            payload={"custom_field": "custom_value", "score": 42},
        )

    return pkg


def _default_payload(record_type: str) -> dict[str, Any]:
    """Generate a valid default payload for each record type."""
    payloads: dict[str, dict[str, Any]] = {
        "risk_register": {
            "description": "Conformance test risk",
            "likelihood": "medium",
            "severity": "high",
        },
        "risk_treatment": {
            "treatment_type": "mitigate",
            "description": "Conformance test treatment",
        },
        "dataset_card": {
            "name": "Test Dataset",
            "description": "A test dataset for conformance",
        },
        "data_provenance": {
            "acquisition_method": "licensed",
            "acquisition_date": "2025-01-01",
        },
        "evaluation_report": {
            "methodology": "benchmark",
            "results": {"accuracy": 0.92},
        },
        "event_log": {
            "event_type": "inference",
            "description": "Test event",
        },
        "human_oversight_action": {
            "action_type": "override",
            "description": "Test oversight action",
        },
        "transparency_disclosure": {
            "disclosure_type": "ai_interaction",
            "description": "Test disclosure",
        },
        "transparency_marking": {
            "modality": "text",
            "marking_scheme_id": "c2pa-content-credentials",
            "scheme_version": "2.3",
            "metadata_container": "xmp/c2pa-manifest-store",
            "watermark_applied": True,
        },
        "disclosure_labeling": {
            "disclosure_type": "synthetic_content",
            "placement": "inline",
        },
        "copyright_rights_reservation": {
            "reservation_type": "opt_out",
            "description": "Test copyright reservation",
        },
        "license_record": {
            "license_type": "Apache-2.0",
            "description": "Test license record",
        },
        "incident_report": {
            "incident_type": "malfunction",
            "description": "Test incident",
        },
        "governance_policy": {
            "policy_type": "quality_management",
            "description": "Test governance policy",
        },
        "conformity_declaration": {
            "scope": "Full system",
            "declaration_date": "2025-06-01",
        },
        "evidence_gap": {
            "gap_type": "missing_evidence",
            "description": "Test evidence gap",
        },
    }
    return payloads.get(record_type, {"description": f"Test {record_type}"})
