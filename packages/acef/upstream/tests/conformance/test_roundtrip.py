"""Conformance test: round-trip fidelity.

Verifies that create -> export -> load -> re-export produces
byte-identical content-hashes.json and preserves all data.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from acef.export import export_directory
from acef.integrity import compute_content_hashes, sha256_hex, canonicalize
from acef.loader import load
from acef.package import Package

from tests.conformance.conftest import build_minimal_package


class TestRoundTrip:
    """Round-trip conformance: export -> load -> re-export must be identical."""

    def test_roundtrip_content_hashes_identical(self, tmp_dir: Path) -> None:
        """Create -> export -> load -> re-export produces identical content-hashes.json."""
        pkg = build_minimal_package()

        # First export
        dir1 = tmp_dir / "bundle1"
        pkg.export(str(dir1))

        # Load and re-export
        loaded = load(str(dir1))
        dir2 = tmp_dir / "bundle2"
        loaded.export(str(dir2))

        # Compare content hashes
        hashes1 = (dir1 / "hashes" / "content-hashes.json").read_bytes()
        hashes2 = (dir2 / "hashes" / "content-hashes.json").read_bytes()
        assert hashes1 == hashes2, "content-hashes.json must be byte-identical after round-trip"

    def test_roundtrip_preserves_metadata(self, tmp_dir: Path) -> None:
        """Round-trip preserves all metadata fields."""
        pkg = Package(
            producer={"name": "roundtrip-test", "version": "2.0.0"},
            retention_policy={"min_retention_days": 365},
        )
        system = pkg.add_subject(
            "ai_system",
            name="Roundtrip System",
            risk_classification="high-risk",
            modalities=["text", "image"],
            lifecycle_phase="deployment",
            version="3.0.0",
            provider="Test Corp",
        )
        pkg.record(
            "risk_register",
            provisions=["article-9"],
            payload={"description": "test", "likelihood": "low", "severity": "low"},
            obligation_role="provider",
            entity_refs={"subject_refs": [system.id]},
        )

        # Export and reload
        bundle_dir = tmp_dir / "metadata_rt"
        pkg.export(str(bundle_dir))
        loaded = load(str(bundle_dir))

        assert loaded.metadata.producer.name == "roundtrip-test"
        assert loaded.metadata.producer.version == "2.0.0"
        assert loaded.metadata.package_id == pkg.metadata.package_id
        assert loaded.metadata.timestamp == pkg.metadata.timestamp
        assert loaded.metadata.retention_policy is not None
        assert loaded.metadata.retention_policy.min_retention_days == 365

    def test_roundtrip_preserves_subjects(self, tmp_dir: Path) -> None:
        """Round-trip preserves subject definitions including type, name, version."""
        pkg = Package(producer={"name": "test", "version": "1.0.0"})
        sys1 = pkg.add_subject(
            "ai_system", name="System A", version="1.0.0",
            risk_classification="high-risk", modalities=["text"],
        )
        model1 = pkg.add_subject(
            "ai_model", name="Model B", version="2.0.0",
            risk_classification="gpai", modalities=["text", "image"],
        )
        pkg.record("risk_register", provisions=["article-9"],
                    payload={"description": "test", "likelihood": "low", "severity": "low"},
                    entity_refs={"subject_refs": [sys1.id]})

        bundle_dir = tmp_dir / "subjects_rt"
        pkg.export(str(bundle_dir))
        loaded = load(str(bundle_dir))

        assert len(loaded.subjects) == 2
        loaded_names = {s.name for s in loaded.subjects}
        assert "System A" in loaded_names
        assert "Model B" in loaded_names

        model_loaded = next(s for s in loaded.subjects if s.name == "Model B")
        assert model_loaded.subject_type.value == "ai_model"
        assert model_loaded.version == "2.0.0"

    def test_roundtrip_preserves_entities(self, tmp_dir: Path) -> None:
        """Round-trip preserves components, datasets, actors, relationships."""
        pkg = Package(producer={"name": "test", "version": "1.0.0"})
        system = pkg.add_subject("ai_system", name="Test Sys")
        comp = pkg.add_component("Retriever", type="retriever", subject_refs=[system.id])
        ds = pkg.add_dataset("Training Data", source_type="licensed", modality="text",
                             subject_refs=[system.id])
        actor = pkg.add_actor(name="Jane", role="provider", organization="ACME")
        pkg.add_relationship(system.id, comp.id, "calls")
        pkg.record("risk_register", provisions=["article-9"],
                    payload={"description": "test", "likelihood": "low", "severity": "low"},
                    entity_refs={"subject_refs": [system.id]})

        bundle_dir = tmp_dir / "entities_rt"
        pkg.export(str(bundle_dir))
        loaded = load(str(bundle_dir))

        assert len(loaded.entities.components) == 1
        assert loaded.entities.components[0].name == "Retriever"
        assert len(loaded.entities.datasets) == 1
        assert loaded.entities.datasets[0].name == "Training Data"
        assert len(loaded.entities.actors) == 1
        assert loaded.entities.actors[0].name == "Jane"
        assert len(loaded.entities.relationships) == 1
        assert loaded.entities.relationships[0].relationship_type.value == "calls"

    def test_roundtrip_preserves_records(self, tmp_dir: Path) -> None:
        """Round-trip preserves record data — types, payloads, entity refs, provisions."""
        pkg = build_minimal_package(
            record_types=["risk_register", "risk_treatment", "evaluation_report"],
            provisions=["article-9", "article-11"],
        )

        bundle_dir = tmp_dir / "records_rt"
        pkg.export(str(bundle_dir))
        loaded = load(str(bundle_dir))

        orig_types = sorted(r.record_type for r in pkg.records)
        loaded_types = sorted(r.record_type for r in loaded.records)
        assert orig_types == loaded_types

        for orig_rec in pkg.records:
            loaded_rec = next(
                (r for r in loaded.records if r.record_id == orig_rec.record_id), None
            )
            assert loaded_rec is not None, f"Record {orig_rec.record_id} not found after round-trip"
            assert loaded_rec.record_type == orig_rec.record_type
            assert loaded_rec.payload == orig_rec.payload
            assert loaded_rec.provisions_addressed == orig_rec.provisions_addressed

    def test_roundtrip_preserves_record_ordering(self, tmp_dir: Path) -> None:
        """Records are stored in timestamp asc, record_id sub-sort order."""
        pkg = Package(producer={"name": "test", "version": "1.0.0"})
        system = pkg.add_subject("ai_system", name="Test Sys")

        # Add records with explicit timestamps for deterministic ordering
        ts_base = "2025-06-01T00:00:0"
        for i in range(5):
            r = pkg.record(
                "risk_register",
                provisions=["article-9"],
                payload={"description": f"Risk {i}", "likelihood": "low", "severity": "low"},
                entity_refs={"subject_refs": [system.id]},
                timestamp=f"{ts_base}{i}Z",
            )

        bundle_dir = tmp_dir / "ordering_rt"
        pkg.export(str(bundle_dir))
        loaded = load(str(bundle_dir))

        loaded_rr = [r for r in loaded.records if r.record_type == "risk_register"]
        timestamps = [r.timestamp for r in loaded_rr]
        assert timestamps == sorted(timestamps), "Records must be in timestamp ascending order"

    def test_roundtrip_preserves_profiles(self, tmp_dir: Path) -> None:
        """Round-trip preserves profile declarations."""
        pkg = build_minimal_package(
            with_profile="eu-ai-act-2024",
            provisions=["article-9", "article-10"],
        )

        bundle_dir = tmp_dir / "profiles_rt"
        pkg.export(str(bundle_dir))
        loaded = load(str(bundle_dir))

        assert len(loaded.profiles) == 1
        assert loaded.profiles[0].profile_id == "eu-ai-act-2024"
        assert "article-9" in loaded.profiles[0].applicable_provisions
        assert "article-10" in loaded.profiles[0].applicable_provisions

    def test_archive_roundtrip(self, tmp_dir: Path) -> None:
        """Create -> export .tar.gz -> load -> re-export dir produces identical hashes."""
        pkg = build_minimal_package(
            record_types=["risk_register", "risk_treatment"],
        )

        # Export as archive
        archive_path = tmp_dir / "bundle.acef.tar.gz"
        pkg.export(str(archive_path))

        # Load from archive
        loaded = load(str(archive_path))

        # Re-export as directory
        dir_out = tmp_dir / "from_archive"
        loaded.export(str(dir_out))

        # The content hashes from the original package (exported as dir) must match
        dir_orig = tmp_dir / "orig_dir"
        pkg.export(str(dir_orig))

        hashes_orig = (dir_orig / "hashes" / "content-hashes.json").read_bytes()
        hashes_reexported = (dir_out / "hashes" / "content-hashes.json").read_bytes()
        assert hashes_orig == hashes_reexported, (
            "Archive round-trip must produce identical content-hashes.json"
        )

    def test_roundtrip_with_attachments(self, tmp_dir: Path) -> None:
        """Bundle with attachments round-trips correctly, preserving file content."""
        pkg = build_minimal_package(with_attachment=True)

        bundle_dir = tmp_dir / "attach_rt"
        pkg.export(str(bundle_dir))

        # Verify attachment exists on disk
        att_path = bundle_dir / "artifacts" / "eval-report.pdf"
        assert att_path.exists(), "Attachment must be written to artifacts/"
        assert att_path.read_bytes() == b"PDF CONTENT FOR TESTING"

        # Load and verify attachment survives via public property
        loaded = load(str(bundle_dir))
        assert "artifacts/eval-report.pdf" in loaded.attachments
        assert loaded.attachments["artifacts/eval-report.pdf"] == b"PDF CONTENT FOR TESTING"

        # Re-export and verify
        dir2 = tmp_dir / "attach_rt2"
        loaded.export(str(dir2))
        att_path2 = dir2 / "artifacts" / "eval-report.pdf"
        assert att_path2.exists()
        assert att_path2.read_bytes() == b"PDF CONTENT FOR TESTING"

    def test_roundtrip_manifest_byte_identical(self, tmp_dir: Path) -> None:
        """The manifest JSON is byte-identical after round-trip (RFC 8785 canonical)."""
        pkg = build_minimal_package()

        dir1 = tmp_dir / "manifest_rt1"
        pkg.export(str(dir1))
        loaded = load(str(dir1))
        dir2 = tmp_dir / "manifest_rt2"
        loaded.export(str(dir2))

        manifest1 = (dir1 / "acef-manifest.json").read_bytes()
        manifest2 = (dir2 / "acef-manifest.json").read_bytes()
        assert manifest1 == manifest2, "Manifest must be byte-identical after round-trip"
