"""Integration tests — end-to-end bundle creation, export, load, validate."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

import acef
from acef.integrity import compute_bundle_digest, compute_content_hashes
from acef.package import Package


class TestEndToEndBundleFlow:
    """Full lifecycle: create → export → load → validate → assess."""

    def test_minimal_bundle_lifecycle(self, tmp_dir: Path) -> None:
        """Create minimal bundle, export, load, re-export with identical hashes."""
        pkg = Package(producer={"name": "test", "version": "1.0"})
        pkg.add_subject("ai_system", name="Test", risk_classification="minimal-risk")
        pkg.record("risk_register", payload={"description": "test"})

        # Export
        bundle_dir = tmp_dir / "test.acef"
        pkg.export(str(bundle_dir))
        assert (bundle_dir / "acef-manifest.json").exists()
        assert (bundle_dir / "hashes" / "content-hashes.json").exists()
        assert (bundle_dir / "records" / "risk_register.jsonl").exists()

        # Load
        pkg2 = acef.load(str(bundle_dir))
        assert len(pkg2.records) == 1
        assert len(pkg2.subjects) == 1

        # Re-export
        bundle_dir2 = tmp_dir / "test2.acef"
        pkg2.export(str(bundle_dir2))

        # Compare content hashes (round-trip determinism)
        h1 = json.loads((bundle_dir / "hashes" / "content-hashes.json").read_text())
        h2 = json.loads((bundle_dir2 / "hashes" / "content-hashes.json").read_text())
        assert h1 == h2

    def test_full_package_lifecycle(self, full_package: Package, tmp_dir: Path) -> None:
        """Full package with multiple subjects and records round-trips correctly."""
        bundle_dir = tmp_dir / "full.acef"
        full_package.export(str(bundle_dir))

        pkg2 = acef.load(str(bundle_dir))
        assert len(pkg2.subjects) == 2
        assert len(pkg2.records) == len(full_package.records)
        assert len(pkg2.entities.components) == 2
        assert len(pkg2.entities.datasets) == 1
        assert len(pkg2.entities.relationships) == 3
        assert len(pkg2.profiles) == 1

    def test_archive_round_trip(self, minimal_package: Package, tmp_dir: Path) -> None:
        """Export as .tar.gz, load, re-export — content hashes match."""
        archive_path = tmp_dir / "test.acef.tar.gz"
        minimal_package.export(str(archive_path))
        assert archive_path.exists()

        pkg2 = acef.load(str(archive_path))
        assert len(pkg2.records) == 1

        # Re-export as directory
        dir_path = tmp_dir / "from_archive.acef"
        pkg2.export(str(dir_path))
        assert (dir_path / "acef-manifest.json").exists()

    def test_multiple_record_types(self, tmp_dir: Path) -> None:
        """Bundle with multiple record types exports correctly."""
        pkg = Package(producer={"name": "test", "version": "1.0"})
        system = pkg.add_subject("ai_system", name="Test")

        pkg.record("risk_register", payload={"description": "R1"})
        pkg.record("risk_treatment", payload={"treatment_type": "mitigate"})
        pkg.record("dataset_card", payload={"name": "DS1"})
        pkg.record("evaluation_report", payload={"methodology": "test"})
        pkg.record("event_log", payload={"event_type": "inference"})

        bundle_dir = tmp_dir / "multi.acef"
        pkg.export(str(bundle_dir))

        # Check multiple JSONL files created
        records_dir = bundle_dir / "records"
        jsonl_files = list(records_dir.glob("*.jsonl"))
        assert len(jsonl_files) == 5

        # Load and verify
        pkg2 = acef.load(str(bundle_dir))
        assert len(pkg2.records) == 5

    def test_attachments(self, tmp_dir: Path) -> None:
        """Bundle with attachments includes them in artifacts/."""
        pkg = Package(producer={"name": "test", "version": "1.0"})
        pkg.add_subject("ai_system", name="Test")

        content = b"Test report content"
        pkg.add_attachment("eval-report.pdf", content)

        pkg.record(
            "evaluation_report",
            payload={"methodology": "test"},
            attachments=[{
                "path": "artifacts/eval-report.pdf",
                "media_type": "application/pdf",
                "description": "Test report",
            }],
        )

        bundle_dir = tmp_dir / "with_attachments.acef"
        pkg.export(str(bundle_dir))

        assert (bundle_dir / "artifacts" / "eval-report.pdf").exists()
        assert (bundle_dir / "artifacts" / "eval-report.pdf").read_bytes() == content

        # Verify attachment is in content hashes
        hashes = json.loads((bundle_dir / "hashes" / "content-hashes.json").read_text())
        assert "artifacts/eval-report.pdf" in hashes

    def test_evidence_gap_handling(self, tmp_dir: Path) -> None:
        """Evidence gaps are correctly handled in bundle lifecycle."""
        pkg = Package(producer={"name": "test", "version": "1.0"})
        system = pkg.add_subject("ai_system", name="Test", risk_classification="high-risk")
        pkg.add_profile("eu-ai-act-2024", provisions=["article-15"])

        pkg.record(
            "evidence_gap",
            provisions=["article-15"],
            payload={
                "missing_record_type": "evaluation_report",
                "reason": "testing_scheduled",
                "expected_completion_date": "2026-06-30",
            },
            entity_refs={"subject_refs": [system.id]},
        )

        bundle_dir = tmp_dir / "gap.acef"
        pkg.export(str(bundle_dir))

        pkg2 = acef.load(str(bundle_dir))
        assert len(pkg2.records) == 1
        assert pkg2.records[0].record_type == "evidence_gap"


class TestValidation:
    """Integration tests for the validation pipeline."""

    def test_validate_exported_bundle(self, full_package: Package, tmp_dir: Path) -> None:
        """Validate an exported bundle produces assessment results."""
        bundle_dir = tmp_dir / "validate.acef"
        full_package.export(str(bundle_dir))

        assessment = acef.validate(str(bundle_dir))
        assert assessment.assessment_id.startswith("urn:acef:asx:")
        assert assessment.evidence_bundle_ref.package_id

    def test_validate_package_directly(self, minimal_package: Package) -> None:
        """Validate a Package object without exporting first."""
        assessment = acef.validate(minimal_package)
        assert assessment.assessment_id.startswith("urn:acef:asx:")

    def test_bundle_digest(self, minimal_package: Package, tmp_dir: Path) -> None:
        """Bundle digest is deterministic."""
        bundle_dir = tmp_dir / "digest.acef"
        minimal_package.export(str(bundle_dir))

        hashes1 = compute_content_hashes(bundle_dir)
        digest1 = compute_bundle_digest(hashes1)

        # Re-export should produce same digest
        bundle_dir2 = tmp_dir / "digest2.acef"
        pkg2 = acef.load(str(bundle_dir))
        pkg2.export(str(bundle_dir2))

        hashes2 = compute_content_hashes(bundle_dir2)
        digest2 = compute_bundle_digest(hashes2)

        assert digest1 == digest2
        assert digest1.startswith("sha256:")


class TestPackageChaining:
    """Test package version chaining via prior_package_ref."""

    def test_chain_packages(self, tmp_dir: Path) -> None:
        """Chain two packages via prior_package_ref."""
        # Create first package
        pkg1 = Package(producer={"name": "test", "version": "1.0"})
        pkg1.add_subject("ai_system", name="Test")
        pkg1.record("risk_register", payload={"description": "V1"})

        bundle_dir1 = tmp_dir / "v1.acef"
        pkg1.export(str(bundle_dir1))

        # Get digest of first package
        hashes1 = compute_content_hashes(bundle_dir1)
        digest1 = compute_bundle_digest(hashes1)

        # Create second package chained to first
        pkg2 = Package(
            producer={"name": "test", "version": "1.0"},
            prior_package_ref=digest1,
        )
        pkg2.add_subject("ai_system", name="Test")
        pkg2.record("risk_register", payload={"description": "V2"})

        bundle_dir2 = tmp_dir / "v2.acef"
        pkg2.export(str(bundle_dir2))

        manifest = json.loads((bundle_dir2 / "acef-manifest.json").read_text())
        assert manifest["metadata"]["prior_package_ref"] == digest1


class TestMerge:
    """Integration tests for package merging."""

    def test_merge_two_packages(self, tmp_dir: Path) -> None:
        """Merge two packages into one."""
        pkg1 = Package(producer={"name": "tool1", "version": "1.0"})
        s1 = pkg1.add_subject("ai_system", name="System A")
        pkg1.record("risk_register", provisions=["article-9"], payload={"desc": "R1"}, entity_refs={"subject_refs": [s1.id]})

        pkg2 = Package(producer={"name": "tool2", "version": "1.0"})
        s2 = pkg2.add_subject("ai_model", name="Model B")
        pkg2.record("dataset_card", provisions=["article-10"], payload={"name": "DS"}, entity_refs={"subject_refs": [s2.id]})

        result = acef.merge_packages([pkg1, pkg2])
        assert not result.has_conflicts
        assert len(result.package.subjects) == 2
        assert len(result.package.records) == 2


class TestRedaction:
    """Integration tests for evidence redaction."""

    def test_redact_and_verify(self) -> None:
        """Redact a package, verify hash commitments match."""
        pkg = Package(producer={"name": "test", "version": "1.0"})
        pkg.add_subject("ai_system", name="Test")

        rec = pkg.record(
            "copyright_rights_reservation",
            payload={"opt_out_method": "robots_txt", "removal_count": 42},
            confidentiality="regulator-only",
        )

        original_payload = rec.payload.copy()

        redacted_pkg = acef.redact_package(
            pkg,
            record_filter={"confidentiality_levels": ["regulator-only"]},
        )

        assert len(redacted_pkg.records) == 1
        redacted_rec = redacted_pkg.records[0]
        assert redacted_rec.confidentiality.value == "hash-committed"
        assert "_redacted" in redacted_rec.payload

        # Verify hash commitment
        from acef.redaction import verify_redaction
        assert verify_redaction(redacted_rec, original_payload)
