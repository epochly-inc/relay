"""Conformance test: integrity verification.

Verifies that the 4-phase validation pipeline correctly detects
tampered files, missing files, extra files, and Merkle root mismatches.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from acef.integrity import (
    build_merkle_tree,
    canonicalize,
    compute_content_hashes,
    sha256_hex,
    verify_content_hashes,
    verify_merkle_root,
)
from acef.loader import load
from acef.validation.engine import validate_bundle
from acef.validation.integrity_checker import check_integrity

from tests.conformance.conftest import build_minimal_package


class TestIntegrity:
    """Integrity conformance: hash verification, Merkle tree, tampering detection."""

    def test_valid_bundle_passes_integrity(self, tmp_dir: Path) -> None:
        """A freshly exported bundle passes all integrity checks with zero diagnostics."""
        pkg = build_minimal_package()
        bundle_dir = tmp_dir / "valid_bundle"
        pkg.export(str(bundle_dir))

        diagnostics = check_integrity(bundle_dir)
        integrity_errors = [d for d in diagnostics if d.code in ("ACEF-010", "ACEF-011", "ACEF-014")]
        assert len(integrity_errors) == 0, (
            f"Valid bundle should have no integrity errors, got: "
            f"{[(d.code, d.message) for d in integrity_errors]}"
        )

    def test_tampered_manifest_produces_acef_010(self, tmp_dir: Path) -> None:
        """Modifying acef-manifest.json after export triggers ACEF-010 hash mismatch."""
        pkg = build_minimal_package()
        bundle_dir = tmp_dir / "tampered_manifest"
        pkg.export(str(bundle_dir))

        # Tamper with the manifest
        manifest_path = bundle_dir / "acef-manifest.json"
        manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest_data["metadata"]["producer"]["name"] = "evil-tool"
        manifest_path.write_bytes(canonicalize(manifest_data))

        diagnostics = check_integrity(bundle_dir)
        acef_010_errors = [d for d in diagnostics if d.code == "ACEF-010"]
        assert len(acef_010_errors) > 0, "Tampered manifest must produce ACEF-010"

    def test_tampered_record_file_produces_acef_010(self, tmp_dir: Path) -> None:
        """Modifying a record JSONL file after export triggers ACEF-010 hash mismatch."""
        pkg = build_minimal_package()
        bundle_dir = tmp_dir / "tampered_record"
        pkg.export(str(bundle_dir))

        # Find and tamper with the record file
        record_files = list((bundle_dir / "records").rglob("*.jsonl"))
        assert len(record_files) > 0, "Bundle should have at least one record file"

        target = record_files[0]
        original = target.read_text(encoding="utf-8")
        lines = original.strip().split("\n")
        if lines:
            record = json.loads(lines[0])
            record["payload"]["description"] = "TAMPERED VALUE"
            lines[0] = json.dumps(record, separators=(",", ":"))
            target.write_text("\n".join(lines) + "\n", encoding="utf-8")

        diagnostics = check_integrity(bundle_dir)
        acef_010_errors = [d for d in diagnostics if d.code == "ACEF-010"]
        assert len(acef_010_errors) > 0, "Tampered record file must produce ACEF-010"

    def test_missing_file_in_content_hashes_produces_acef_014(self, tmp_dir: Path) -> None:
        """Deleting a file that is listed in content-hashes.json triggers ACEF-014."""
        pkg = build_minimal_package()
        bundle_dir = tmp_dir / "missing_file"
        pkg.export(str(bundle_dir))

        # Delete a record file
        record_files = list((bundle_dir / "records").rglob("*.jsonl"))
        assert len(record_files) > 0
        record_files[0].unlink()

        diagnostics = check_integrity(bundle_dir)
        acef_014_errors = [d for d in diagnostics if d.code == "ACEF-014"]
        assert len(acef_014_errors) > 0, (
            "Missing file listed in content-hashes.json must produce ACEF-014"
        )

    def test_extra_file_not_in_content_hashes_produces_acef_014(self, tmp_dir: Path) -> None:
        """Adding a file to the hash domain without updating content-hashes.json triggers ACEF-014."""
        pkg = build_minimal_package()
        bundle_dir = tmp_dir / "extra_file"
        pkg.export(str(bundle_dir))

        # Add an extra file in the records/ directory (part of hash domain)
        extra_file = bundle_dir / "records" / "sneaky_file.jsonl"
        extra_file.write_text('{"record_type":"risk_register"}\n', encoding="utf-8")

        diagnostics = check_integrity(bundle_dir)
        acef_014_errors = [d for d in diagnostics if d.code == "ACEF-014"]
        assert len(acef_014_errors) > 0, (
            "Extra file in hash domain but not in content-hashes.json must produce ACEF-014"
        )

    def test_merkle_root_mismatch_produces_acef_011(self, tmp_dir: Path) -> None:
        """Corrupting the Merkle root triggers ACEF-011."""
        pkg = build_minimal_package()
        bundle_dir = tmp_dir / "bad_merkle"
        pkg.export(str(bundle_dir))

        # Tamper with the Merkle tree root
        merkle_path = bundle_dir / "hashes" / "merkle-tree.json"
        merkle_data = json.loads(merkle_path.read_text(encoding="utf-8"))
        merkle_data["root"] = "0" * 64  # bogus root
        merkle_path.write_bytes(canonicalize(merkle_data))

        diagnostics = check_integrity(bundle_dir)
        acef_011_errors = [d for d in diagnostics if d.code == "ACEF-011"]
        assert len(acef_011_errors) > 0, "Corrupted Merkle root must produce ACEF-011"

    def test_content_hashes_cover_manifest_and_records(self, tmp_dir: Path) -> None:
        """content-hashes.json must include entries for manifest and all record files."""
        pkg = build_minimal_package(
            record_types=["risk_register", "risk_treatment", "evaluation_report"]
        )
        bundle_dir = tmp_dir / "hash_coverage"
        pkg.export(str(bundle_dir))

        ch_path = bundle_dir / "hashes" / "content-hashes.json"
        content_hashes = json.loads(ch_path.read_text(encoding="utf-8"))

        assert "acef-manifest.json" in content_hashes, (
            "content-hashes.json must include acef-manifest.json"
        )

        record_files = list((bundle_dir / "records").rglob("*.jsonl"))
        for rf in record_files:
            rel = rf.relative_to(bundle_dir).as_posix()
            assert rel in content_hashes, (
                f"content-hashes.json must include record file {rel}"
            )

    def test_merkle_tree_structure_valid(self, tmp_dir: Path) -> None:
        """Merkle tree has correct structure with leaves and root."""
        pkg = build_minimal_package(
            record_types=["risk_register", "risk_treatment"]
        )
        bundle_dir = tmp_dir / "merkle_structure"
        pkg.export(str(bundle_dir))

        merkle_path = bundle_dir / "hashes" / "merkle-tree.json"
        merkle_data = json.loads(merkle_path.read_text(encoding="utf-8"))

        assert "root" in merkle_data, "Merkle tree must have 'root' key"
        assert "leaves" in merkle_data, "Merkle tree must have 'leaves' key"
        assert len(merkle_data["root"]) == 64, "Root must be a 64-char hex SHA-256"
        assert len(merkle_data["leaves"]) > 0, "Must have at least one leaf"

        for leaf in merkle_data["leaves"]:
            assert "path" in leaf, "Each leaf must have a 'path'"
            assert "hash" in leaf, "Each leaf must have a 'hash'"

    def test_verify_content_hashes_empty_on_valid_bundle(self, tmp_dir: Path) -> None:
        """verify_content_hashes returns empty error list for a valid bundle."""
        pkg = build_minimal_package()
        bundle_dir = tmp_dir / "verify_valid"
        pkg.export(str(bundle_dir))

        ch_path = bundle_dir / "hashes" / "content-hashes.json"
        expected_hashes = json.loads(ch_path.read_text(encoding="utf-8"))

        errors = verify_content_hashes(bundle_dir, expected_hashes)
        assert errors == [], f"Valid bundle must produce zero hash errors, got: {errors}"

    def test_full_validation_passes_for_valid_bundle(self, tmp_dir: Path) -> None:
        """validate_bundle on a valid exported bundle produces zero structural errors."""
        pkg = build_minimal_package()
        bundle_dir = tmp_dir / "full_valid"
        pkg.export(str(bundle_dir))

        assessment = validate_bundle(bundle_dir)
        integrity_errors = [
            e for e in assessment.structural_errors
            if e.get("code", "").startswith("ACEF-01")
        ]
        assert len(integrity_errors) == 0, (
            f"Valid bundle should have no integrity structural errors, got: {integrity_errors}"
        )
