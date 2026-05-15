"""Conformance test: ACEF error taxonomy.

Each error code with an active code path has at least one test
that triggers it.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from acef.errors import (
    ACEFError,
    ACEFEvaluationError,
    ACEFFormatError,
    ACEFIntegrityError,
    ACEFMergeError,
    ACEFProfileError,
    ACEFSchemaError,
    ACEFSigningError,
    ERROR_REGISTRY,
)
from acef.integrity import canonicalize
from acef.loader import load
from acef.package import Package
from acef.validation.engine import validate_bundle
from acef.validation.integrity_checker import check_integrity
from acef.validation.reference_checker import check_references
from acef.validation.schema_validator import validate_manifest_schema, validate_record_schemas

from tests.conformance.conftest import build_minimal_package


class TestACEF002ManifestSchemaViolation:
    """ACEF-002: Manifest fails JSON Schema validation."""

    def test_empty_manifest_produces_acef_002(self) -> None:
        diagnostics = validate_manifest_schema({})
        codes = [d.code for d in diagnostics]
        assert "ACEF-002" in codes

    def test_manifest_missing_metadata_produces_acef_002(self) -> None:
        manifest: dict[str, Any] = {
            "versioning": {"core_version": "1.0.0"},
            "subjects": [],
        }
        diagnostics = validate_manifest_schema(manifest)
        codes = [d.code for d in diagnostics]
        assert "ACEF-002" in codes


class TestACEF003UnknownRecordType:
    """ACEF-003: Unknown record_type with no schema."""

    def test_unknown_type_produces_acef_003(self) -> None:
        record: dict[str, Any] = {
            "record_id": "urn:acef:rec:00000000-0000-0000-0000-000000000001",
            "record_type": "completely_bogus_type",
            "timestamp": "2025-06-01T00:00:00Z",
            "provisions_addressed": [],
            "confidentiality": "public",
            "trust_level": "self-attested",
            "entity_refs": {"subject_refs": [], "component_refs": [],
                            "dataset_refs": [], "actor_refs": []},
            "payload": {"foo": "bar"},
        }
        diagnostics = validate_record_schemas([record])
        codes = [d.code for d in diagnostics]
        assert "ACEF-003" in codes

    def test_package_rejects_unknown_type(self) -> None:
        """Package.record() raises ACEFSchemaError(ACEF-003) for unknown types."""
        pkg = Package(producer={"name": "test", "version": "1.0.0"})
        with pytest.raises(ACEFSchemaError) as exc_info:
            pkg.record("totally_invalid_type", payload={"x": 1})
        assert "ACEF-003" in str(exc_info.value)


class TestACEF004PayloadSchemaViolation:
    """ACEF-004: Record payload fails type-specific schema validation."""

    def test_empty_payload_produces_acef_004(self) -> None:
        record: dict[str, Any] = {
            "record_id": "urn:acef:rec:00000000-0000-0000-0000-000000000001",
            "record_type": "risk_register",
            "timestamp": "2025-06-01T00:00:00Z",
            "provisions_addressed": ["article-9"],
            "confidentiality": "public",
            "trust_level": "self-attested",
            "entity_refs": {"subject_refs": [], "component_refs": [],
                            "dataset_refs": [], "actor_refs": []},
            "payload": {},  # Missing required fields
        }
        diagnostics = validate_record_schemas([record])
        has_004 = any(d.code == "ACEF-004" for d in diagnostics)
        assert has_004, "Empty payload must produce ACEF-004"


class TestACEF010HashMismatch:
    """ACEF-010: File hash mismatch."""

    def test_tampered_manifest_produces_acef_010(self, tmp_dir: Path) -> None:
        pkg = build_minimal_package()
        bundle_dir = tmp_dir / "acef010"
        pkg.export(str(bundle_dir))

        # Tamper with the manifest
        manifest_path = bundle_dir / "acef-manifest.json"
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        data["metadata"]["producer"]["name"] = "tampered"
        manifest_path.write_bytes(canonicalize(data))

        diagnostics = check_integrity(bundle_dir)
        codes = [d.code for d in diagnostics]
        assert "ACEF-010" in codes


class TestACEF011MerkleRootMismatch:
    """ACEF-011: Merkle root mismatch."""

    def test_corrupted_merkle_root_produces_acef_011(self, tmp_dir: Path) -> None:
        pkg = build_minimal_package()
        bundle_dir = tmp_dir / "acef011"
        pkg.export(str(bundle_dir))

        merkle_path = bundle_dir / "hashes" / "merkle-tree.json"
        merkle_data = json.loads(merkle_path.read_text(encoding="utf-8"))
        merkle_data["root"] = "a" * 64
        merkle_path.write_bytes(canonicalize(merkle_data))

        diagnostics = check_integrity(bundle_dir)
        codes = [d.code for d in diagnostics]
        assert "ACEF-011" in codes


class TestACEF012InvalidSignature:
    """ACEF-012: Invalid or expired signature."""

    def test_malformed_jws_produces_acef_012(self, tmp_dir: Path) -> None:
        pkg = build_minimal_package()
        bundle_dir = tmp_dir / "acef012"
        pkg.export(str(bundle_dir))

        # Write a malformed JWS
        sig_dir = bundle_dir / "signatures"
        sig_dir.mkdir(exist_ok=True)
        (sig_dir / "bad-sig.jws").write_text("not.a.valid-jws-string-at-all", encoding="utf-8")

        diagnostics = check_integrity(bundle_dir)
        codes = [d.code for d in diagnostics]
        assert "ACEF-012" in codes


class TestACEF013UnsupportedAlgorithm:
    """ACEF-013: Unsupported JWS algorithm."""

    def test_unsupported_algorithm_produces_acef_013(self, tmp_dir: Path) -> None:
        import base64

        pkg = build_minimal_package()
        bundle_dir = tmp_dir / "acef013"
        pkg.export(str(bundle_dir))

        # Write a JWS with unsupported algorithm
        header = base64.urlsafe_b64encode(b'{"alg":"HS256"}').rstrip(b"=").decode()
        sig_dir = bundle_dir / "signatures"
        sig_dir.mkdir(exist_ok=True)
        (sig_dir / "bad-alg.jws").write_text(f"{header}..fakesig", encoding="utf-8")

        diagnostics = check_integrity(bundle_dir)
        codes = [d.code for d in diagnostics]
        assert "ACEF-013" in codes

    def test_signing_module_rejects_unsupported_key_type(self) -> None:
        """The signing module raises ACEF-013 for unsupported key types."""
        from acef.signing import _detect_algorithm

        # EdDSA key (Ed25519) is not RS256/ES256
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        ed_key = Ed25519PrivateKey.generate()
        with pytest.raises(ACEFSigningError) as exc_info:
            _detect_algorithm(ed_key)
        assert "ACEF-013" in str(exc_info.value)


class TestACEF014HashIndexCompleteness:
    """ACEF-014: Hash index completeness failure."""

    def test_missing_content_hashes_produces_acef_014(self, tmp_dir: Path) -> None:
        pkg = build_minimal_package()
        bundle_dir = tmp_dir / "acef014_missing"
        pkg.export(str(bundle_dir))

        # Delete content-hashes.json
        (bundle_dir / "hashes" / "content-hashes.json").unlink()

        diagnostics = check_integrity(bundle_dir)
        codes = [d.code for d in diagnostics]
        assert "ACEF-014" in codes

    def test_extra_file_produces_acef_014(self, tmp_dir: Path) -> None:
        pkg = build_minimal_package()
        bundle_dir = tmp_dir / "acef014_extra"
        pkg.export(str(bundle_dir))

        (bundle_dir / "records" / "extra.jsonl").write_text('{"x":1}\n', encoding="utf-8")

        diagnostics = check_integrity(bundle_dir)
        codes = [d.code for d in diagnostics]
        assert "ACEF-014" in codes


class TestACEF020DanglingRef:
    """ACEF-020: Dangling entity_refs."""

    def test_dangling_entity_ref_produces_acef_020(self, tmp_dir: Path) -> None:
        pkg = build_minimal_package()
        bundle_dir = tmp_dir / "acef020"
        pkg.export(str(bundle_dir))

        manifest_data = json.loads(
            (bundle_dir / "acef-manifest.json").read_text(encoding="utf-8")
        )
        # Inject a record with a dangling ref
        records_data: list[dict[str, Any]] = []
        for rf in manifest_data.get("record_files", []):
            rf_path = bundle_dir / rf["path"]
            if rf_path.exists():
                for line in rf_path.read_text(encoding="utf-8").strip().split("\n"):
                    if line.strip():
                        records_data.append(json.loads(line))

        # Add a fake record with dangling ref
        records_data.append({
            "record_id": "urn:acef:rec:99999999-9999-9999-9999-999999999999",
            "record_type": "risk_register",
            "timestamp": "2025-06-01T00:00:00Z",
            "provisions_addressed": [],
            "entity_refs": {
                "subject_refs": ["urn:acef:sub:NONEXISTENT-0000-0000-0000-000000000000"],
                "component_refs": [],
                "dataset_refs": [],
                "actor_refs": [],
            },
            "payload": {"description": "dangling"},
        })

        diagnostics = check_references(manifest_data, records_data, bundle_dir)
        codes = [d.code for d in diagnostics]
        assert "ACEF-020" in codes


class TestACEF021DuplicateURN:
    """ACEF-021: Duplicate URNs within the package."""

    def test_duplicate_subject_urn_produces_acef_021(self, tmp_dir: Path) -> None:
        pkg = build_minimal_package()
        bundle_dir = tmp_dir / "acef021"
        pkg.export(str(bundle_dir))

        manifest_data = json.loads(
            (bundle_dir / "acef-manifest.json").read_text(encoding="utf-8")
        )
        # Duplicate a subject URN
        if manifest_data.get("subjects"):
            dup = dict(manifest_data["subjects"][0])
            manifest_data["subjects"].append(dup)

        records_data: list[dict[str, Any]] = []
        for rf in manifest_data.get("record_files", []):
            rf_path = bundle_dir / rf["path"]
            if rf_path.exists():
                for line in rf_path.read_text(encoding="utf-8").strip().split("\n"):
                    if line.strip():
                        records_data.append(json.loads(line))

        diagnostics = check_references(manifest_data, records_data, bundle_dir)
        codes = [d.code for d in diagnostics]
        assert "ACEF-021" in codes


class TestACEF022MissingRecordFile:
    """ACEF-022: record_files entry references nonexistent file."""

    def test_missing_record_file_produces_acef_022(self, tmp_dir: Path) -> None:
        pkg = build_minimal_package()
        bundle_dir = tmp_dir / "acef022"
        pkg.export(str(bundle_dir))

        manifest_data = json.loads(
            (bundle_dir / "acef-manifest.json").read_text(encoding="utf-8")
        )
        # Delete the actual record file
        for rf in manifest_data.get("record_files", []):
            rf_path = bundle_dir / rf["path"]
            if rf_path.exists():
                rf_path.unlink()
                break

        diagnostics = check_references(manifest_data, [], bundle_dir)
        codes = [d.code for d in diagnostics]
        assert "ACEF-022" in codes


class TestACEF023MissingAttachment:
    """ACEF-023: Attachment path references file not in artifacts/."""

    def test_missing_attachment_produces_acef_023(self, tmp_dir: Path) -> None:
        pkg = build_minimal_package(with_attachment=True)
        bundle_dir = tmp_dir / "acef023"
        pkg.export(str(bundle_dir))

        # Delete the attachment file
        att_file = bundle_dir / "artifacts" / "eval-report.pdf"
        if att_file.exists():
            att_file.unlink()

        manifest_data = json.loads(
            (bundle_dir / "acef-manifest.json").read_text(encoding="utf-8")
        )
        records_data: list[dict[str, Any]] = []
        for rf in manifest_data.get("record_files", []):
            rf_path = bundle_dir / rf["path"]
            if rf_path.exists():
                for line in rf_path.read_text(encoding="utf-8").strip().split("\n"):
                    if line.strip():
                        records_data.append(json.loads(line))

        diagnostics = check_references(manifest_data, records_data, bundle_dir)
        codes = [d.code for d in diagnostics]
        assert "ACEF-023" in codes


class TestACEF025RecordCountMismatch:
    """ACEF-025: Record count mismatch between manifest and actual JSONL."""

    def test_count_mismatch_produces_acef_025(self, tmp_dir: Path) -> None:
        pkg = build_minimal_package()
        bundle_dir = tmp_dir / "acef025"
        pkg.export(str(bundle_dir))

        manifest_data = json.loads(
            (bundle_dir / "acef-manifest.json").read_text(encoding="utf-8")
        )
        # Inflate the expected count
        if manifest_data.get("record_files"):
            manifest_data["record_files"][0]["count"] = 999

        records_data: list[dict[str, Any]] = []
        for rf in manifest_data.get("record_files", []):
            rf_path = bundle_dir / rf["path"]
            if rf_path.exists():
                for line in rf_path.read_text(encoding="utf-8").strip().split("\n"):
                    if line.strip():
                        records_data.append(json.loads(line))

        diagnostics = check_references(manifest_data, records_data, bundle_dir)
        codes = [d.code for d in diagnostics]
        assert "ACEF-025" in codes


class TestACEF026DuplicateRecordId:
    """ACEF-026: Duplicate record_id within the package."""

    def test_duplicate_record_id_produces_acef_026(self, tmp_dir: Path) -> None:
        pkg = build_minimal_package()
        bundle_dir = tmp_dir / "acef026"
        pkg.export(str(bundle_dir))

        manifest_data = json.loads(
            (bundle_dir / "acef-manifest.json").read_text(encoding="utf-8")
        )
        records_data: list[dict[str, Any]] = []
        for rf in manifest_data.get("record_files", []):
            rf_path = bundle_dir / rf["path"]
            if rf_path.exists():
                for line in rf_path.read_text(encoding="utf-8").strip().split("\n"):
                    if line.strip():
                        records_data.append(json.loads(line))

        # Duplicate a record
        if records_data:
            records_data.append(dict(records_data[0]))

        diagnostics = check_references(manifest_data, records_data, bundle_dir)
        codes = [d.code for d in diagnostics]
        assert "ACEF-026" in codes


class TestACEF027AttachmentHashMismatch:
    """ACEF-027: Attachment hash field does not match content-hashes.json.

    Verifier M2: This error code was actively emitted but had no conformance test.
    """

    def test_attachment_hash_mismatch_produces_acef_027(self, tmp_dir: Path) -> None:
        """Create a bundle with an attachment whose hash field mismatches content-hashes."""
        pkg = build_minimal_package(with_attachment=True)
        bundle_dir = tmp_dir / "acef027"
        pkg.export(str(bundle_dir))

        # Read the manifest and content-hashes
        manifest_data = json.loads(
            (bundle_dir / "acef-manifest.json").read_text(encoding="utf-8")
        )
        content_hashes_path = bundle_dir / "hashes" / "content-hashes.json"
        content_hashes = json.loads(content_hashes_path.read_text(encoding="utf-8"))

        # Read existing records
        records_data: list[dict[str, Any]] = []
        for rf in manifest_data.get("record_files", []):
            rf_path = bundle_dir / rf["path"]
            if rf_path.exists():
                for line in rf_path.read_text(encoding="utf-8").strip().split("\n"):
                    if line.strip():
                        records_data.append(json.loads(line))

        # Find a record with an attachment and add a mismatched hash
        att_path = "artifacts/eval-report.pdf"
        found = False
        for rec in records_data:
            if rec.get("attachments"):
                for att in rec["attachments"]:
                    if att.get("path") == att_path:
                        # Set a wrong hash that differs from content-hashes
                        att["hash"] = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                        found = True
                        break
            if found:
                break

        assert found, "Should have found an attachment to tamper with"

        diagnostics = check_references(manifest_data, records_data, bundle_dir)
        codes = [d.code for d in diagnostics]
        assert "ACEF-027" in codes, (
            f"Expected ACEF-027 for hash mismatch, got codes: {codes}"
        )


class TestACEF030TemplateNotFound:
    """ACEF-030: Validate with nonexistent profile/template ID.

    Verifier M2: This error code was actively emitted but had no conformance test.
    """

    def test_nonexistent_profile_produces_acef_030(self, tmp_dir: Path) -> None:
        """Validating against a profile ID with no matching template produces ACEF-030."""
        pkg = build_minimal_package(with_profile="nonexistent-fake-template-id-999")
        bundle_dir = tmp_dir / "acef030"
        pkg.export(str(bundle_dir))

        assessment = validate_bundle(
            bundle_dir,
            profiles=["nonexistent-fake-template-id-999"],
            evaluation_instant="2026-01-15T00:00:00Z",
        )

        structural_codes = [e.get("code", "") for e in assessment.structural_errors]
        assert "ACEF-030" in structural_codes, (
            f"Expected ACEF-030 for missing template, got codes: {structural_codes}"
        )


class TestACEF044DuplicateRuleIds:
    """ACEF-044: Template with duplicate rule_ids.

    Verifier M2: This error code was actively emitted but had no conformance test.
    """

    def test_duplicate_rule_ids_produces_acef_044(self, tmp_dir: Path) -> None:
        """A template with duplicate rule_ids produces ACEF-044 diagnostic."""
        import tempfile

        from acef.templates.models import EvaluationRule, Provision, Template

        # Create a template with duplicate rule_ids
        duplicate_rule = EvaluationRule(
            rule_id="dup-rule-001",
            rule="has_record_type",
            params={"type": "risk_register", "min_count": 1},
            severity="fail",
            message="Risk register required",
        )
        provisions = [
            Provision(
                provision_id="test-prov-1",
                evaluation=[duplicate_rule],
            ),
            Provision(
                provision_id="test-prov-2",
                evaluation=[
                    EvaluationRule(
                        rule_id="dup-rule-001",  # Same rule_id as above
                        rule="has_record_type",
                        params={"type": "dataset_card", "min_count": 1},
                        severity="fail",
                        message="Dataset card required",
                    ),
                ],
            ),
        ]
        template = Template(
            template_id="test-dup-rules",
            template_name="Test Duplicate Rules",
            version="1.0.0",
            provisions=provisions,
        )

        # Write template to templates directory temporarily
        template_path = (
            Path(__file__).parent.parent.parent
            / "src" / "acef" / "templates" / "test-dup-rules.json"
        )
        template_path.write_text(template.model_dump_json(indent=2), encoding="utf-8")

        try:
            pkg = build_minimal_package(with_profile="test-dup-rules")
            bundle_dir = tmp_dir / "acef044"
            pkg.export(str(bundle_dir))

            assessment = validate_bundle(
                bundle_dir,
                profiles=["test-dup-rules"],
                evaluation_instant="2026-01-15T00:00:00Z",
            )

            structural_codes = [e.get("code", "") for e in assessment.structural_errors]
            assert "ACEF-044" in structural_codes, (
                f"Expected ACEF-044 for duplicate rule_ids, got codes: {structural_codes}"
            )
        finally:
            # Clean up the temporary template file
            if template_path.exists():
                template_path.unlink()


class TestACEF060MergeDuplicateSubjects:
    """ACEF-060: Merge packages with duplicate subjects.

    Verifier M2: This error code was actively emitted but had no conformance test.
    """

    def test_merge_duplicate_subjects_produces_acef_060(self) -> None:
        """Merging packages with identical subjects produces ACEF-060 diagnostics."""
        from acef.merge import merge_packages

        pkg1 = build_minimal_package()
        pkg2 = build_minimal_package()

        result = merge_packages([pkg1, pkg2], conflict_strategy="keep_all")

        assert result.has_conflicts
        conflict_codes = [c.code for c in result.conflicts]
        assert "ACEF-060" in conflict_codes, (
            f"Expected ACEF-060 for duplicate subjects, got codes: {conflict_codes}"
        )

    def test_merge_fail_strategy_raises_acef_060(self) -> None:
        """Merging with fail strategy raises ACEFMergeError(ACEF-060) on duplicate subjects."""
        from acef.merge import merge_packages

        pkg1 = build_minimal_package()
        pkg2 = build_minimal_package()

        with pytest.raises(ACEFMergeError) as exc_info:
            merge_packages([pkg1, pkg2], conflict_strategy="fail")
        assert "ACEF-060" in str(exc_info.value)


class TestACEF050FormatError:
    """ACEF-050: Malformed JSONL / format errors."""

    def test_malformed_archive_raises_acef_050(self, tmp_dir: Path) -> None:
        """Attempting to load a non-archive file raises ACEFFormatError with code ACEF-050."""
        bad_file = tmp_dir / "not_a_bundle.tar.gz"
        bad_file.write_bytes(b"this is not a valid gzip file")
        with pytest.raises(ACEFFormatError) as exc_info:
            load(str(bad_file))
        assert exc_info.value.code == "ACEF-050"


class TestACEF052PathViolation:
    """ACEF-052: Path contains .. segments or non-normalized characters."""

    def test_path_traversal_raises_acef_052(self) -> None:
        from acef.loader import _validate_path

        with pytest.raises(ACEFFormatError) as exc_info:
            _validate_path("../../../etc/passwd")
        assert "ACEF-052" in str(exc_info.value)

    def test_backslash_path_raises_acef_052(self) -> None:
        from acef.loader import _validate_path

        with pytest.raises(ACEFFormatError) as exc_info:
            _validate_path("records\\risk_register.jsonl")
        assert "ACEF-052" in str(exc_info.value)

    def test_dot_segment_raises_acef_052(self) -> None:
        from acef.loader import _validate_path

        with pytest.raises(ACEFFormatError) as exc_info:
            _validate_path("records/./risk_register.jsonl")
        assert "ACEF-052" in str(exc_info.value)

    def test_absolute_path_raises_acef_052(self) -> None:
        from acef.loader import _validate_path

        with pytest.raises(ACEFFormatError) as exc_info:
            _validate_path("/records/risk_register.jsonl")
        assert "ACEF-052" in str(exc_info.value)
