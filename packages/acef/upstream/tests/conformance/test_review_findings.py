"""Conformance tests added to address review findings M-VERIFY-2 through M-VERIFY-5.

M-VERIFY-2: Shard boundary tests at exact 100k record boundary
M-VERIFY-3: Archive determinism — raw byte comparison
M-VERIFY-4: Negative schema tests for normative minimum payloads
M-VERIFY-5: Variant registry conformance tests
"""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path
from typing import Any

import pytest

from acef.export import export_archive, export_directory
from acef.integrity import compute_content_hashes
from acef.loader import load
from acef.models.records import RecordEnvelope
from acef.package import Package
from acef.records_util import compute_shard_boundaries, sort_records
from acef.schemas.registry import load_variant_registry, resolve_variant
from acef.validation.operators import op_exists_where
from acef.validation.schema_validator import validate_record_schemas

from tests.conformance.conftest import build_minimal_package


# --- M-VERIFY-2: Shard boundary tests ------------------------------------


class TestShardBoundaryExact:
    """Test shard boundary computation at the exact 100k record count boundary."""

    def _build_n_records(self, n: int) -> list[RecordEnvelope]:
        """Build exactly n records for shard testing."""
        records = []
        for i in range(n):
            ts = f"2025-01-01T00:00:{str(i % 60).zfill(2)}Z"
            records.append(
                RecordEnvelope(
                    record_type="risk_register",
                    provisions_addressed=["article-9"],
                    payload={"description": f"r{i}", "likelihood": "low", "severity": "low"},
                    timestamp=ts,
                )
            )
        return records

    def test_99999_records_single_shard(self) -> None:
        """99,999 records must fit in a single shard (below 100k limit)."""
        records = self._build_n_records(99_999)
        sorted_recs = sort_records(records)
        shards = compute_shard_boundaries(sorted_recs)
        assert len(shards) == 1
        assert len(shards[0]) == 99_999

    def test_100000_records_single_shard(self) -> None:
        """Exactly 100,000 records must fit in a single shard (at boundary)."""
        records = self._build_n_records(100_000)
        sorted_recs = sort_records(records)
        shards = compute_shard_boundaries(sorted_recs)
        assert len(shards) == 1
        assert len(shards[0]) == 100_000

    def test_100001_records_two_shards(self) -> None:
        """100,001 records must split into exactly 2 shards."""
        records = self._build_n_records(100_001)
        sorted_recs = sort_records(records)
        shards = compute_shard_boundaries(sorted_recs)
        assert len(shards) == 2
        assert len(shards[0]) == 100_000
        assert len(shards[1]) == 1

    def test_200000_records_two_shards(self) -> None:
        """200,000 records must split into exactly 2 shards of 100k each."""
        records = self._build_n_records(200_000)
        sorted_recs = sort_records(records)
        shards = compute_shard_boundaries(sorted_recs)
        assert len(shards) == 2
        assert len(shards[0]) == 100_000
        assert len(shards[1]) == 100_000

    def test_manifest_reflects_sharding(self, tmp_dir: Path) -> None:
        """A package with 100,001 records must produce sharded manifest entries."""
        pkg = Package()
        for i in range(100_001):
            pkg.record(
                "risk_register",
                payload={"description": f"r{i}", "likelihood": "low", "severity": "low"},
                timestamp=f"2025-01-01T00:00:{str(i % 60).zfill(2)}Z",
            )
        manifest = pkg.build_manifest()
        rr_files = [rf for rf in manifest.record_files if rf.record_type == "risk_register"]
        assert len(rr_files) == 2
        # First shard has 100k, second has 1
        assert rr_files[0].count == 100_000
        assert rr_files[1].count == 1
        # Sharded paths use subdirectory format
        assert "risk_register/risk_register.0001.jsonl" in rr_files[0].path
        assert "risk_register/risk_register.0002.jsonl" in rr_files[1].path


# --- M-VERIFY-3: Archive determinism — byte-identical output --------------


class TestArchiveDeterminism:
    """Export the same package twice and verify byte-identical archives."""

    def test_same_name_archives_byte_identical(self, tmp_dir: Path) -> None:
        """Two exports of the same package to the same archive name produce
        byte-identical .acef.tar.gz files."""
        pkg = build_minimal_package()

        archive1 = tmp_dir / "det_a" / "bundle.acef.tar.gz"
        archive2 = tmp_dir / "det_b" / "bundle.acef.tar.gz"

        archive1.parent.mkdir(parents=True)
        archive2.parent.mkdir(parents=True)

        export_archive(pkg, str(archive1))
        export_archive(pkg, str(archive2))

        bytes1 = archive1.read_bytes()
        bytes2 = archive2.read_bytes()
        assert bytes1 == bytes2, "Archives from the same package must be byte-identical"

    def test_archive_tar_member_metadata(self, tmp_dir: Path) -> None:
        """Tar members must have deterministic modes, mtimes, uid/gid."""
        pkg = build_minimal_package()
        archive = tmp_dir / "meta.acef.tar.gz"
        export_archive(pkg, str(archive))

        with tarfile.open(str(archive), "r:gz") as tar:
            for member in tar.getmembers():
                if member.isdir():
                    assert member.mode == 0o755, f"Dir {member.name} mode != 0755"
                elif member.isfile():
                    assert member.mode == 0o644, f"File {member.name} mode != 0644"
                assert member.uid == 0, f"{member.name} uid != 0"
                assert member.gid == 0, f"{member.name} gid != 0"
                assert member.uname == "", f"{member.name} uname not empty"
                assert member.gname == "", f"{member.name} gname not empty"

    def test_archive_gzip_os_byte(self, tmp_dir: Path) -> None:
        """Gzip OS byte must be 0xFF (unknown) per spec."""
        pkg = build_minimal_package()
        archive = tmp_dir / "os.acef.tar.gz"
        export_archive(pkg, str(archive))

        raw = archive.read_bytes()
        # Gzip header: bytes[0:2]=magic, [2]=method, [9]=OS
        assert raw[0:2] == b"\x1f\x8b", "Not a gzip file"
        assert raw[9] == 0xFF, f"OS byte must be 0xFF, got 0x{raw[9]:02X}"


# --- M-VERIFY-4: Negative schema tests for normative minimum payloads ----


class TestNegativePayloadSchemaValidation:
    """Verify that records with missing required payload fields produce ACEF-004."""

    def _make_record(self, record_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Build a record dict with all envelope-level required fields satisfied.

        Only the payload varies between tests, so payload-level ACEF-004
        diagnostics are isolated from envelope-level schema failures.
        """
        return {
            "record_id": "urn:acef:rec:00000000-0000-0000-0000-000000000001",
            "record_type": record_type,
            "provisions_addressed": ["article-9"],
            "timestamp": "2025-06-01T00:00:00Z",
            "lifecycle_phase": "deployment",
            "collector": {"name": "test-tool", "version": "1.0.0"},
            "obligation_role": "provider",
            "confidentiality": "public",
            "trust_level": "self-attested",
            "entity_refs": {
                "subject_refs": ["urn:acef:sub:00000000-0000-0000-0000-000000000001"],
                "component_refs": [],
                "dataset_refs": [],
                "actor_refs": [],
            },
            "payload": payload,
        }

    def test_event_log_without_event_type_fails_acef_004(self) -> None:
        """event_log payload without required 'event_type' must produce ACEF-004."""
        record = self._make_record("event_log", {"description": "missing event_type"})
        diagnostics = validate_record_schemas([record])
        # Filter to payload-level ACEF-004 (not envelope-level)
        payload_004 = [
            d for d in diagnostics
            if d.code == "ACEF-004" and "payload" in d.message.lower()
        ]
        assert len(payload_004) > 0, (
            "event_log without event_type must produce payload ACEF-004"
        )

    def test_transparency_marking_without_modality_fails_acef_004(self) -> None:
        """transparency_marking payload without 'modality' must produce ACEF-004."""
        record = self._make_record(
            "transparency_marking",
            {
                "marking_scheme_id": "c2pa-content-credentials",
                "scheme_version": "2.3",
                "metadata_container": "xmp/c2pa-manifest-store",
                "watermark_applied": True,
                # missing 'modality'
            },
        )
        diagnostics = validate_record_schemas([record])
        payload_004 = [
            d for d in diagnostics
            if d.code == "ACEF-004" and "payload" in d.message.lower()
        ]
        assert len(payload_004) > 0, (
            "transparency_marking without modality must produce payload ACEF-004"
        )

    def test_transparency_marking_without_marking_scheme_id_fails_acef_004(self) -> None:
        """transparency_marking without 'marking_scheme_id' must produce ACEF-004."""
        record = self._make_record(
            "transparency_marking",
            {
                "modality": "text",
                # missing marking_scheme_id
                "scheme_version": "2.3",
                "metadata_container": "xmp/c2pa-manifest-store",
                "watermark_applied": True,
            },
        )
        diagnostics = validate_record_schemas([record])
        payload_004 = [
            d for d in diagnostics
            if d.code == "ACEF-004" and "payload" in d.message.lower()
        ]
        assert len(payload_004) > 0, (
            "transparency_marking without marking_scheme_id must produce payload ACEF-004"
        )

    def test_disclosure_labeling_without_disclosure_subtype_fails_acef_004(self) -> None:
        """disclosure_labeling without 'disclosure_subtype' must produce ACEF-004."""
        record = self._make_record(
            "disclosure_labeling",
            {
                "label_type": "text",
                "presentation": "inline",
                "locale": "en",
                "disclosure_text": "AI-generated",
                "first_exposure_timestamp": "2025-06-01T00:00:00Z",
                # missing disclosure_subtype
            },
        )
        diagnostics = validate_record_schemas([record])
        payload_004 = [
            d for d in diagnostics
            if d.code == "ACEF-004" and "payload" in d.message.lower()
        ]
        assert len(payload_004) > 0, (
            "disclosure_labeling without disclosure_subtype must produce payload ACEF-004"
        )

    def test_valid_event_log_passes(self) -> None:
        """A valid event_log record should not produce any ACEF-004."""
        record = self._make_record("event_log", {
            "event_type": "inference",
            "description": "Test event",
        })
        diagnostics = validate_record_schemas([record])
        acef_004 = [d for d in diagnostics if d.code == "ACEF-004"]
        assert len(acef_004) == 0, (
            f"Valid event_log should not produce ACEF-004, got: "
            f"{[(d.code, d.message) for d in acef_004]}"
        )


# --- M-VERIFY-5: Variant registry conformance ----------------------------


class TestVariantRegistryConformance:
    """Verify variant-registry.json entries resolve to valid record types
    and that exists_where correctly matches variant discriminators."""

    def test_all_variant_entries_have_required_fields(self) -> None:
        """Every variant entry must have artifact_name, record_type,
        discriminator_field, and discriminator_value."""
        variants = load_variant_registry("v1")
        assert len(variants) > 0, "Variant registry must not be empty"

        for entry in variants:
            assert "artifact_name" in entry, f"Missing artifact_name: {entry}"
            assert "record_type" in entry, f"Missing record_type: {entry}"
            assert "discriminator_field" in entry, f"Missing discriminator_field: {entry}"
            assert "discriminator_value" in entry, f"Missing discriminator_value: {entry}"

    def test_variant_record_types_are_valid(self) -> None:
        """Every variant's record_type must correspond to a known ACEF record type."""
        from acef.models.enums import RECORD_TYPES

        variants = load_variant_registry("v1")
        for entry in variants:
            rt = entry["record_type"]
            assert rt in RECORD_TYPES, (
                f"Variant {entry['artifact_name']!r} references unknown "
                f"record_type {rt!r}"
            )

    def test_variant_discriminator_fields_are_json_pointers(self) -> None:
        """Every discriminator_field must be a valid JSON Pointer (starts with /)."""
        variants = load_variant_registry("v1")
        for entry in variants:
            field = entry["discriminator_field"]
            assert field.startswith("/"), (
                f"Variant {entry['artifact_name']!r} discriminator_field "
                f"{field!r} is not a valid JSON Pointer"
            )

    def test_exists_where_matches_variant_discriminator(self) -> None:
        """exists_where must correctly match a record that conforms to
        a variant's discriminator field/value."""
        # Pick 'management_review' variant: record_type=risk_register,
        # discriminator=/payload/review_type, value=management_review
        entry = resolve_variant("management_review", "v1")
        assert entry is not None

        record = RecordEnvelope(
            record_type=entry["record_type"],
            provisions_addressed=["article-9"],
            payload={
                "review_type": entry["discriminator_value"],
                "description": "Q1 management review",
                "likelihood": "medium",
                "severity": "medium",
            },
        )

        passed, refs = op_exists_where(
            {
                "record_type": entry["record_type"],
                "field": entry["discriminator_field"],
                "op": "eq",
                "value": entry["discriminator_value"],
                "min_count": 1,
            },
            [record],
        )
        assert passed is True, (
            f"exists_where must match record with discriminator "
            f"{entry['discriminator_field']}={entry['discriminator_value']!r}"
        )
        assert len(refs) == 1

    def test_exists_where_rejects_wrong_discriminator(self) -> None:
        """exists_where must fail when the discriminator value doesn't match."""
        entry = resolve_variant("management_review", "v1")
        assert entry is not None

        record = RecordEnvelope(
            record_type=entry["record_type"],
            provisions_addressed=["article-9"],
            payload={
                "review_type": "not_management_review",
                "description": "Wrong review type",
                "likelihood": "low",
                "severity": "low",
            },
        )

        passed, refs = op_exists_where(
            {
                "record_type": entry["record_type"],
                "field": entry["discriminator_field"],
                "op": "eq",
                "value": entry["discriminator_value"],
                "min_count": 1,
            },
            [record],
        )
        assert passed is False

    def test_all_variants_resolve(self) -> None:
        """Every artifact_name in the registry must be resolvable."""
        variants = load_variant_registry("v1")
        for entry in variants:
            resolved = resolve_variant(entry["artifact_name"], "v1")
            assert resolved is not None, (
                f"Variant {entry['artifact_name']!r} failed to resolve"
            )
            assert resolved["record_type"] == entry["record_type"]
