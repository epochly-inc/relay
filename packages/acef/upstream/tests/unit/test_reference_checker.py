"""Tests for acef.validation.reference_checker — referential integrity checks."""

from __future__ import annotations

import json
from pathlib import Path

from acef.validation.reference_checker import check_references


def _make_manifest(
    subjects: list[dict] | None = None,
    components: list[dict] | None = None,
    datasets: list[dict] | None = None,
    actors: list[dict] | None = None,
    relationships: list[dict] | None = None,
    record_files: list[dict] | None = None,
) -> dict:
    """Helper to create a manifest dict."""
    return {
        "metadata": {"package_id": "urn:acef:pkg:00000000-0000-0000-0000-000000000001"},
        "subjects": subjects or [],
        "entities": {
            "components": components or [],
            "datasets": datasets or [],
            "actors": actors or [],
            "relationships": relationships or [],
        },
        "record_files": record_files or [],
    }


class TestDanglingEntityRefs:
    """Test ACEF-020: Dangling entity_refs."""

    def test_no_errors_with_valid_refs(self):
        manifest = _make_manifest(
            subjects=[{"subject_id": "urn:acef:sub:00000000-0000-0000-0000-000000000001"}],
        )
        records = [{
            "record_id": "urn:acef:rec:00000000-0000-0000-0000-000000000001",
            "record_type": "risk_register",
            "entity_refs": {
                "subject_refs": ["urn:acef:sub:00000000-0000-0000-0000-000000000001"],
                "component_refs": [],
                "dataset_refs": [],
                "actor_refs": [],
            },
        }]
        diags = check_references(manifest, records)
        acef_020 = [d for d in diags if d.code == "ACEF-020"]
        assert len(acef_020) == 0

    def test_dangling_subject_ref(self):
        manifest = _make_manifest()
        records = [{
            "record_id": "urn:acef:rec:00000000-0000-0000-0000-000000000001",
            "record_type": "risk_register",
            "entity_refs": {
                "subject_refs": ["urn:acef:sub:99999999-9999-9999-9999-999999999999"],
                "component_refs": [],
                "dataset_refs": [],
                "actor_refs": [],
            },
        }]
        diags = check_references(manifest, records)
        acef_020 = [d for d in diags if d.code == "ACEF-020"]
        assert len(acef_020) >= 1

    def test_dangling_relationship_ref(self):
        manifest = _make_manifest(
            subjects=[{"subject_id": "urn:acef:sub:00000000-0000-0000-0000-000000000001"}],
            relationships=[{
                "source_ref": "urn:acef:sub:00000000-0000-0000-0000-000000000001",
                "target_ref": "urn:acef:sub:99999999-9999-9999-9999-999999999999",
                "relationship_type": "wraps",
            }],
        )
        diags = check_references(manifest, [])
        acef_020 = [d for d in diags if d.code == "ACEF-020"]
        assert len(acef_020) >= 1


class TestDuplicateURNs:
    """Test ACEF-021: Duplicate URNs."""

    def test_duplicate_subject_urns(self):
        urn = "urn:acef:sub:00000000-0000-0000-0000-000000000001"
        manifest = _make_manifest(
            subjects=[
                {"subject_id": urn},
                {"subject_id": urn},
            ],
        )
        diags = check_references(manifest, [])
        acef_021 = [d for d in diags if d.code == "ACEF-021"]
        assert len(acef_021) >= 1

    def test_no_duplicate_with_unique_urns(self):
        manifest = _make_manifest(
            subjects=[
                {"subject_id": "urn:acef:sub:00000000-0000-0000-0000-000000000001"},
                {"subject_id": "urn:acef:sub:00000000-0000-0000-0000-000000000002"},
            ],
        )
        diags = check_references(manifest, [])
        acef_021 = [d for d in diags if d.code == "ACEF-021"]
        assert len(acef_021) == 0


class TestMissingRecordFiles:
    """Test ACEF-022: Missing record files."""

    def test_missing_record_file(self, tmp_dir: Path):
        manifest = _make_manifest(
            record_files=[{
                "path": "records/risk_register.jsonl",
                "record_type": "risk_register",
                "count": 1,
            }],
        )
        # Don't create the file
        diags = check_references(manifest, [], bundle_dir=tmp_dir)
        acef_022 = [d for d in diags if d.code == "ACEF-022"]
        assert len(acef_022) >= 1

    def test_existing_record_file(self, tmp_dir: Path):
        records_dir = tmp_dir / "records"
        records_dir.mkdir()
        (records_dir / "risk_register.jsonl").write_text("{}\n", encoding="utf-8")

        manifest = _make_manifest(
            record_files=[{
                "path": "records/risk_register.jsonl",
                "record_type": "risk_register",
                "count": 1,
            }],
        )
        diags = check_references(manifest, [{"record_type": "risk_register"}], bundle_dir=tmp_dir)
        acef_022 = [d for d in diags if d.code == "ACEF-022"]
        assert len(acef_022) == 0


class TestDuplicateRecordIDs:
    """Test ACEF-026: Duplicate record IDs."""

    def test_duplicate_record_ids(self):
        rec_id = "urn:acef:rec:00000000-0000-0000-0000-000000000001"
        manifest = _make_manifest()
        records = [
            {"record_id": rec_id, "record_type": "risk_register", "entity_refs": {}},
            {"record_id": rec_id, "record_type": "risk_register", "entity_refs": {}},
        ]
        diags = check_references(manifest, records)
        acef_026 = [d for d in diags if d.code == "ACEF-026"]
        assert len(acef_026) >= 1

    def test_unique_record_ids(self):
        manifest = _make_manifest()
        records = [
            {"record_id": "urn:acef:rec:00000000-0000-0000-0000-000000000001",
             "record_type": "risk_register", "entity_refs": {}},
            {"record_id": "urn:acef:rec:00000000-0000-0000-0000-000000000002",
             "record_type": "risk_register", "entity_refs": {}},
        ]
        diags = check_references(manifest, records)
        acef_026 = [d for d in diags if d.code == "ACEF-026"]
        assert len(acef_026) == 0


class TestRecordCountMismatches:
    """Test ACEF-025: Record count mismatches."""

    def test_count_mismatch(self):
        manifest = _make_manifest(
            record_files=[{
                "path": "records/risk_register.jsonl",
                "record_type": "risk_register",
                "count": 5,
            }],
        )
        records = [
            {"record_type": "risk_register", "record_id": f"rec-{i}", "entity_refs": {}}
            for i in range(3)
        ]
        diags = check_references(manifest, records)
        acef_025 = [d for d in diags if d.code == "ACEF-025"]
        assert len(acef_025) >= 1

    def test_count_matches(self):
        manifest = _make_manifest(
            record_files=[{
                "path": "records/risk_register.jsonl",
                "record_type": "risk_register",
                "count": 2,
            }],
        )
        records = [
            {"record_type": "risk_register", "record_id": f"rec-{i}", "entity_refs": {}}
            for i in range(2)
        ]
        diags = check_references(manifest, records)
        acef_025 = [d for d in diags if d.code == "ACEF-025"]
        assert len(acef_025) == 0


class TestComponentSubjectRefs:
    """Test dangling subject_refs on components and datasets."""

    def test_dangling_component_subject_ref(self):
        manifest = _make_manifest(
            components=[{
                "component_id": "urn:acef:cmp:00000000-0000-0000-0000-000000000001",
                "name": "Model",
                "type": "model",
                "subject_refs": ["urn:acef:sub:99999999-9999-9999-9999-999999999999"],
            }],
        )
        diags = check_references(manifest, [])
        acef_020 = [d for d in diags if d.code == "ACEF-020"]
        assert len(acef_020) >= 1
