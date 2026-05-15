"""Tests for acef.merge — multi-source evidence merging with conflict detection."""

from __future__ import annotations

import pytest

from acef.errors import ACEFMergeError
from acef.merge import MergeResult, merge_packages
from acef.package import Package


def _make_package(
    name: str = "tool",
    version: str = "1.0",
    subject_name: str = "System A",
    subject_type: str = "ai_system",
    record_type: str = "risk_register",
    payload: dict | None = None,
) -> Package:
    """Helper to create a package for testing."""
    pkg = Package(producer={"name": name, "version": version})
    sub = pkg.add_subject(subject_type, name=subject_name)
    pkg.record(
        record_type,
        payload=payload or {"data": "value"},
        entity_refs={"subject_refs": [sub.id]},
    )
    return pkg


class TestMergeBasic:
    """Test basic merge operations."""

    def test_merge_two_packages(self):
        pkg1 = _make_package(subject_name="System A", payload={"a": 1})
        pkg2 = _make_package(subject_name="System B", payload={"b": 2})

        result = merge_packages([pkg1, pkg2])

        assert isinstance(result, MergeResult)
        assert len(result.package.subjects) == 2
        assert len(result.package.records) == 2
        assert not result.has_conflicts

    def test_merge_empty_raises(self):
        with pytest.raises(ACEFMergeError, match="No packages"):
            merge_packages([])

    def test_merge_single_package(self):
        pkg = _make_package()
        result = merge_packages([pkg])
        assert len(result.package.subjects) == 1
        assert len(result.package.records) == 1

    def test_merge_creates_audit_trail(self):
        pkg1 = _make_package(subject_name="A")
        pkg2 = _make_package(subject_name="B")
        result = merge_packages([pkg1, pkg2])
        manifest = result.package.build_manifest()
        merge_events = [
            e for e in manifest.audit_trail
            if "Merged" in e.description
        ]
        assert len(merge_events) >= 1


class TestDuplicateSubjects:
    """Test detection of duplicate subjects."""

    def test_duplicate_subject_detected(self):
        pkg1 = _make_package(subject_name="Same System")
        pkg2 = _make_package(subject_name="Same System")

        result = merge_packages([pkg1, pkg2])

        assert result.has_conflicts
        conflict_messages = [c.message for c in result.conflicts]
        assert any("Duplicate subject" in m for m in conflict_messages)


class TestDuplicateRecordIDs:
    """Test detection of duplicate record IDs."""

    def test_duplicate_record_id_detected(self):
        pkg1 = _make_package(subject_name="A")
        pkg2 = _make_package(subject_name="B")

        # Force same record ID
        pkg2._records[0].record_id = pkg1._records[0].record_id

        result = merge_packages([pkg1, pkg2])

        assert result.has_conflicts
        conflict_messages = [c.message for c in result.conflicts]
        assert any("Duplicate record_id" in m for m in conflict_messages)


class TestKeepLatestStrategy:
    """Test keep_latest conflict resolution strategy."""

    def test_keeps_later_on_duplicate_record(self):
        pkg1 = _make_package(subject_name="A", payload={"version": "old"})
        pkg2 = _make_package(subject_name="B", payload={"version": "new"})

        # Force same record ID
        shared_id = pkg1._records[0].record_id
        pkg2._records[0].record_id = shared_id

        result = merge_packages([pkg1, pkg2], conflict_strategy="keep_latest")

        # Should replace with the later one
        matching = [r for r in result.package.records if r.record_id == shared_id]
        assert len(matching) == 1
        assert matching[0].payload == {"version": "new"}

    def test_skips_duplicate_subject(self):
        pkg1 = _make_package(subject_name="Same")
        pkg2 = _make_package(subject_name="Same")

        result = merge_packages([pkg1, pkg2], conflict_strategy="keep_latest")
        # Should only have one subject with that name
        assert len(result.package.subjects) == 1


class TestKeepAllStrategy:
    """Test keep_all conflict resolution strategy."""

    def test_keeps_both_duplicate_records(self):
        pkg1 = _make_package(subject_name="A", payload={"v": 1})
        pkg2 = _make_package(subject_name="B", payload={"v": 2})

        # Force same record ID
        shared_id = pkg1._records[0].record_id
        pkg2._records[0].record_id = shared_id

        result = merge_packages([pkg1, pkg2], conflict_strategy="keep_all")

        matching = [r for r in result.package.records if r.record_id == shared_id]
        assert len(matching) == 2


class TestFailStrategy:
    """Test fail conflict resolution strategy."""

    def test_raises_on_duplicate_subject(self):
        pkg1 = _make_package(subject_name="Same")
        pkg2 = _make_package(subject_name="Same")

        with pytest.raises(ACEFMergeError, match="Conflict"):
            merge_packages([pkg1, pkg2], conflict_strategy="fail")

    def test_raises_on_duplicate_record(self):
        pkg1 = _make_package(subject_name="A")
        pkg2 = _make_package(subject_name="B")
        pkg2._records[0].record_id = pkg1._records[0].record_id

        with pytest.raises(ACEFMergeError, match="Conflict"):
            merge_packages([pkg1, pkg2], conflict_strategy="fail")


class TestMergeEntities:
    """Test that entities are properly merged."""

    def test_components_merged(self):
        pkg1 = _make_package(subject_name="A")
        pkg1.add_component(name="Model", type="model")
        pkg2 = _make_package(subject_name="B")
        pkg2.add_component(name="Guard", type="guardrail")

        result = merge_packages([pkg1, pkg2])
        assert len(result.package.entities.components) == 2

    def test_profiles_deduplicated(self):
        pkg1 = _make_package(subject_name="A")
        pkg1.add_profile("eu-ai-act", provisions=["article-9"])
        pkg2 = _make_package(subject_name="B")
        pkg2.add_profile("eu-ai-act", provisions=["article-10"])

        result = merge_packages([pkg1, pkg2])
        profiles = result.package.profiles
        profile_ids = [p.profile_id for p in profiles]
        assert profile_ids.count("eu-ai-act") == 1
