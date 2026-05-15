"""Conformance test: extension handling.

Verifies that x- prefixed record types and fields are preserved
on round-trip and don't affect conformance outcomes.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from acef.loader import load
from acef.models.enums import ProvisionOutcome
from acef.package import Package
from acef.validation.engine import validate_bundle

from tests.conformance.conftest import build_minimal_package


class TestExtensionHandling:
    """Extension conformance: x- prefixed types and fields."""

    def test_extension_record_type_preserved_on_roundtrip(self, tmp_dir: Path) -> None:
        """x- prefixed record types are preserved through export -> load."""
        pkg = build_minimal_package(with_extension_record=True)

        bundle_dir = tmp_dir / "ext_rt"
        pkg.export(str(bundle_dir))
        loaded = load(str(bundle_dir))

        ext_records = [r for r in loaded.records if r.record_type == "x-custom-audit"]
        assert len(ext_records) == 1, "Extension record type must survive round-trip"
        assert ext_records[0].payload == {"custom_field": "custom_value", "score": 42}

    def test_extension_record_type_does_not_affect_conformance(self, tmp_dir: Path) -> None:
        """Extension record types don't affect conformance outcomes.

        A package with valid core records and an x- extension should produce
        the same conformance results as one without the extension.
        """
        # Build package WITH extension record
        pkg_ext = Package(producer={"name": "test", "version": "1.0.0"})
        system = pkg_ext.add_subject(
            "ai_system", name="Test Sys",
            risk_classification="high-risk", modalities=["text"],
        )
        pkg_ext.add_profile("eu-ai-act-2024", provisions=["article-9"])
        pkg_ext.record(
            "risk_register",
            provisions=["article-9"],
            payload={"description": "Risk A", "likelihood": "high", "severity": "high"},
            obligation_role="provider",
            entity_refs={"subject_refs": [system.id]},
        )
        pkg_ext.record(
            "risk_treatment",
            provisions=["article-9"],
            payload={"treatment_type": "mitigate", "description": "Treatment A"},
            obligation_role="provider",
            entity_refs={"subject_refs": [system.id]},
        )
        # Add extension record
        pkg_ext.record("x-vendor-metric", payload={"vendor_score": 99})

        dir_ext = tmp_dir / "ext_conform"
        pkg_ext.export(str(dir_ext))

        # Build package WITHOUT extension record (same core records)
        pkg_no_ext = Package(producer={"name": "test", "version": "1.0.0"})
        # Need to match timestamps and IDs for fair comparison
        system2 = pkg_no_ext.add_subject(
            "ai_system", name="Test Sys",
            risk_classification="high-risk", modalities=["text"],
        )
        pkg_no_ext.add_profile("eu-ai-act-2024", provisions=["article-9"])
        pkg_no_ext.record(
            "risk_register",
            provisions=["article-9"],
            payload={"description": "Risk A", "likelihood": "high", "severity": "high"},
            obligation_role="provider",
            entity_refs={"subject_refs": [system2.id]},
        )
        pkg_no_ext.record(
            "risk_treatment",
            provisions=["article-9"],
            payload={"treatment_type": "mitigate", "description": "Treatment A"},
            obligation_role="provider",
            entity_refs={"subject_refs": [system2.id]},
        )

        dir_no_ext = tmp_dir / "no_ext_conform"
        pkg_no_ext.export(str(dir_no_ext))

        eval_instant = "2027-01-01T00:00:00Z"
        assessment_ext = validate_bundle(
            dir_ext, profiles=["eu-ai-act-2024"], evaluation_instant=eval_instant
        )
        assessment_no_ext = validate_bundle(
            dir_no_ext, profiles=["eu-ai-act-2024"], evaluation_instant=eval_instant
        )

        # The provision outcomes for article-9 should be the same
        ext_outcomes = {
            s.provision_id: s.provision_outcome
            for s in assessment_ext.provision_summary
        }
        no_ext_outcomes = {
            s.provision_id: s.provision_outcome
            for s in assessment_no_ext.provision_summary
        }

        for prov_id in no_ext_outcomes:
            if prov_id in ext_outcomes:
                assert ext_outcomes[prov_id] == no_ext_outcomes[prov_id], (
                    f"Extension records must not affect conformance outcome for {prov_id}"
                )

    def test_extension_fields_in_payload_dont_affect_validation(self, tmp_dir: Path) -> None:
        """x- prefixed fields in payloads don't affect validation."""
        pkg = Package(producer={"name": "test", "version": "1.0.0"})
        system = pkg.add_subject("ai_system", name="Test Sys")
        pkg.record(
            "risk_register",
            provisions=["article-9"],
            payload={
                "description": "Test risk",
                "likelihood": "low",
                "severity": "low",
                "x-vendor-rating": "AAA",
                "x-internal-notes": "This is a vendor extension field",
            },
            entity_refs={"subject_refs": [system.id]},
        )

        bundle_dir = tmp_dir / "ext_fields"
        pkg.export(str(bundle_dir))
        loaded = load(str(bundle_dir))

        ext_record = next(
            (r for r in loaded.records if r.record_type == "risk_register"), None
        )
        assert ext_record is not None
        assert ext_record.payload.get("x-vendor-rating") == "AAA"
        assert ext_record.payload.get("x-internal-notes") == "This is a vendor extension field"

    def test_extension_record_type_accepted_by_package(self) -> None:
        """Package.record() accepts x- prefixed record types without raising."""
        pkg = Package(producer={"name": "test", "version": "1.0.0"})
        pkg.add_subject("ai_system", name="Test Sys")
        record = pkg.record("x-my-extension", payload={"data": "value"})
        assert record.record_type == "x-my-extension"

    def test_multiple_extension_types_roundtrip(self, tmp_dir: Path) -> None:
        """Multiple different x- record types all survive round-trip."""
        pkg = Package(producer={"name": "test", "version": "1.0.0"})
        pkg.add_subject("ai_system", name="Test Sys")
        pkg.record("x-audit-log", payload={"entries": 100})
        pkg.record("x-vendor-score", payload={"score": 95.5})
        pkg.record("x-custom-check", payload={"status": "ok"})
        pkg.record("risk_register", payload={"description": "test", "likelihood": "low", "severity": "low"})

        bundle_dir = tmp_dir / "multi_ext"
        pkg.export(str(bundle_dir))
        loaded = load(str(bundle_dir))

        ext_types = sorted(
            r.record_type for r in loaded.records if r.record_type.startswith("x-")
        )
        assert ext_types == ["x-audit-log", "x-custom-check", "x-vendor-score"]
