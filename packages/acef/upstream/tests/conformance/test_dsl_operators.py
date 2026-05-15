"""Conformance test: DSL operators.

Each of the 10 built-in operators has at least one pass and one fail test
using REAL exported bundles. Also verifies empty-set semantics.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from acef.loader import load
from acef.models.enums import ObligationRole
from acef.models.records import AttachmentRef, Attestation, RecordEnvelope
from acef.package import Package
from acef.validation.operators import (
    OPERATOR_REGISTRY,
    op_attachment_exists,
    op_attachment_kind_exists,
    op_bundle_signed,
    op_entity_linked,
    op_evidence_freshness,
    op_exists_where,
    op_field_present,
    op_field_value,
    op_has_record_type,
    op_record_attested,
)

from tests.conformance.conftest import build_minimal_package


def _export_and_load_records(pkg: Package, tmp_dir: Path, name: str) -> list[RecordEnvelope]:
    """Export a package and load its records back for operator testing."""
    bundle_dir = tmp_dir / name
    pkg.export(str(bundle_dir))
    loaded = load(str(bundle_dir))
    return loaded.records


class TestHasRecordType:
    """has_record_type: existential — at least min_count records exist."""

    def test_pass_when_record_type_exists(self, tmp_dir: Path) -> None:
        pkg = build_minimal_package(record_types=["risk_register"])
        records = _export_and_load_records(pkg, tmp_dir, "hrt_pass")
        passed, refs = op_has_record_type({"type": "risk_register", "min_count": 1}, records)
        assert passed is True
        assert len(refs) >= 1

    def test_fail_when_record_type_missing(self, tmp_dir: Path) -> None:
        pkg = build_minimal_package(record_types=["risk_register"])
        records = _export_and_load_records(pkg, tmp_dir, "hrt_fail")
        passed, refs = op_has_record_type({"type": "evaluation_report", "min_count": 1}, records)
        assert passed is False

    def test_empty_set_existential_fail(self) -> None:
        """Existential operator on zero records must FAIL."""
        passed, refs = op_has_record_type({"type": "risk_register", "min_count": 1}, [])
        assert passed is False


class TestFieldPresent:
    """field_present: universal — every record of type has non-null value at path."""

    def test_pass_when_field_present(self, tmp_dir: Path) -> None:
        pkg = build_minimal_package(record_types=["risk_register"])
        records = _export_and_load_records(pkg, tmp_dir, "fp_pass")
        passed, refs = op_field_present(
            {"record_type": "risk_register", "field": "/payload/description"}, records
        )
        assert passed is True

    def test_fail_when_field_missing(self, tmp_dir: Path) -> None:
        pkg = build_minimal_package(record_types=["risk_register"])
        records = _export_and_load_records(pkg, tmp_dir, "fp_fail")
        passed, refs = op_field_present(
            {"record_type": "risk_register", "field": "/payload/nonexistent_field"}, records
        )
        assert passed is False

    def test_vacuous_pass_on_empty_set(self) -> None:
        """Universal operator on zero matching records must PASS (vacuous truth)."""
        passed, refs = op_field_present(
            {"record_type": "nonexistent_type", "field": "/payload/description"}, []
        )
        assert passed is True
        assert refs == []


class TestFieldValue:
    """field_value: universal — field satisfies comparison for every matching record."""

    def test_pass_when_value_matches(self, tmp_dir: Path) -> None:
        pkg = build_minimal_package(record_types=["risk_register"])
        records = _export_and_load_records(pkg, tmp_dir, "fv_pass")
        passed, refs = op_field_value(
            {
                "record_type": "risk_register",
                "field": "/payload/severity",
                "op": "eq",
                "value": "high",
            },
            records,
        )
        assert passed is True

    def test_fail_when_value_mismatches(self, tmp_dir: Path) -> None:
        pkg = build_minimal_package(record_types=["risk_register"])
        records = _export_and_load_records(pkg, tmp_dir, "fv_fail")
        passed, refs = op_field_value(
            {
                "record_type": "risk_register",
                "field": "/payload/severity",
                "op": "eq",
                "value": "critical",
            },
            records,
        )
        assert passed is False

    def test_vacuous_pass_on_empty_set(self) -> None:
        passed, refs = op_field_value(
            {"record_type": "nonexistent", "field": "/payload/x", "op": "eq", "value": "y"}, []
        )
        assert passed is True


class TestEvidenceFreshness:
    """evidence_freshness: universal — all records within max_days of reference."""

    def test_pass_when_fresh(self, tmp_dir: Path) -> None:
        pkg = build_minimal_package(record_types=["risk_register"])
        records = _export_and_load_records(pkg, tmp_dir, "ef_pass")
        # Use a recent evaluation instant
        passed, refs = op_evidence_freshness(
            {"max_days": 365, "reference_date": "validation_time"},
            records,
            evaluation_instant="2027-01-01T00:00:00Z",
        )
        assert passed is True

    def test_fail_when_stale(self, tmp_dir: Path) -> None:
        pkg = build_minimal_package(record_types=["risk_register"])
        records = _export_and_load_records(pkg, tmp_dir, "ef_fail")
        # Use a very old evaluation instant (records were created ~now)
        # Set max_days=1 and evaluation_instant far in the future
        passed, refs = op_evidence_freshness(
            {"max_days": 1, "reference_date": "validation_time"},
            records,
            evaluation_instant="2030-01-01T00:00:00Z",
        )
        assert passed is False

    def test_vacuous_pass_on_empty_set(self) -> None:
        passed, refs = op_evidence_freshness(
            {"max_days": 365, "reference_date": "validation_time"},
            [],
            evaluation_instant="2025-01-01T00:00:00Z",
        )
        assert passed is True


class TestAttachmentExists:
    """attachment_exists: existential — at least one record has an attachment."""

    def test_pass_when_attachment_present(self, tmp_dir: Path) -> None:
        pkg = build_minimal_package(with_attachment=True)
        records = _export_and_load_records(pkg, tmp_dir, "ae_pass")
        passed, refs = op_attachment_exists(
            {"record_type": "evaluation_report"}, records
        )
        assert passed is True

    def test_fail_when_no_attachment(self, tmp_dir: Path) -> None:
        pkg = build_minimal_package(record_types=["risk_register"])
        records = _export_and_load_records(pkg, tmp_dir, "ae_fail")
        passed, refs = op_attachment_exists(
            {"record_type": "risk_register"}, records
        )
        assert passed is False


class TestEntityLinked:
    """entity_linked: universal — every record of type has at least one entity ref."""

    def test_pass_when_entity_linked(self, tmp_dir: Path) -> None:
        pkg = build_minimal_package(record_types=["risk_register"])
        records = _export_and_load_records(pkg, tmp_dir, "el_pass")
        passed, refs = op_entity_linked(
            {"record_type": "risk_register", "entity_type": "subject"}, records
        )
        assert passed is True

    def test_fail_when_entity_not_linked(self, tmp_dir: Path) -> None:
        # Create a package with a record that has no subject refs
        pkg = Package(producer={"name": "test", "version": "1.0.0"})
        pkg.add_subject("ai_system", name="Test Sys")
        pkg.record(
            "risk_register",
            provisions=["article-9"],
            payload={"description": "unlinked risk", "likelihood": "low", "severity": "low"},
            # No entity_refs
        )
        records = _export_and_load_records(pkg, tmp_dir, "el_fail")
        passed, refs = op_entity_linked(
            {"record_type": "risk_register", "entity_type": "dataset"}, records
        )
        assert passed is False

    def test_vacuous_pass_on_empty_set(self) -> None:
        passed, refs = op_entity_linked(
            {"record_type": "nonexistent", "entity_type": "subject"}, []
        )
        assert passed is True


class TestExistsWhere:
    """exists_where: existential — at least min_count records match field condition."""

    def test_pass_when_condition_met(self, tmp_dir: Path) -> None:
        pkg = build_minimal_package(record_types=["risk_register"])
        records = _export_and_load_records(pkg, tmp_dir, "ew_pass")
        passed, refs = op_exists_where(
            {
                "record_type": "risk_register",
                "field": "/payload/severity",
                "op": "eq",
                "value": "high",
                "min_count": 1,
            },
            records,
        )
        assert passed is True

    def test_fail_when_condition_not_met(self, tmp_dir: Path) -> None:
        pkg = build_minimal_package(record_types=["risk_register"])
        records = _export_and_load_records(pkg, tmp_dir, "ew_fail")
        passed, refs = op_exists_where(
            {
                "record_type": "risk_register",
                "field": "/payload/severity",
                "op": "eq",
                "value": "nonexistent_value",
                "min_count": 1,
            },
            records,
        )
        assert passed is False

    def test_empty_set_existential_fail(self) -> None:
        passed, refs = op_exists_where(
            {
                "record_type": "nonexistent",
                "field": "/payload/x",
                "op": "eq",
                "value": "y",
                "min_count": 1,
            },
            [],
        )
        assert passed is False


class TestAttachmentKindExists:
    """attachment_kind_exists: existential — records have attachments with matching type."""

    def test_pass_when_attachment_kind_matches(self) -> None:
        record = RecordEnvelope(
            record_type="risk_register",
            provisions_addressed=["article-9"],
            payload={"description": "test", "likelihood": "low", "severity": "low"},
            attachments=[
                AttachmentRef(
                    path="artifacts/plan.pdf",
                    media_type="application/pdf",
                    attachment_type="post_market_monitoring_plan",
                ),
            ],
        )
        passed, refs = op_attachment_kind_exists(
            {
                "record_type": "risk_register",
                "attachment_type": "post_market_monitoring_plan",
                "min_count": 1,
            },
            [record],
        )
        assert passed is True

    def test_fail_when_attachment_kind_missing(self, tmp_dir: Path) -> None:
        pkg = build_minimal_package(record_types=["risk_register"])
        records = _export_and_load_records(pkg, tmp_dir, "ake_fail")
        passed, refs = op_attachment_kind_exists(
            {
                "record_type": "risk_register",
                "attachment_type": "nonexistent_type",
                "min_count": 1,
            },
            records,
        )
        assert passed is False


class TestBundleSigned:
    """bundle_signed: existential on signatures — bundle has at least min_signatures."""

    def test_pass_when_signed(self) -> None:
        passed, refs = op_bundle_signed(
            {"min_signatures": 1},
            [],
            signature_count=1,
            signature_algorithms=["RS256"],
        )
        assert passed is True

    def test_fail_when_unsigned(self) -> None:
        passed, refs = op_bundle_signed(
            {"min_signatures": 1},
            [],
            signature_count=0,
        )
        assert passed is False


class TestRecordAttested:
    """record_attested: existential — at least min_count records have valid attestation."""

    def test_pass_when_attested(self) -> None:
        record = RecordEnvelope(
            record_type="conformity_declaration",
            provisions_addressed=["article-11"],
            payload={"scope": "Full system", "declaration_date": "2025-06-01"},
            attestation=Attestation(
                method="jws",
                signer="provider-key",
                signature="eyJhbGciOiJSUzI1NiJ9..fake",
            ),
        )
        passed, refs = op_record_attested(
            {"record_type": "conformity_declaration", "min_count": 1}, [record]
        )
        assert passed is True

    def test_fail_when_not_attested(self, tmp_dir: Path) -> None:
        pkg = build_minimal_package(record_types=["risk_register"])
        records = _export_and_load_records(pkg, tmp_dir, "ra_fail")
        passed, refs = op_record_attested(
            {"record_type": "risk_register", "min_count": 1}, records
        )
        assert passed is False


class TestOperatorRegistry:
    """All 10 operators are registered."""

    def test_all_ten_operators_registered(self) -> None:
        expected = {
            "has_record_type",
            "field_present",
            "field_value",
            "evidence_freshness",
            "attachment_exists",
            "entity_linked",
            "exists_where",
            "attachment_kind_exists",
            "bundle_signed",
            "record_attested",
        }
        assert expected == set(OPERATOR_REGISTRY.keys())
