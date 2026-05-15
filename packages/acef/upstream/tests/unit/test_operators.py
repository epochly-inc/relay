"""Tests for acef.validation.operators — all 10 DSL operators with pass/fail and empty-set."""

from __future__ import annotations

import pytest

from acef.errors import ACEFEvaluationError
from acef.models.enums import Confidentiality, ObligationRole, TrustLevel
from acef.models.records import AttachmentRef, Attestation, EntityRefs, RecordEnvelope
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


def _make_record(
    record_type: str = "risk_register",
    payload: dict | None = None,
    subject_refs: list[str] | None = None,
    component_refs: list[str] | None = None,
    dataset_refs: list[str] | None = None,
    actor_refs: list[str] | None = None,
    attachments: list[AttachmentRef] | None = None,
    attestation: Attestation | None = None,
    obligation_role: ObligationRole | None = None,
    timestamp: str = "2025-06-01T00:00:00Z",
    record_id: str | None = None,
) -> RecordEnvelope:
    """Helper to create test records."""
    rec = RecordEnvelope(
        record_type=record_type,
        payload=payload or {},
        entity_refs=EntityRefs(
            subject_refs=subject_refs or [],
            component_refs=component_refs or [],
            dataset_refs=dataset_refs or [],
            actor_refs=actor_refs or [],
        ),
        attachments=attachments or [],
        attestation=attestation,
        obligation_role=obligation_role,
        timestamp=timestamp,
    )
    if record_id:
        rec.record_id = record_id
    return rec


class TestOperatorRegistry:
    """Verify all 10 operators registered."""

    def test_all_10_operators(self):
        expected = {
            "has_record_type", "field_present", "field_value",
            "evidence_freshness", "attachment_exists", "entity_linked",
            "exists_where", "attachment_kind_exists", "bundle_signed",
            "record_attested",
        }
        assert set(OPERATOR_REGISTRY.keys()) == expected


class TestHasRecordType:
    """has_record_type: Existential operator."""

    def test_pass_with_matching_records(self):
        records = [_make_record("risk_register")]
        passed, refs = op_has_record_type({"type": "risk_register"}, records)
        assert passed
        assert len(refs) == 1

    def test_fail_no_matching_records(self):
        records = [_make_record("dataset_card")]
        passed, refs = op_has_record_type({"type": "risk_register"}, records)
        assert not passed
        assert refs == []

    def test_fail_empty_records(self):
        passed, refs = op_has_record_type({"type": "risk_register", "min_count": 1}, [])
        assert not passed

    def test_min_count(self):
        records = [_make_record("risk_register")]
        passed, _ = op_has_record_type({"type": "risk_register", "min_count": 2}, records)
        assert not passed

    def test_min_count_satisfied(self):
        records = [_make_record("risk_register"), _make_record("risk_register")]
        passed, refs = op_has_record_type({"type": "risk_register", "min_count": 2}, records)
        assert passed
        assert len(refs) == 2


class TestFieldPresent:
    """field_present: Universal operator — vacuous truth on empty set."""

    def test_pass_field_exists(self):
        records = [_make_record("risk_register", payload={"description": "risk"})]
        passed, refs = op_field_present(
            {"record_type": "risk_register", "field": "/payload/description"}, records
        )
        assert passed
        assert len(refs) == 1

    def test_fail_field_missing(self):
        records = [_make_record("risk_register", payload={})]
        passed, refs = op_field_present(
            {"record_type": "risk_register", "field": "/payload/description"}, records
        )
        assert not passed

    def test_vacuous_truth_empty_set(self):
        passed, refs = op_field_present(
            {"record_type": "risk_register", "field": "/payload/description"}, []
        )
        assert passed
        assert refs == []

    def test_vacuous_truth_no_matching_type(self):
        records = [_make_record("dataset_card")]
        passed, refs = op_field_present(
            {"record_type": "risk_register", "field": "/payload/description"}, records
        )
        assert passed
        assert refs == []


class TestFieldValue:
    """field_value: Universal operator with comparison operations."""

    def test_eq_pass(self):
        records = [_make_record("risk_register", payload={"severity": "high"})]
        passed, _ = op_field_value(
            {"record_type": "risk_register", "field": "/payload/severity",
             "op": "eq", "value": "high"}, records
        )
        assert passed

    def test_eq_fail(self):
        records = [_make_record("risk_register", payload={"severity": "low"})]
        passed, _ = op_field_value(
            {"record_type": "risk_register", "field": "/payload/severity",
             "op": "eq", "value": "high"}, records
        )
        assert not passed

    def test_ne_pass(self):
        records = [_make_record("risk_register", payload={"severity": "low"})]
        passed, _ = op_field_value(
            {"record_type": "risk_register", "field": "/payload/severity",
             "op": "ne", "value": "high"}, records
        )
        assert passed

    def test_gt_pass(self):
        records = [_make_record("risk_register", payload={"score": 80})]
        passed, _ = op_field_value(
            {"record_type": "risk_register", "field": "/payload/score",
             "op": "gt", "value": 70}, records
        )
        assert passed

    def test_gt_fail(self):
        records = [_make_record("risk_register", payload={"score": 50})]
        passed, _ = op_field_value(
            {"record_type": "risk_register", "field": "/payload/score",
             "op": "gt", "value": 70}, records
        )
        assert not passed

    def test_gte_pass(self):
        records = [_make_record("risk_register", payload={"score": 70})]
        passed, _ = op_field_value(
            {"record_type": "risk_register", "field": "/payload/score",
             "op": "gte", "value": 70}, records
        )
        assert passed

    def test_lt_pass(self):
        records = [_make_record("risk_register", payload={"score": 30})]
        passed, _ = op_field_value(
            {"record_type": "risk_register", "field": "/payload/score",
             "op": "lt", "value": 50}, records
        )
        assert passed

    def test_lte_pass(self):
        records = [_make_record("risk_register", payload={"score": 50})]
        passed, _ = op_field_value(
            {"record_type": "risk_register", "field": "/payload/score",
             "op": "lte", "value": 50}, records
        )
        assert passed

    def test_in_pass(self):
        records = [_make_record("risk_register", payload={"severity": "high"})]
        passed, _ = op_field_value(
            {"record_type": "risk_register", "field": "/payload/severity",
             "op": "in", "value": ["high", "critical"]}, records
        )
        assert passed

    def test_in_fail(self):
        records = [_make_record("risk_register", payload={"severity": "low"})]
        passed, _ = op_field_value(
            {"record_type": "risk_register", "field": "/payload/severity",
             "op": "in", "value": ["high", "critical"]}, records
        )
        assert not passed

    def test_regex_pass(self):
        records = [_make_record("risk_register", payload={"name": "Model-v2.3"})]
        passed, _ = op_field_value(
            {"record_type": "risk_register", "field": "/payload/name",
             "op": "regex", "value": r"Model-v\d+\.\d+"}, records
        )
        assert passed

    def test_regex_fail(self):
        records = [_make_record("risk_register", payload={"name": "Other"})]
        passed, _ = op_field_value(
            {"record_type": "risk_register", "field": "/payload/name",
             "op": "regex", "value": r"^Model-"}, records
        )
        assert not passed

    def test_invalid_regex_raises_acef_045(self):
        records = [_make_record("risk_register", payload={"name": "test"})]
        with pytest.raises(ACEFEvaluationError) as exc_info:
            op_field_value(
                {"record_type": "risk_register", "field": "/payload/name",
                 "op": "regex", "value": "[invalid("}, records
            )
        assert exc_info.value.code == "ACEF-045"

    def test_vacuous_truth_empty(self):
        passed, _ = op_field_value(
            {"record_type": "risk_register", "field": "/payload/x",
             "op": "eq", "value": 1}, []
        )
        assert passed

    def test_missing_path_ne_true(self):
        records = [_make_record("risk_register", payload={})]
        passed, _ = op_field_value(
            {"record_type": "risk_register", "field": "/payload/missing",
             "op": "ne", "value": "anything"}, records
        )
        assert passed

    def test_missing_path_eq_false(self):
        records = [_make_record("risk_register", payload={})]
        passed, _ = op_field_value(
            {"record_type": "risk_register", "field": "/payload/missing",
             "op": "eq", "value": "anything"}, records
        )
        assert not passed


class TestEvidenceFreshness:
    """evidence_freshness: Universal operator."""

    def test_pass_within_window(self):
        records = [_make_record("risk_register", timestamp="2025-06-01T00:00:00Z")]
        passed, _ = op_evidence_freshness(
            {"max_days": 365},
            records,
            evaluation_instant="2025-06-15T00:00:00Z",
        )
        assert passed

    def test_fail_outside_window(self):
        records = [_make_record("risk_register", timestamp="2020-01-01T00:00:00Z")]
        passed, _ = op_evidence_freshness(
            {"max_days": 30},
            records,
            evaluation_instant="2025-06-01T00:00:00Z",
        )
        assert not passed

    def test_vacuous_truth_empty(self):
        passed, _ = op_evidence_freshness(
            {"max_days": 30}, [], evaluation_instant="2025-01-01T00:00:00Z"
        )
        assert passed


class TestAttachmentExists:
    """attachment_exists: Existential operator."""

    def test_pass_with_attachment(self):
        att = AttachmentRef(path="artifacts/report.pdf", media_type="application/pdf")
        records = [_make_record("evaluation_report", attachments=[att])]
        passed, refs = op_attachment_exists(
            {"record_type": "evaluation_report"}, records
        )
        assert passed
        assert len(refs) == 1

    def test_fail_no_attachment(self):
        records = [_make_record("evaluation_report")]
        passed, refs = op_attachment_exists(
            {"record_type": "evaluation_report"}, records
        )
        assert not passed

    def test_fail_empty_records(self):
        passed, _ = op_attachment_exists({"record_type": "evaluation_report"}, [])
        assert not passed

    def test_media_type_filter(self):
        att = AttachmentRef(path="artifacts/report.pdf", media_type="application/pdf")
        records = [_make_record("evaluation_report", attachments=[att])]
        passed, _ = op_attachment_exists(
            {"record_type": "evaluation_report", "media_type": "image/png"}, records
        )
        assert not passed


class TestEntityLinked:
    """entity_linked: Universal operator — vacuous truth on empty set."""

    def test_pass_subject_linked(self):
        records = [_make_record("risk_register", subject_refs=["urn:acef:sub:00000000-0000-0000-0000-000000000001"])]
        passed, refs = op_entity_linked(
            {"record_type": "risk_register", "entity_type": "subject"}, records
        )
        assert passed
        assert len(refs) == 1

    def test_fail_no_subject_linked(self):
        records = [_make_record("risk_register")]
        passed, _ = op_entity_linked(
            {"record_type": "risk_register", "entity_type": "subject"}, records
        )
        assert not passed

    def test_vacuous_truth_empty(self):
        passed, _ = op_entity_linked(
            {"record_type": "risk_register", "entity_type": "subject"}, []
        )
        assert passed

    def test_dataset_linked(self):
        records = [_make_record("data_provenance", dataset_refs=["urn:acef:dat:00000000-0000-0000-0000-000000000001"])]
        passed, _ = op_entity_linked(
            {"record_type": "data_provenance", "entity_type": "dataset"}, records
        )
        assert passed


class TestExistsWhere:
    """exists_where: Existential operator."""

    def test_pass(self):
        records = [_make_record("risk_register", payload={"severity": "high"})]
        passed, refs = op_exists_where(
            {"record_type": "risk_register", "field": "/payload/severity",
             "op": "eq", "value": "high"}, records
        )
        assert passed
        assert len(refs) == 1

    def test_fail(self):
        records = [_make_record("risk_register", payload={"severity": "low"})]
        passed, _ = op_exists_where(
            {"record_type": "risk_register", "field": "/payload/severity",
             "op": "eq", "value": "high"}, records
        )
        assert not passed

    def test_fail_empty_records(self):
        passed, _ = op_exists_where(
            {"record_type": "risk_register", "field": "/payload/x",
             "op": "eq", "value": 1, "min_count": 1}, []
        )
        assert not passed

    def test_min_count(self):
        records = [_make_record("risk_register", payload={"severity": "high"})]
        passed, _ = op_exists_where(
            {"record_type": "risk_register", "field": "/payload/severity",
             "op": "eq", "value": "high", "min_count": 2}, records
        )
        assert not passed


class TestAttachmentKindExists:
    """attachment_kind_exists: Existential operator."""

    def test_pass(self):
        att = AttachmentRef(path="artifacts/report.pdf", attachment_type="evaluation_report")
        records = [_make_record("evaluation_report", attachments=[att])]
        passed, refs = op_attachment_kind_exists(
            {"record_type": "evaluation_report", "attachment_type": "evaluation_report"}, records
        )
        assert passed
        assert len(refs) == 1

    def test_fail_wrong_kind(self):
        att = AttachmentRef(path="artifacts/other.pdf", attachment_type="other")
        records = [_make_record("evaluation_report", attachments=[att])]
        passed, _ = op_attachment_kind_exists(
            {"record_type": "evaluation_report", "attachment_type": "evaluation_report"}, records
        )
        assert not passed

    def test_fail_empty(self):
        passed, _ = op_attachment_kind_exists(
            {"record_type": "evaluation_report", "attachment_type": "evaluation_report"}, []
        )
        assert not passed


class TestBundleSigned:
    """bundle_signed: Existential operator on signatures."""

    def test_pass(self):
        passed, _ = op_bundle_signed(
            {"min_signatures": 1}, [], signature_count=1
        )
        assert passed

    def test_fail_no_signatures(self):
        passed, _ = op_bundle_signed(
            {"min_signatures": 1}, [], signature_count=0
        )
        assert not passed

    def test_required_alg(self):
        passed, _ = op_bundle_signed(
            {"min_signatures": 1, "required_alg": ["RS256"]},
            [],
            signature_count=1,
            signature_algorithms=["ES256"],
        )
        assert not passed


class TestRecordAttested:
    """record_attested: Existential operator."""

    def test_pass_with_attestation(self):
        att = Attestation(method="jws", signer="provider", signature="abc")
        records = [_make_record("risk_register", attestation=att)]
        passed, refs = op_record_attested(
            {"record_type": "risk_register"}, records
        )
        assert passed
        assert len(refs) == 1

    def test_fail_no_attestation(self):
        records = [_make_record("risk_register")]
        passed, _ = op_record_attested({"record_type": "risk_register"}, records)
        assert not passed

    def test_fail_empty_signature(self):
        att = Attestation(method="jws", signer="provider", signature="")
        records = [_make_record("risk_register", attestation=att)]
        passed, _ = op_record_attested({"record_type": "risk_register"}, records)
        assert not passed

    def test_fail_empty_records(self):
        passed, _ = op_record_attested({"record_type": "risk_register"}, [])
        assert not passed
