"""Tests for acef.redaction — privacy-preserving redaction with hash commitments."""

from __future__ import annotations

from acef.integrity import canonicalize, sha256_hex
from acef.models.enums import Confidentiality, ObligationRole
from acef.models.records import EntityRefs, RecordEnvelope
from acef.package import Package
from acef.redaction import redact_package, redact_record, verify_redaction


def _make_record(
    record_type: str = "risk_register",
    payload: dict | None = None,
    confidentiality: Confidentiality = Confidentiality.PUBLIC,
) -> RecordEnvelope:
    """Helper to create a record for testing."""
    return RecordEnvelope(
        record_type=record_type,
        payload=payload or {"description": "sensitive data", "score": 95},
        confidentiality=confidentiality,
    )


class TestRedactRecord:
    """Test redact_record creates hash commitments."""

    def test_creates_hash_commitment(self):
        original = _make_record()
        redacted = redact_record(original)

        assert redacted.confidentiality == Confidentiality.HASH_COMMITTED
        assert redacted.redaction_method is not None
        assert "sha256-hash-commitment:" in redacted.redaction_method
        assert redacted.payload["_redacted"] is True
        assert redacted.payload["_commitment"].startswith("sha256:")

    def test_preserves_envelope_fields(self):
        original = _make_record()
        redacted = redact_record(original)

        assert redacted.record_id == original.record_id
        assert redacted.record_type == original.record_type
        assert redacted.timestamp == original.timestamp

    def test_original_payload_not_in_redacted(self):
        original = _make_record(payload={"secret": "value123"})
        redacted = redact_record(original)

        assert "secret" not in redacted.payload
        assert "value123" not in str(redacted.payload)

    def test_access_policy_set(self):
        original = _make_record()
        policy = {"roles": ["regulator"], "organizations": ["EU Commission"]}
        redacted = redact_record(original, access_policy=policy)

        assert redacted.access_policy == policy

    def test_hash_is_deterministic(self):
        original = _make_record(payload={"key": "value"})
        r1 = redact_record(original)
        r2 = redact_record(original)

        # Same payload should produce same hash
        assert r1.redaction_method == r2.redaction_method


class TestVerifyRedaction:
    """Test verify_redaction matches original payload."""

    def test_verify_succeeds_with_correct_payload(self):
        original_payload = {"description": "sensitive data", "score": 95}
        original = _make_record(payload=original_payload)
        redacted = redact_record(original)

        assert verify_redaction(redacted, original_payload)

    def test_verify_fails_with_different_payload(self):
        original_payload = {"description": "sensitive data", "score": 95}
        original = _make_record(payload=original_payload)
        redacted = redact_record(original)

        tampered = {"description": "modified data", "score": 50}
        assert not verify_redaction(redacted, tampered)

    def test_verify_fails_without_redaction_method(self):
        record = _make_record()
        assert not verify_redaction(record, {"key": "value"})

    def test_verify_fails_with_bad_redaction_method(self):
        record = _make_record()
        record.redaction_method = "invalid"
        assert not verify_redaction(record, {"key": "value"})


class TestRedactPackage:
    """Test redact_package filters by record_type and confidentiality."""

    def test_redact_by_record_type(self):
        pkg = Package()
        pkg.record("risk_register", payload={"risk": "high"})
        pkg.record("dataset_card", payload={"name": "Data"})

        redacted_pkg = redact_package(
            pkg,
            record_filter={"record_types": ["risk_register"]},
        )

        assert len(redacted_pkg.records) == 2

        rr = next(r for r in redacted_pkg.records if r.record_type == "risk_register")
        dc = next(r for r in redacted_pkg.records if r.record_type == "dataset_card")

        assert rr.confidentiality == Confidentiality.HASH_COMMITTED
        assert rr.payload.get("_redacted") is True

        assert dc.confidentiality == Confidentiality.PUBLIC
        assert dc.payload == {"name": "Data"}

    def test_redact_by_confidentiality_level(self):
        pkg = Package()
        pkg.record("risk_register", payload={"r": 1}, confidentiality="regulator-only")
        pkg.record("dataset_card", payload={"d": 1}, confidentiality="public")

        redacted_pkg = redact_package(
            pkg,
            record_filter={"confidentiality_levels": ["regulator-only"]},
        )

        rr = next(r for r in redacted_pkg.records if r.record_type == "risk_register")
        dc = next(r for r in redacted_pkg.records if r.record_type == "dataset_card")

        assert rr.confidentiality == Confidentiality.HASH_COMMITTED
        assert dc.confidentiality == Confidentiality.PUBLIC

    def test_redacted_package_preserves_metadata(self):
        pkg = Package(producer={"name": "tool", "version": "1.0"})
        pkg.add_subject("ai_system", name="System")
        pkg.record("risk_register", payload={"x": 1})

        redacted_pkg = redact_package(pkg, record_filter={"record_types": ["risk_register"]})

        assert redacted_pkg.metadata.package_id == pkg.metadata.package_id
        assert len(redacted_pkg.subjects) == 1

    def test_empty_filter_no_redaction(self):
        pkg = Package()
        pkg.record("risk_register", payload={"x": 1})

        redacted_pkg = redact_package(pkg)

        rec = redacted_pkg.records[0]
        assert rec.confidentiality == Confidentiality.PUBLIC
        assert rec.payload == {"x": 1}
