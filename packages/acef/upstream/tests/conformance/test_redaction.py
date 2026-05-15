"""Conformance test: redaction with hash commitments.

Verifies that redacted packages preserve envelope fields,
replace payloads correctly, and verify hash commitments.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from acef.integrity import canonicalize, sha256_hex
from acef.loader import load
from acef.models.enums import Confidentiality
from acef.package import Package
from acef.redaction import redact_package, redact_record, verify_redaction

from tests.conformance.conftest import build_minimal_package


class TestRedaction:
    """Redaction conformance: hash-commitment redaction and verification."""

    def test_redacted_record_preserves_envelope(self) -> None:
        """Redaction preserves envelope fields (record_id, type, timestamp, provisions)
        but replaces the payload."""
        pkg = build_minimal_package()
        original = pkg.records[0]
        redacted = redact_record(original)

        assert redacted.record_id == original.record_id
        assert redacted.record_type == original.record_type
        assert redacted.timestamp == original.timestamp
        assert redacted.provisions_addressed == original.provisions_addressed
        assert redacted.confidentiality == Confidentiality.HASH_COMMITTED
        assert redacted.redaction_method is not None
        assert redacted.payload.get("_redacted") is True

    def test_redacted_payload_contains_hash_commitment(self) -> None:
        """The redacted payload contains a sha256 hash commitment."""
        pkg = build_minimal_package()
        original = pkg.records[0]
        redacted = redact_record(original)

        commitment = redacted.payload.get("_commitment", "")
        assert commitment.startswith("sha256:"), (
            f"Commitment must start with 'sha256:', got: {commitment}"
        )

        # Verify the hash matches
        payload_canonical = canonicalize(original.payload)
        expected_hash = sha256_hex(payload_canonical)
        assert commitment == f"sha256:{expected_hash}"

    def test_verify_redaction_matches_original(self) -> None:
        """verify_redaction returns True when given the correct original payload."""
        pkg = build_minimal_package()
        original = pkg.records[0]
        original_payload = dict(original.payload)
        redacted = redact_record(original)

        assert verify_redaction(redacted, original_payload) is True

    def test_verify_redaction_fails_on_wrong_payload(self) -> None:
        """verify_redaction returns False when given an incorrect payload."""
        pkg = build_minimal_package()
        original = pkg.records[0]
        redacted = redact_record(original)

        wrong_payload = {"description": "COMPLETELY DIFFERENT DATA"}
        assert verify_redaction(redacted, wrong_payload) is False

    def test_redacted_package_roundtrips(self, tmp_dir: Path) -> None:
        """A redacted package can be exported and loaded, preserving commitments."""
        pkg = build_minimal_package(
            record_types=["risk_register", "evaluation_report"],
            provisions=["article-9", "article-11"],
        )

        # Store original payloads for verification
        original_payloads = {r.record_id: dict(r.payload) for r in pkg.records}

        # Redact only risk_register records
        redacted_pkg = redact_package(
            pkg,
            record_filter={"record_types": ["risk_register"]},
        )

        # Export and reload
        bundle_dir = tmp_dir / "redacted_rt"
        redacted_pkg.export(str(bundle_dir))
        loaded = load(str(bundle_dir))

        # Find the redacted risk_register record
        rr_records = [r for r in loaded.records if r.record_type == "risk_register"]
        assert len(rr_records) > 0

        for rr in rr_records:
            assert rr.payload.get("_redacted") is True, (
                "Redacted record must have _redacted=True after round-trip"
            )
            # Verify commitment still valid against original
            original_pl = original_payloads.get(rr.record_id)
            if original_pl:
                assert verify_redaction(rr, original_pl) is True, (
                    "Hash commitment must still verify after round-trip"
                )

        # Non-redacted records should be unmodified
        eval_records = [r for r in loaded.records if r.record_type == "evaluation_report"]
        for er in eval_records:
            assert er.payload.get("_redacted") is not True, (
                "Non-redacted records must not have _redacted flag"
            )
