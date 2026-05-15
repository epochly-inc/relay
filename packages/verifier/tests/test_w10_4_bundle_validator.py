"""W10.4 full-bundle validator -- core verdict + tamper detection.

Covers assertions:
  * VAL-W10-021 (happy path)
  * VAL-W10-022 (tampered artifact)
  * VAL-W10-023 (tampered claim payload)
  * VAL-W10-024 (Merkle root mismatch)
  * VAL-W10-035 (trust_anchor surfaced)
  * VAL-W10-036 (archive bomb limit)
  * VAL-W10-039 (output JSON schema validated)

Companion files:
  * test_w10_4_tsa_and_log.py     -- VAL-W10-025..030
  * test_w10_4_key_lifecycle.py   -- VAL-W10-031..034
  * test_w10_4_retention_and_anchor.py -- VAL-W10-037..038, 041
  * test_w10_4_chain_and_invariants.py -- VAL-W10-040, 042

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest
import yaml

# Sibling helper import (see conftest_w10_4.py docstring for rationale).
sys.path.insert(0, str(Path(__file__).resolve().parent))

from conftest_w10_4 import build_bundle  # noqa: E402
from relay_verifier import (  # noqa: E402
    MAX_BUNDLE_BYTES,
    MAX_BUNDLE_ENTRIES,
    RELAY_EVID_014,
    RELAY_EVID_024,
    RELAY_EVID_040,
    SUBJECT_RESOLUTION_UNKNOWN,
    VERIFIER_OUTPUT_SCHEMA,
    ValidateBundleOptions,
    check_archive_bomb_limits,
    validate_bundle,
    validate_bundle_with_archive_check,
)

# ---------------------------------------------------------------------------
# VAL-W10-021: full bundle happy-path verification end-to-end
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-021")
def test_happy_path_full_bundle_verification_end_to_end() -> None:
    """A canonical hosted-signed bundle verifies end-to-end with every
    output field populated and overall="pass"."""
    built = build_bundle()

    def resolver(artifact_id: str) -> bytes:
        if artifact_id == "art-1":
            return b"artifact-1-bytes"
        raise KeyError(artifact_id)

    output = validate_bundle(
        bundle=built.bundle,
        jwks=built.jwks,
        bundle_path="/tmp/test-bundle.json",
        trust_anchor_source="live",
        options=ValidateBundleOptions(artifact_resolver=resolver),
    )
    assert output["schema_version"] == VERIFIER_OUTPUT_SCHEMA
    assert output["overall"] == "pass", output
    assert output["digest_ok"] is True
    assert output["structure_ok"] is True
    assert output["signatures_ok"] is True
    assert output["claims_count"] == 1
    assert output["merkle_check"] == "ok"
    assert output["tsa_check"] == "ok"
    assert output["log_inclusion"] == "ok"
    assert output["trust_anchor"].endswith("jwks.json")
    assert output["trust_anchor_source"] == "live"
    assert output["signer_key_revoked"] is False
    assert output["signer_key_revoked_at"] is None
    assert output["subject_resolution"] == SUBJECT_RESOLUTION_UNKNOWN
    assert output["errors"] == []
    # signatures_checked has the per-sig verdict.
    assert len(output["signatures_checked"]) == 1
    assert output["signatures_checked"][0]["ok"] is True


# ---------------------------------------------------------------------------
# VAL-W10-022: tampered artifact digest -> bundle rejected
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-022")
def test_tampered_artifact_digest_rejected_with_evid_014() -> None:
    """Mutating any byte of an artifact MUST cause rejection naming the
    offending evidence_ref index with RELAY-EVID-014."""
    built = build_bundle()

    def resolver(artifact_id: str) -> bytes:
        # Return DIFFERENT bytes than the digest was computed over.
        if artifact_id == "art-1":
            return b"artifact-1-bytes-TAMPERED"
        raise KeyError(artifact_id)

    output = validate_bundle(
        bundle=built.bundle,
        jwks=built.jwks,
        options=ValidateBundleOptions(artifact_resolver=resolver),
    )
    assert output["overall"] == "fail"
    assert output["digest_ok"] is False
    # The error names the offending claim+ref index and uses RELAY-EVID-014.
    matching_errors = [
        e for e in output["errors"]
        if e["reason"] == "artifact_digest_mismatch"
        and e.get("code") == RELAY_EVID_014
    ]
    assert matching_errors, output["errors"]
    assert "evidence_refs[0]" in matching_errors[0]["message"]


# ---------------------------------------------------------------------------
# VAL-W10-023: tampered claim payload -> JWS verification fails
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-023")
def test_tampered_claim_payload_fails_jws_with_evid_014() -> None:
    """Mutating any field of any claim AFTER signing MUST cause JWS
    verification to fail with RELAY-EVID-014 and the bundle to be
    rejected overall."""
    built = build_bundle()

    # Mutate a claim's exit_code after signing.
    built.bundle["claims"][0]["exit_code"] = 99

    output = validate_bundle(
        bundle=built.bundle,
        jwks=built.jwks,
    )
    assert output["overall"] == "fail"
    assert output["signatures_ok"] is False
    # The first signature failure should be tagged with RELAY-EVID-014.
    assert any(
        e.get("code") == RELAY_EVID_014 for e in output["errors"]
    ), output["errors"]


# ---------------------------------------------------------------------------
# VAL-W10-024: Merkle root mismatch -> bundle rejected
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-024")
def test_merkle_root_mismatch_rejected_with_evid_040() -> None:
    """Tampering with the bundle's stored merkle_root_hex MUST produce
    a Merkle-root mismatch error (RELAY-EVID-040) distinct from a
    per-claim JWS failure."""
    built = build_bundle()
    # Replace merkle root with a value that does NOT match.
    fake_root = hashlib.sha256(b"forged-root").hexdigest()
    built.bundle["merkle_root_hex"] = fake_root
    # Note: this also breaks signatures_ok because the signed payload
    # included the original root; the explicit merkle_check field
    # captures the dedicated diagnostic.

    output = validate_bundle(bundle=built.bundle, jwks=built.jwks)
    assert output["overall"] == "fail"
    assert output["merkle_check"] == "mismatch"
    merkle_errors = [
        e for e in output["errors"]
        if e["reason"] == "merkle_root_mismatch"
        and e.get("code") == RELAY_EVID_040
    ]
    assert merkle_errors, output["errors"]


# ---------------------------------------------------------------------------
# VAL-W10-035: trust_anchor field surfaced verbatim in output
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-035")
def test_trust_anchor_field_surfaced_for_hosted_anchor() -> None:
    """The verifier output JSON's `trust_anchor` field MUST echo the
    bundle's claim verbatim for the hosted profile."""
    hosted_anchor = "https://relay.epochly.com/.well-known/jwks.json"
    built = build_bundle(trust_anchor=hosted_anchor)
    output = validate_bundle(bundle=built.bundle, jwks=built.jwks)
    assert output["trust_anchor"] == hosted_anchor


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-035")
def test_trust_anchor_field_surfaced_for_local_dev() -> None:
    """`trust_anchor: "local_dev"` echoed verbatim."""
    built = build_bundle(trust_anchor="local_dev")
    output = validate_bundle(bundle=built.bundle, jwks=built.jwks)
    assert output["trust_anchor"] == "local_dev"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-035")
def test_trust_anchor_field_surfaced_for_third_party_anchor() -> None:
    """Third-party trust anchor echoed verbatim."""
    third = "https://forks.example.com/jwks.json"
    built = build_bundle(trust_anchor=third)
    output = validate_bundle(bundle=built.bundle, jwks=built.jwks)
    assert output["trust_anchor"] == third


# ---------------------------------------------------------------------------
# VAL-W10-036: archive bomb limit enforced before signature work
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-036")
def test_archive_bomb_entry_count_rejected_with_evid_024() -> None:
    """entry_count > 4096 MUST be rejected with RELAY-EVID-024 before
    any signature work is attempted."""
    built = build_bundle()
    output = validate_bundle_with_archive_check(
        bundle=built.bundle,
        jwks=built.jwks,
        entry_count=MAX_BUNDLE_ENTRIES + 1,
        uncompressed_size_bytes=1024,
    )
    assert output["overall"] == "fail"
    assert any(
        e["reason"] == "archive_bomb_limit_exceeded"
        and e.get("code") == RELAY_EVID_024
        for e in output["errors"]
    ), output["errors"]
    # Confirm signature work was skipped: signatures_checked stays empty
    # because we never invoked verify_bundle.
    assert output["signatures_checked"] == []


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-036")
def test_archive_bomb_total_bytes_rejected_with_evid_024() -> None:
    """uncompressed_size_bytes > 256 MiB MUST be rejected with
    RELAY-EVID-024 before any signature work."""
    built = build_bundle()
    output = validate_bundle_with_archive_check(
        bundle=built.bundle,
        jwks=built.jwks,
        entry_count=10,
        uncompressed_size_bytes=MAX_BUNDLE_BYTES + 1,
    )
    assert output["overall"] == "fail"
    assert any(
        e.get("code") == RELAY_EVID_024 for e in output["errors"]
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-036")
def test_archive_bomb_under_limits_proceeds_to_verification() -> None:
    """entry_count <= 4096 AND size <= 256 MiB proceeds normally."""
    ok, reason = check_archive_bomb_limits(
        entry_count=MAX_BUNDLE_ENTRIES,
        uncompressed_size_bytes=MAX_BUNDLE_BYTES,
    )
    assert ok is True
    assert reason == ""


# ---------------------------------------------------------------------------
# VAL-W10-039: verifier output JSON schema-validated
# ---------------------------------------------------------------------------


VERIFIER_OUTPUT_SCHEMA_YAML = (
    Path(__file__).resolve().parents[3]
    / "packages"
    / "schemas"
    / "raw"
    / "verifier-output.yaml"
)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-039")
def test_verifier_output_yaml_schema_parses_and_pins_v1() -> None:
    """The canonical verifier-output YAML schema MUST parse and pin
    schema_version 'relay.verifier.output.v1'."""
    raw = VERIFIER_OUTPUT_SCHEMA_YAML.read_text(encoding="utf-8")
    doc = yaml.safe_load(raw)
    assert doc["schema"] == "relay.schema.verifier_output.v1"
    assert doc["envelope"]["schema_version"] == VERIFIER_OUTPUT_SCHEMA


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-039")
def test_verifier_output_contains_every_schema_required_field() -> None:
    """Every required field in the YAML schema MUST be present in the
    output of a happy-path validation."""
    raw = VERIFIER_OUTPUT_SCHEMA_YAML.read_text(encoding="utf-8")
    doc = yaml.safe_load(raw)
    declared_fields = set(doc["envelope"]["fields"].keys())

    built = build_bundle()
    output = validate_bundle(bundle=built.bundle, jwks=built.jwks)
    output_fields = set(output.keys())
    missing = declared_fields - output_fields
    extra = output_fields - declared_fields
    assert not missing, f"missing fields in validator output: {missing}"
    assert not extra, f"extra fields in validator output: {extra}"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-039")
def test_verifier_output_is_json_serializable() -> None:
    """The validator output MUST be byte-for-byte JSON-serializable so
    cross-language parity is achievable."""
    built = build_bundle()
    output = validate_bundle(bundle=built.bundle, jwks=built.jwks)
    serialized = json.dumps(output, sort_keys=True)
    reloaded = json.loads(serialized)
    assert reloaded == output
