"""W10.3 bundle-digest tests (VAL-W10-020).

Asserts that :func:`relay_verifier.canonical.bundle_digest` computes
``SHA-256(JCS(claim_payload_without_signature))`` per spec section K
line 4390 and that the resulting digest matches every artifact's
``evidence_refs[].digest`` round-trip.

The W10.4 feature wires this digest into the bundle-validation pipeline
proper (rejection with ``RELAY-EVID-014`` on tamper); the W10.3 scope
asserts the digest primitive is correct in isolation.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from relay_verifier.canonical import bundle_digest, jcs_canonicalize

CORPUS_PATH = (
    Path(__file__).resolve().parents[3]
    / "tests"
    / "conformance"
    / "jcs"
    / "rfc8785_corpus.json"
)


def _load_corpus() -> dict[str, Any]:
    return json.loads(CORPUS_PATH.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# VAL-W10-020: bundle digest computed correctly from canonical claims
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-020")
def test_bundle_digest_strips_top_level_signatures_field() -> None:
    """A claim wrapped with ``signatures`` digests to the same value as
    the same claim WITHOUT the signatures field. Defends against the
    sign-then-replay attack where the signatures envelope is replayed
    over a different payload.
    """
    payload = {"kid": "k1", "data": {"a": 1, "b": 2}}
    with_sigs = {**payload, "signatures": [{"alg": "EdDSA", "sig": "xxx"}]}

    digest_without = bundle_digest(payload)
    digest_with_strip = bundle_digest(with_sigs, strip_signatures=True)
    assert digest_without == digest_with_strip


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-020")
def test_bundle_digest_includes_signatures_when_strip_disabled() -> None:
    """``strip_signatures=False`` digests the value as supplied."""
    payload = {"kid": "k1", "data": {"a": 1}}
    with_sigs = {**payload, "signatures": [{"alg": "EdDSA", "sig": "xxx"}]}

    digest_without = bundle_digest(payload, strip_signatures=False)
    digest_with = bundle_digest(with_sigs, strip_signatures=False)
    assert digest_without != digest_with


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-020")
def test_bundle_digest_equals_sha256_of_jcs_canonical_bytes() -> None:
    """The helper is sha256(jcs_canonicalize(...)).hex() -- no salt,
    no double-hash, no hex-uppercase. Wired contractually for callers
    that recompute by hand."""
    payload = {"a": 1, "b": 2}
    expected = hashlib.sha256(jcs_canonicalize(payload)).hexdigest()
    assert bundle_digest(payload) == expected


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-020")
def test_bundle_digest_corpus_cases_round_trip() -> None:
    """Every corpus bundle_digest case digests to the corpus golden."""
    corpus = _load_corpus()
    bundle_cases = [c for c in corpus["cases"] if c["kind"] == "bundle_digest"]
    assert bundle_cases, "corpus must contain at least one bundle_digest case"
    failures: list[str] = []
    for case in bundle_cases:
        actual_digest = bundle_digest(
            case["input"], strip_signatures=case["strip_signatures"]
        )
        expected_digest = case["expected_sha256"]
        if actual_digest != expected_digest:
            failures.append(
                f"{case['name']}: expected={expected_digest!r} "
                f"got={actual_digest!r}"
            )
        # Cross-check: the corpus also pins the canonical bytes.
        case_input = case["input"]
        if (
            case["strip_signatures"]
            and isinstance(case_input, dict)
            and "signatures" in case_input
        ):
            payload = {k: v for k, v in case_input.items() if k != "signatures"}
        else:
            payload = case_input
        actual_bytes = jcs_canonicalize(payload)
        expected_bytes = base64.b64decode(case["expected_canonical_b64"])
        if actual_bytes != expected_bytes:
            failures.append(
                f"{case['name']}: canonical-bytes mismatch "
                f"expected={expected_bytes!r} got={actual_bytes!r}"
            )
    assert not failures, (
        "VAL-W10-020 bundle_digest mismatches: " + "; ".join(failures)
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-020")
def test_bundle_digest_changes_when_any_byte_of_payload_changes() -> None:
    """Tamper test: flipping ANY byte in the payload changes the digest.
    The W10.4 verifier rejects with RELAY-EVID-014 when this happens
    over the wire; W10.3 asserts the primitive's sensitivity here."""
    base_payload = {"claim_id": "c1", "value": 100}
    base_digest = bundle_digest(base_payload)

    # Mutate value
    mutated_value = {"claim_id": "c1", "value": 101}
    assert bundle_digest(mutated_value) != base_digest

    # Mutate key
    mutated_key = {"claim_id": "c2", "value": 100}
    assert bundle_digest(mutated_key) != base_digest

    # Add field
    extra_field = {"claim_id": "c1", "value": 100, "extra": True}
    assert bundle_digest(extra_field) != base_digest

    # Remove field
    missing_field = {"claim_id": "c1"}
    assert bundle_digest(missing_field) != base_digest


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-020")
def test_bundle_digest_stable_across_key_insertion_order() -> None:
    """JCS sorts keys, so two dicts with the same keys in different
    insertion order MUST digest to the same value. Without this
    invariant, two semantically identical claims would have different
    digests."""
    a = {"a": 1, "b": 2, "c": 3}
    b = {"c": 3, "b": 2, "a": 1}
    d = {}
    d["b"] = 2
    d["a"] = 1
    d["c"] = 3
    assert bundle_digest(a) == bundle_digest(b) == bundle_digest(d)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-020")
def test_bundle_digest_artifact_digest_round_trip() -> None:
    """Simulate the spec section K line 4402-4406 contract: each
    ``evidence_refs[].digest`` MUST equal SHA-256 of the referenced
    artifact's canonical form. We round-trip a simulated artifact +
    digest pair and assert tampering with the artifact breaks the
    binding."""
    artifact: dict[str, Any] = {"kind": "log_excerpt", "lines": ["a", "b", "c"]}
    canonical = jcs_canonicalize(artifact)
    declared = hashlib.sha256(canonical).hexdigest()

    # Round-trip ok
    assert bundle_digest(artifact, strip_signatures=False) == declared

    # Tamper -> digest diverges
    tampered = {"kind": "log_excerpt", "lines": ["a", "b", "X"]}
    assert bundle_digest(tampered, strip_signatures=False) != declared


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-020")
def test_bundle_digest_with_non_dict_value_does_not_raise() -> None:
    """``bundle_digest`` accepts any JSON-encodable value (e.g., list)
    and treats ``signatures`` strip as a no-op when the value is not
    a dict."""
    arr = [1, 2, 3]
    expected = hashlib.sha256(jcs_canonicalize(arr)).hexdigest()
    assert bundle_digest(arr) == expected
    assert bundle_digest(arr, strip_signatures=False) == expected
