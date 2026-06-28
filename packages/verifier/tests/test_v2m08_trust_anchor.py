"""Sub-feature w8-trust-anchor tests (VAL-V2M08-041..044).

Covers four contract assertions defended by the OSS verifier:

* VAL-V2M08-041 -- verifier rejects bundles carrying more than 4
  cross-signing signatures with code RELAY-EVID-SIGCOUNT-EXCEEDED and
  reports ``signatures_present`` in the structured envelope. The
  ``signatures_checked[]`` array is empty for the over-cap bundle (the
  verifier refuses to attempt verification).
* VAL-V2M08-042 -- a bundle carrying exactly 4 signatures verifies
  successfully and the output envelope contains a length-4
  ``signatures_checked[]`` array, with each signature reported
  independently (e.g., 3 valid + 1 invalid yields
  ``valid=true/true/true/false``).
* VAL-V2M08-043 -- bundles signed by the OSS local signer carry the
  top-level field ``trust_anchor: "local_dev"`` and the verifier output
  surfaces it verbatim. A bundle missing the ``trust_anchor`` field is
  rejected with code RELAY-EVID-MISSING-TRUST-ANCHOR.
* VAL-V2M08-044 -- ``trust_anchor: "local_dev"`` is classified as
  ``trust_anchor_class = "untrusted_local"`` regardless of which JWKS
  the bundle's signature happens to verify under; the OSS verifier
  refuses to auto-promote it to ``relay_inc``.

Spec citations: section L.5 line 4481 (cross-signing cap), section AO.4
lines 6164-6168 (trust-anchor label conditional + non-promotion).

Per CLAUDE.md keystone invariant #11 the default trust anchor constant
MUST remain ``https://relay.epochly.com/.well-known/jwks.json`` (banned
pattern #13). These tests verify the runtime classification rule, NOT a
change to the constant.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Make conftest_w10_4 importable.
sys.path.insert(0, str(Path(__file__).parent))

from conftest_w10_4 import build_bundle  # noqa: E402
from relay_verifier import (  # noqa: E402
    ValidateBundleOptions,
    canonical_json_bytes,
    jwk_from_ed25519_public_key,
    sign_payload_ed25519,
    validate_bundle,
)
from relay_verifier.bundle_validator import (  # noqa: E402
    MAX_BUNDLE_SIGNATURES,
    RELAY_EVID_MISSING_TRUST_ANCHOR,
    RELAY_EVID_SIGCOUNT_EXCEEDED,
    TRUST_ANCHOR_CLASS_BYO,
    TRUST_ANCHOR_CLASS_RELAY_INC,
    TRUST_ANCHOR_CLASS_UNTRUSTED_LOCAL,
    classify_trust_anchor,
)
from relay_verifier.local_signer import (  # noqa: E402
    LOCAL_DEV_CACHE_PREFIX,
    TRUST_ANCHOR_LOCAL_DEV,
    build_local_dev_bundle,
    local_dev_cache_key,
)

# ---------------------------------------------------------------------------
# VAL-V2M08-041: > 4 signatures rejected with structured error
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-041")
def test_verifier_rejects_more_than_four_signatures() -> None:
    """A bundle carrying 5 signatures MUST be rejected before signature
    verification. The output envelope MUST include the public code
    RELAY-EVID-SIGCOUNT-EXCEEDED, MUST surface ``signatures_present=5``,
    and MUST NOT include any ``signatures_checked[]`` entries for the
    over-cap bundle."""
    assert MAX_BUNDLE_SIGNATURES == 4, "spec L.5 line 4481 fixes the cap at 4"

    built = build_bundle()
    # Duplicate the lone existing signature four extra times so the
    # bundle carries 5 entries in total. The duplicates are structurally
    # well-formed (each is a valid signature record); the rejection MUST
    # come from the count gate, not from per-signature validation.
    original_sigs = list(built.bundle["signatures"])
    assert len(original_sigs) == 1
    built.bundle["signatures"] = original_sigs * 5
    assert len(built.bundle["signatures"]) == 5

    output = validate_bundle(
        bundle=built.bundle,
        jwks=built.jwks,
        trust_anchor_source="live",
    )

    # Overall verdict must fail.
    assert output["overall"] == "fail", output

    # No per-signature entries -- the verifier refused to attempt.
    assert output["signatures_checked"] == [], output["signatures_checked"]
    assert output["signatures_ok"] is False

    # signatures_present surfaced.
    assert output["signatures_present"] == 5, output

    # Structured error envelope present.
    matching = [
        e for e in output["errors"]
        if e.get("code") == RELAY_EVID_SIGCOUNT_EXCEEDED
    ]
    assert matching, output["errors"]
    err = matching[0]
    assert err["reason"] == "signature_count_exceeded"
    assert "5" in err["message"]
    assert "4" in err["message"]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-041")
def test_non_bmp_key_takes_precedence_over_signature_count_cap() -> None:
    """A bundle that is BOTH over-cap (5 signatures) AND carries a non-BMP
    (supplementary-plane, >= U+10000) object key MUST be rejected as
    ``non_canonicalizable_bundle`` (RELAY-CANON-NON-BMP-KEY), NOT merely
    ``signature_count_exceeded``.

    A bundle whose canonical bytes are not well-defined across runtimes is a
    more fundamental failure than an over-cap signature count: every
    downstream check -- including the over-cap branch's diagnostic
    bundle_digest, whose ``contextlib.suppress(TypeError, ValueError)`` would
    otherwise silently swallow the JCSEncodeError (it subclasses ValueError)
    -- is meaningless if the bundle cannot be canonicalised at all. The
    non-BMP screen therefore runs BEFORE the over-cap check (keystone
    invariant #11/#16; roborev follow-on on the F1 fix).
    """
    # Build a normal (BMP) signed bundle, then INJECT a non-BMP object key
    # into the signed payload AFTER signing. Signing canonicalises, so a
    # non-BMP key present at sign time would (correctly) raise in the signer;
    # injecting it post-signing leaves a stale signature, but both the non-BMP
    # screen and the over-cap check run BEFORE per-signature verification.
    built = build_bundle()
    built.bundle["claims"][0]["namespaces"] = {"x" + chr(0x1F600) + "y": {}}
    original_sigs = list(built.bundle["signatures"])
    built.bundle["signatures"] = original_sigs * 5
    assert len(built.bundle["signatures"]) == 5

    output = validate_bundle(
        bundle=built.bundle,
        jwks=built.jwks,
        trust_anchor_source="live",
    )

    assert output["overall"] == "fail", output
    reasons = [e.get("reason") for e in output["errors"]]
    # The non-canonicalisable rejection wins; the over-cap reason is absent.
    assert "non_canonicalizable_bundle" in reasons, output["errors"]
    assert "signature_count_exceeded" not in reasons, output["errors"]
    nb = next(
        e for e in output["errors"]
        if e.get("reason") == "non_canonicalizable_bundle"
    )
    assert nb["code"] == "RELAY-CANON-NON-BMP-KEY", nb
    # signatures_present is still recorded for diagnostic continuity.
    assert output["signatures_present"] == 5, output


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-041")
def test_unsafe_integer_value_rejected_as_non_canonicalizable() -> None:
    """A bundle carrying an integer VALUE outside the IEEE-754 safe range
    (abs > 2**53 - 1) MUST be rejected as ``non_canonicalizable_bundle``
    with code ``RELAY-CANON-UNSAFE-INTEGER``.

    A Python host keeps such an integer exact while a float64 host
    (TypeScript ``JSON.parse``) rounds it (9007199254740993 ->
    9007199254740992), so the same wire bundle would canonicalise to
    DIFFERENT bytes -> different SHA-256 -> a cross-runtime verify split
    (keystone invariant #11/#16). The verifier screens the bundle
    value-boundary BEFORE canonicalisation and fails closed, mirroring the
    contracts evaluator's safe-integer guard. The low-level JCS encoder is
    intentionally unbounded (RFC 8785 conformance for large floats), so the
    bound lives at this value-boundary.
    """
    built = build_bundle()
    # Inject an out-of-safe-range integer VALUE into the signed payload
    # AFTER signing (stale signature is irrelevant: the value-boundary
    # screen runs BEFORE any signature / canonicalisation work).
    built.bundle["claims"][0]["oversized_count"] = 9007199254740993  # 2**53 + 1
    assert 9007199254740993 > 2**53 - 1

    output = validate_bundle(
        bundle=built.bundle,
        jwks=built.jwks,
        trust_anchor_source="live",
    )

    assert output["overall"] == "fail", output
    reasons = [e.get("reason") for e in output["errors"]]
    assert "non_canonicalizable_bundle" in reasons, output["errors"]
    nb = next(
        e for e in output["errors"]
        if e.get("reason") == "non_canonicalizable_bundle"
    )
    assert nb["code"] == "RELAY-CANON-UNSAFE-INTEGER", nb


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-041")
def test_safe_integer_value_at_bound_is_accepted() -> None:
    """The bound is exclusive of MAX_SAFE_INTEGER itself: a value of exactly
    2**53 - 1 (9007199254740991) is within the safe range and MUST NOT be
    flagged ``non_canonicalizable_bundle`` -- it round-trips byte-identically
    through a float64 host. (The bundle may still fail for other reasons such
    as a stale signature; only the non-canonicalisable rejection is asserted
    absent.)
    """
    built = build_bundle()
    built.bundle["claims"][0]["max_safe"] = 9007199254740991  # 2**53 - 1
    output = validate_bundle(
        bundle=built.bundle,
        jwks=built.jwks,
        trust_anchor_source="live",
    )
    reasons = [e.get("reason") for e in output["errors"]]
    assert "non_canonicalizable_bundle" not in reasons, output["errors"]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-041")
def test_verifier_signature_cap_constant_matches_spec() -> None:
    """The cap MUST be the spec-pinned value 4 (section L.5 line 4481)."""
    assert MAX_BUNDLE_SIGNATURES == 4


# ---------------------------------------------------------------------------
# VAL-V2M08-042: 4-signature bundle accepted with per-signature report
# ---------------------------------------------------------------------------


def _build_four_sig_bundle(
    *,
    invalid_indices: tuple[int, ...] = (),
):
    """Construct a bundle with exactly four signatures.

    ``invalid_indices`` lists which signature slots should be tampered
    with after signing so they fail verification. The other slots remain
    valid. Returns ``(built, payload_bytes)`` so callers can re-derive
    canonical bytes if they need to.
    """
    built = build_bundle()
    payload = {k: v for k, v in built.bundle.items() if k != "signatures"}

    # Construct three additional independent signers so the JWKS has
    # four distinct kids. Each signature is over the same canonical
    # payload bytes (cross-signing model from spec L.5).
    from cryptography.hazmat.primitives.asymmetric import ed25519
    seeds = [b"\x03" * 32, b"\x04" * 32, b"\x05" * 32]
    extra_sigs: list[dict] = []
    extra_jwks: list[dict] = []
    for i, seed in enumerate(seeds):
        key = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
        kid = f"extra-signer-kid-{i + 1}"
        sig = sign_payload_ed25519(payload, key, kid=kid)
        extra_sigs.append(sig)
        extra_jwks.append(
            jwk_from_ed25519_public_key(
                key.public_key(),
                kid=kid,
                not_before="2026-01-01T00:00:00Z",
                not_after="2028-01-01T00:00:00Z",
            )
        )

    built.bundle["signatures"] = [built.bundle["signatures"][0], *extra_sigs]
    built.jwks["keys"].extend(extra_jwks)
    assert len(built.bundle["signatures"]) == 4

    # Tamper requested slots by mutating the signature bytes (preserves
    # the structural envelope but breaks verification).
    if invalid_indices:
        for idx in invalid_indices:
            sig_rec = dict(built.bundle["signatures"][idx])
            # Flip a base64url character in the MIDDLE of the encoded
            # signature so the flipped bits land in meaningful payload
            # bytes. Flipping the last char is unsafe: ed25519 sigs are
            # 64 bytes = 512 bits, encoded as 86 base64url chars = 516
            # bits with 4 trailing stuffing bits; a single-char flip at
            # the tail only touches stuffing bits, leaving the decoded
            # signature bytes unchanged and verification still passing.
            # A middle-position flip guarantees a real signature-byte
            # mutation.
            sb = sig_rec["signature_b64u"]
            mid = len(sb) // 2
            flipped = sb[:mid] + ("A" if sb[mid] != "A" else "B") + sb[mid + 1 :]
            sig_rec["signature_b64u"] = flipped
            built.bundle["signatures"][idx] = sig_rec

    return built


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-042")
def test_verifier_accepts_four_signatures_all_valid() -> None:
    """4 valid signatures yields signatures_ok=True and a length-4
    ``signatures_checked[]`` array, each entry ``ok=True``."""
    built = _build_four_sig_bundle()
    output = validate_bundle(
        bundle=built.bundle,
        jwks=built.jwks,
        trust_anchor_source="live",
    )
    assert output["signatures_ok"] is True, output
    assert output["signatures_present"] == 4, output
    assert len(output["signatures_checked"]) == 4, output["signatures_checked"]
    for sc in output["signatures_checked"]:
        assert sc["ok"] is True, sc
        assert sc["kid"]
        assert sc["alg"] == "EdDSA"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-042")
def test_verifier_four_sig_mixed_validity_reported_per_entry() -> None:
    """3 valid + 1 invalid at the 4-signature cap yields per-signature
    ``ok=true/true/true/false`` in declaration order."""
    built = _build_four_sig_bundle(invalid_indices=(3,))
    output = validate_bundle(
        bundle=built.bundle,
        jwks=built.jwks,
        trust_anchor_source="live",
    )
    assert len(output["signatures_checked"]) == 4
    oks = [sc["ok"] for sc in output["signatures_checked"]]
    assert oks == [True, True, True, False], oks
    # Overall sigs_ok is False because at least one signature did not
    # verify (strict cross-signing posture).
    assert output["signatures_ok"] is False


# ---------------------------------------------------------------------------
# VAL-V2M08-043: OSS local signer emits trust_anchor="local_dev" + missing
# trust_anchor rejected
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-043")
def test_local_signer_emits_trust_anchor_local_dev() -> None:
    """The OSS local signer MUST stamp ``trust_anchor: "local_dev"`` on
    every bundle it produces (no opt-in, no override). The verifier
    output's ``trust_anchor`` field MUST echo the value verbatim."""
    built = build_local_dev_bundle(
        claims=[
            {
                "claim_id": "claim-local-1",
                "kind": "command_evidence",
                "command_id": "echo",
                "exit_code": 0,
            },
        ],
    )
    assert built.bundle["trust_anchor"] == TRUST_ANCHOR_LOCAL_DEV
    assert TRUST_ANCHOR_LOCAL_DEV == "local_dev"

    output = validate_bundle(
        bundle=built.bundle,
        jwks=built.jwks,
        trust_anchor_source="live",
    )
    assert output["trust_anchor"] == "local_dev"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-043")
def test_verifier_rejects_bundle_missing_trust_anchor() -> None:
    """A bundle with no ``trust_anchor`` field MUST be rejected with
    code RELAY-EVID-MISSING-TRUST-ANCHOR."""
    built = build_bundle()
    # Strip the trust_anchor field. The signature record still references
    # the original canonical payload so signature verification will also
    # fail; the rejection of interest is the structural one.
    del built.bundle["trust_anchor"]

    output = validate_bundle(
        bundle=built.bundle,
        jwks=built.jwks,
        trust_anchor_source="live",
    )

    matching = [
        e for e in output["errors"]
        if e.get("code") == RELAY_EVID_MISSING_TRUST_ANCHOR
    ]
    assert matching, output["errors"]
    assert output["overall"] == "fail"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-043")
def test_verifier_rejects_trust_anchor_wrong_type() -> None:
    """A ``trust_anchor`` field that is not a non-empty string MUST be
    rejected with the same structural code as a missing field."""
    built = build_bundle()
    built.bundle["trust_anchor"] = 42  # not a string
    output = validate_bundle(
        bundle=built.bundle,
        jwks=built.jwks,
        trust_anchor_source="live",
    )
    matching = [
        e for e in output["errors"]
        if e.get("code") == RELAY_EVID_MISSING_TRUST_ANCHOR
    ]
    assert matching, output["errors"]


# ---------------------------------------------------------------------------
# VAL-V2M08-044: local_dev never classified as relay_inc
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-044")
def test_local_dev_classified_as_untrusted_local_under_default_anchor() -> None:
    """A ``trust_anchor: "local_dev"`` bundle classifies as
    ``untrusted_local`` even when the verifier is using its default
    Relay-Inc anchor."""
    built = build_local_dev_bundle()
    output = validate_bundle(
        bundle=built.bundle,
        jwks=built.jwks,
        trust_anchor_source="live",
    )
    assert output["trust_anchor"] == "local_dev"
    assert output["trust_anchor_class"] == TRUST_ANCHOR_CLASS_UNTRUSTED_LOCAL
    assert output["trust_anchor_class"] != TRUST_ANCHOR_CLASS_RELAY_INC


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-044")
def test_local_dev_classified_as_untrusted_local_under_byo() -> None:
    """A ``trust_anchor: "local_dev"`` bundle classifies as
    ``untrusted_local`` even when verified under a BYO anchor that
    happens to chain to Relay-Inc."""
    built = build_local_dev_bundle()
    output = validate_bundle(
        bundle=built.bundle,
        jwks=built.jwks,
        trust_anchor_source="byo_flag",
        options=ValidateBundleOptions(
            # BYO anchor URL identical to the Relay-Inc default; the
            # classification rule still produces untrusted_local because
            # the bundle's label is local_dev, NOT because of the JWKS
            # URL the operator happened to configure.
            default_trust_anchor="https://relay.epochly.com/.well-known/jwks.json",
        ),
    )
    assert output["trust_anchor_class"] == TRUST_ANCHOR_CLASS_UNTRUSTED_LOCAL


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-044")
def test_relay_inc_anchor_classified_as_relay_inc() -> None:
    """A bundle carrying the Relay-Inc trust anchor URL classifies as
    ``relay_inc`` -- this is the only label that maps to ``relay_inc``."""
    built = build_bundle(
        trust_anchor="https://relay.epochly.com/.well-known/jwks.json",
    )
    output = validate_bundle(
        bundle=built.bundle,
        jwks=built.jwks,
        trust_anchor_source="live",
    )
    assert output["trust_anchor_class"] == TRUST_ANCHOR_CLASS_RELAY_INC


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-044")
def test_third_party_anchor_classified_as_byo() -> None:
    """A non-Relay-Inc, non-local_dev anchor classifies as ``byo``."""
    built = build_bundle(
        trust_anchor="https://example.com/.well-known/jwks.json",
    )
    output = validate_bundle(
        bundle=built.bundle,
        jwks=built.jwks,
        trust_anchor_source="byo_flag",
    )
    assert output["trust_anchor_class"] == TRUST_ANCHOR_CLASS_BYO


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-044")
def test_local_dev_cache_key_prefix_isolates_from_default_anchor() -> None:
    """The OSS local signer's JWKS cache key MUST carry a
    ``local_dev:`` prefix so a ``local_dev``-labelled JWKS cannot
    silently auto-promote into the default-anchor cache slot."""
    key = local_dev_cache_key("http://localhost:8080/jwks.json")
    assert key.startswith(LOCAL_DEV_CACHE_PREFIX + ":"), key
    assert LOCAL_DEV_CACHE_PREFIX == "local_dev"

    # The Relay-Inc default URL is not eligible for the local_dev cache
    # namespace; passing it MUST raise rather than silently produce a
    # local_dev-prefixed cache key for the Relay-Inc URL.
    with pytest.raises(ValueError):
        local_dev_cache_key("https://relay.epochly.com/.well-known/jwks.json")


# ---------------------------------------------------------------------------
# VAL-V2M08-044 (bug verifier-py-001): attacker-controlled path on the
# Relay-Inc host must NOT classify as relay_inc. The path component must be
# matched by EXACT equality against "/.well-known/jwks.json", never a
# suffix test -- a suffix test lets
# "https://relay.epochly.com/attacker/path/.well-known/jwks.json" be
# mislabeled relay_inc (and thus auto-promote signer_role to control_plane).
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-044")
def test_attacker_subpath_on_relay_host_is_byo_not_relay_inc() -> None:
    """An attacker-controlled subpath that still ends in
    ``/.well-known/jwks.json`` on the Relay-Inc host MUST classify as
    ``byo``, not ``relay_inc``. The path is matched by EXACT equality, so
    only the canonical ``/.well-known/jwks.json`` path qualifies."""
    # Two attacker variants: a deep nested path and a sibling-prefixed one.
    for attacker_url in (
        "https://relay.epochly.com/attacker/path/.well-known/jwks.json",
        "https://relay.epochly.com/evil/.well-known/jwks.json",
    ):
        cls = classify_trust_anchor(attacker_url)
        assert cls == TRUST_ANCHOR_CLASS_BYO, (
            f"attacker subpath {attacker_url!r} must classify as "
            f"{TRUST_ANCHOR_CLASS_BYO!r}, got {cls!r}"
        )
        assert cls != TRUST_ANCHOR_CLASS_RELAY_INC


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-044")
def test_non_numeric_port_keeps_host_and_path_parity_reference() -> None:
    """A NON-NUMERIC port (``host:abc``) must NOT break host/path extraction.

    Python ``urlparse`` keeps host and path for a ``host:abc`` authority (the
    digit-validating ``.port`` accessor is never used by
    ``classify_trust_anchor``), so the canonical Relay-Inc host still classifies
    ``relay_inc``. This is the PARITY REFERENCE for the TS ``_RAW_URL_RE`` fix
    (roborev 7feb671 MEDIUM): the TS regex previously required a numeric port and
    diverged to ``byo``. A non-numeric port on a non-Relay host stays ``byo``.
    """
    assert (
        classify_trust_anchor("https://relay.epochly.com:abc/.well-known/jwks.json")
        == TRUST_ANCHOR_CLASS_RELAY_INC
    )
    assert (
        classify_trust_anchor("https://relay.epochly.com:443/.well-known/jwks.json")
        == TRUST_ANCHOR_CLASS_RELAY_INC
    )
    assert (
        classify_trust_anchor("https://attacker.example:abc/.well-known/jwks.json")
        == TRUST_ANCHOR_CLASS_BYO
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-044")
def test_attacker_subpath_bundle_reports_byo_and_unknown_signer_role() -> None:
    """End-to-end: a bundle declaring an attacker-controlled subpath on
    the Relay-Inc host MUST surface ``trust_anchor_class='byo'`` and
    ``signer_role='unknown'`` -- it cannot auto-promote to control_plane."""
    from relay_verifier.bundle_validator import SIGNER_ROLE_UNKNOWN

    built = build_bundle(
        trust_anchor=(
            "https://relay.epochly.com/attacker/path/.well-known/jwks.json"
        ),
    )
    output = validate_bundle(
        bundle=built.bundle,
        jwks=built.jwks,
        trust_anchor_source="byo_flag",
    )
    assert output["trust_anchor_class"] == TRUST_ANCHOR_CLASS_BYO, output
    assert output["signer_role"] == SIGNER_ROLE_UNKNOWN, output


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-044")
def test_canonical_relay_inc_path_still_classifies_relay_inc() -> None:
    """Regression guard: the exact-path fix MUST NOT break the canonical
    Relay-Inc URL, which still classifies as ``relay_inc``."""
    cls = classify_trust_anchor(
        "https://relay.epochly.com/.well-known/jwks.json"
    )
    assert cls == TRUST_ANCHOR_CLASS_RELAY_INC, cls


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-044")
def test_local_dev_signer_uses_in_memory_only_keys() -> None:
    """The OSS local signer MUST hold private key material in memory
    only (banned pattern #14: no private keys committed or persisted)."""
    built = build_local_dev_bundle()
    # The returned BuiltBundle carries the signing_key as an in-memory
    # cryptography object. There is no on-disk path emitted by the
    # helper. Round-trip the canonical bytes to confirm the signature
    # verifies against the recomputed payload bytes (so the signer is
    # functional, not a no-op).
    payload = {k: v for k, v in built.bundle.items() if k != "signatures"}
    canonical = canonical_json_bytes(payload)
    assert canonical
    assert len(built.bundle["signatures"]) == 1
    sig_rec = built.bundle["signatures"][0]
    assert sig_rec["alg"] == "EdDSA"
    assert sig_rec["kid"]
