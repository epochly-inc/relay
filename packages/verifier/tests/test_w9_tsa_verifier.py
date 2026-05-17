"""w9-2 cryptographic TSA verification contract tests (VAL-V2M09-015..019).

This file covers the M09 milestone's TSA real-crypto assertions:

  * VAL-V2M09-015: ``validate_tsa_token`` decodes the RFC 3161
    ``TimeStampResp`` ASN.1 structure via ``rfc3161_client``
    (which delegates to ``asn1crypto`` for ASN.1 parsing).
  * VAL-V2M09-016: SignerInfo verifies against the bundled cert chain;
    a leaf chained to a self-signed root NOT in the bundled chain
    returns ``reason="tsa_cert_chain_unknown_root"``.
  * VAL-V2M09-017: forged TSA signature (one byte mutated in the
    SignedData blob) is rejected with
    ``reason="tsa_signature_invalid"``.
  * VAL-V2M09-018: a real Sigstore TSA token verifies end-to-end (gated
    by ``RLY_TEST_ALLOW_NETWORK=1`` so CI can opt-in / dev can opt-out).
  * VAL-V2M09-019: skew threshold parametrised at 0/299/301/86400 seconds.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import ast
import base64
import inspect
import os
import sys
from pathlib import Path

import pytest

# conftest helpers live alongside this test module; mirror the
# sibling-import pattern from test_w10_4_*.py.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from conftest_w10_4 import (  # noqa: E402
    _build_real_tsr_der,
    _make_test_tsa_chain,
    _shift_iso,
    build_bundle,
)
from relay_verifier import (  # noqa: E402
    RELAY_EVID_031,
    RELAY_EVID_038,
    ValidateBundleOptions,
    validate_bundle,
)
from relay_verifier import tsa as _tsa_module  # noqa: E402
from relay_verifier.tsa import validate_tsa_token  # noqa: E402


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


# ---------------------------------------------------------------------------
# VAL-V2M09-015: ASN.1 decode + message_imprint mismatch handling
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M09-015")
def test_validate_tsa_token_calls_real_asn1_decoder() -> None:
    """Static AST inspection of ``relay_verifier.tsa`` MUST show a call
    into ``rfc3161_client.decode_timestamp_response`` (the asn1crypto-
    backed RFC 3161 decoder).

    Per VAL-V2M09-015 the verifier decodes via either
    ``asn1crypto.tsp.TimeStampResp.load(...)`` OR
    ``rfc3161_client.TimeStampResponse.from_der(...)``;
    ``rfc3161_client.decode_timestamp_response`` is the
    asn1crypto-backed entrypoint for the latter.
    """
    source = inspect.getsource(_tsa_module)
    tree = ast.parse(source)
    found = False
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "rfc3161_client"
            and node.attr == "decode_timestamp_response"
        ):
            found = True
            break
    assert found, (
        "relay_verifier.tsa must invoke rfc3161_client.decode_timestamp_response "
        "(the asn1crypto-backed RFC 3161 decoder) per VAL-V2M09-015."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M09-015")
def test_validate_tsa_token_rejects_message_imprint_mismatch() -> None:
    """A token whose declared ``hashed_message_hex`` does not match the
    bundle binding digest MUST return
    ``TSAValidationResult(outcome="invalid", reason="message_imprint_mismatch",
    code="RELAY-EVID-031")``."""
    from cryptography.hazmat.primitives import serialization as _ser

    leaf_sk, leaf_cert, root_cert = _make_test_tsa_chain()
    real_digest_hex = "ab" * 32
    tampered_digest_hex = "cd" * 32
    decided_at = "2026-05-15T12:00:00Z"

    tsr_der = _build_real_tsr_der(
        leaf_sk=leaf_sk,
        leaf_cert=leaf_cert,
        bundle_digest_hex=real_digest_hex,
        gen_time_iso_z=decided_at,
    )
    # Token declares the tampered digest (NOT real_digest_hex) -- the
    # structural binding check fires before crypto.
    token = {
        "version": 1,
        "policy_oid": "1.3.6.1.4.1.601.10.3.1",
        "message_imprint": {
            "hash_algorithm": "sha256",
            "hashed_message_hex": tampered_digest_hex,
        },
        "serial_number": "424242",
        "gen_time": decided_at,
        "tsa_signature_alg": "ES256",
        "tsa_signer_cert_subject": leaf_cert.subject.rfc4514_string(),
        "tsr_der_b64u": _b64u(tsr_der),
    }
    result = validate_tsa_token(
        token=token,
        bundle_digest_hex=real_digest_hex,  # the verifier-recomputed digest
        decided_at=decided_at,
        extra_trusted_roots_pem=root_cert.public_bytes(_ser.Encoding.PEM),
    )
    assert result.outcome == "invalid"
    assert result.reason == "message_imprint_mismatch"
    assert result.code == RELAY_EVID_031


# ---------------------------------------------------------------------------
# VAL-V2M09-016: SignerInfo chains to bundled root (positive + negative)
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M09-016")
def test_signerinfo_chains_to_supplied_root_accepted() -> None:
    """A real RFC 3161 token whose SignerInfo's signing cert chains to a
    root supplied via ``extra_trusted_roots_pem`` MUST verify
    end-to-end and return ``outcome="ok"``."""
    from cryptography.hazmat.primitives import serialization as _ser

    leaf_sk, leaf_cert, root_cert = _make_test_tsa_chain()
    bundle_digest_hex = "12" * 32
    decided_at = "2026-05-15T12:00:00Z"

    tsr_der = _build_real_tsr_der(
        leaf_sk=leaf_sk,
        leaf_cert=leaf_cert,
        bundle_digest_hex=bundle_digest_hex,
        gen_time_iso_z=decided_at,
    )
    token = {
        "version": 1,
        "policy_oid": "1.3.6.1.4.1.601.10.3.1",
        "message_imprint": {
            "hash_algorithm": "sha256",
            "hashed_message_hex": bundle_digest_hex,
        },
        "serial_number": "424242",
        "gen_time": decided_at,
        "tsa_signature_alg": "ES256",
        "tsa_signer_cert_subject": leaf_cert.subject.rfc4514_string(),
        "tsr_der_b64u": _b64u(tsr_der),
    }
    result = validate_tsa_token(
        token=token,
        bundle_digest_hex=bundle_digest_hex,
        decided_at=decided_at,
        extra_trusted_roots_pem=root_cert.public_bytes(_ser.Encoding.PEM),
    )
    assert result.outcome == "ok", (result.outcome, result.reason)
    assert result.code == ""
    assert result.skew_seconds == 0


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M09-016")
def test_signerinfo_chained_to_unknown_root_rejected() -> None:
    """A real RFC 3161 token whose SignerInfo cert chains to a root NOT
    in the bundled chain AND NOT in extra_trusted_roots_pem MUST return
    ``reason="tsa_cert_chain_unknown_root"``."""
    # Generate the signer cert with chain A; build the verifier with
    # chain B (a different ephemeral root) -- no overlap. The leaf has
    # no trusted path.
    leaf_sk_a, leaf_cert_a, root_cert_a = _make_test_tsa_chain()
    _, _, root_cert_b = _make_test_tsa_chain()  # unrelated root

    from cryptography.hazmat.primitives import serialization as _ser
    bundle_digest_hex = "34" * 32
    decided_at = "2026-05-15T12:00:00Z"

    tsr_der = _build_real_tsr_der(
        leaf_sk=leaf_sk_a,
        leaf_cert=leaf_cert_a,
        bundle_digest_hex=bundle_digest_hex,
        gen_time_iso_z=decided_at,
    )
    token = {
        "version": 1,
        "policy_oid": "1.3.6.1.4.1.601.10.3.1",
        "message_imprint": {
            "hash_algorithm": "sha256",
            "hashed_message_hex": bundle_digest_hex,
        },
        "serial_number": "424242",
        "gen_time": decided_at,
        "tsa_signature_alg": "ES256",
        "tsa_signer_cert_subject": leaf_cert_a.subject.rfc4514_string(),
        "tsr_der_b64u": _b64u(tsr_der),
    }
    # Verify with root B only -- chain cannot resolve.
    result = validate_tsa_token(
        token=token,
        bundle_digest_hex=bundle_digest_hex,
        decided_at=decided_at,
        chain_certs=None,
        extra_trusted_roots_pem=root_cert_b.public_bytes(_ser.Encoding.PEM),
    )
    assert result.outcome == "invalid"
    assert result.reason == "tsa_cert_chain_unknown_root"
    assert result.code == RELAY_EVID_031


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M09-016")
def test_bundled_chain_alone_rejects_test_signed_token() -> None:
    """A real RFC 3161 token signed by an ephemeral test root, verified
    against ONLY the wheel-bundled placeholder TSA chain (no extra
    roots), MUST be rejected. The bundled chain has no private-key
    counterpart in OSS so it cannot sign tokens; any test token chains
    to a different root and yields
    ``reason="tsa_cert_chain_unknown_root"``."""
    from relay_verifier.tsa import (
        load_bundled_tsa_chain,
        load_tsa_chain_pem_bytes,
    )

    leaf_sk, leaf_cert, _root_cert = _make_test_tsa_chain()
    bundle_digest_hex = "56" * 32
    decided_at = "2026-05-15T12:00:00Z"

    tsr_der = _build_real_tsr_der(
        leaf_sk=leaf_sk,
        leaf_cert=leaf_cert,
        bundle_digest_hex=bundle_digest_hex,
        gen_time_iso_z=decided_at,
    )
    token = {
        "version": 1,
        "policy_oid": "1.3.6.1.4.1.601.10.3.1",
        "message_imprint": {
            "hash_algorithm": "sha256",
            "hashed_message_hex": bundle_digest_hex,
        },
        "serial_number": "424242",
        "gen_time": decided_at,
        "tsa_signature_alg": "ES256",
        "tsa_signer_cert_subject": leaf_cert.subject.rfc4514_string(),
        "tsr_der_b64u": _b64u(tsr_der),
    }
    _, chain_bytes = load_bundled_tsa_chain()
    bundled_certs = load_tsa_chain_pem_bytes(chain_bytes)
    result = validate_tsa_token(
        token=token,
        bundle_digest_hex=bundle_digest_hex,
        decided_at=decided_at,
        chain_certs=bundled_certs,
        extra_trusted_roots_pem=None,
    )
    assert result.outcome == "invalid"
    assert result.reason == "tsa_cert_chain_unknown_root"
    assert result.code == RELAY_EVID_031


# ---------------------------------------------------------------------------
# VAL-V2M09-017: forged TSA signature (one byte mutated) rejected
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M09-017")
def test_forged_tsa_signature_byte_mutation_rejected() -> None:
    """Mutating one byte of the SignedData blob inside the TSR DER MUST
    cause cryptographic rejection. The verifier returns
    ``outcome="invalid"`` with reason in
    ``{"tsa_signature_invalid", "tsa_cert_chain_unknown_root",
    "tsr_decode_failed"}`` -- ANY mutation in the SignedData portion
    breaks the OpenSSL PKCS#7 verify; the exact reason depends on where
    in the DER the byte landed (signature octets, certificate octets,
    or structural framing).

    Pre-mutation check is in the companion test
    `test_signerinfo_chains_to_supplied_root_accepted`.
    """
    from cryptography.hazmat.primitives import serialization as _ser

    leaf_sk, leaf_cert, root_cert = _make_test_tsa_chain()
    bundle_digest_hex = "78" * 32
    decided_at = "2026-05-15T12:00:00Z"

    tsr_der = _build_real_tsr_der(
        leaf_sk=leaf_sk,
        leaf_cert=leaf_cert,
        bundle_digest_hex=bundle_digest_hex,
        gen_time_iso_z=decided_at,
    )
    # Sanity: pre-mutation verifies OK.
    pre_token = {
        "version": 1,
        "policy_oid": "1.3.6.1.4.1.601.10.3.1",
        "message_imprint": {
            "hash_algorithm": "sha256",
            "hashed_message_hex": bundle_digest_hex,
        },
        "serial_number": "424242",
        "gen_time": decided_at,
        "tsa_signature_alg": "ES256",
        "tsa_signer_cert_subject": leaf_cert.subject.rfc4514_string(),
        "tsr_der_b64u": _b64u(tsr_der),
    }
    pre = validate_tsa_token(
        token=pre_token,
        bundle_digest_hex=bundle_digest_hex,
        decided_at=decided_at,
        extra_trusted_roots_pem=root_cert.public_bytes(_ser.Encoding.PEM),
    )
    assert pre.outcome == "ok", f"pre-mutation must verify; got {pre!r}"

    # Mutate a byte near the END of the DER (likely inside the ECDSA
    # signature OCTET STRING) to maximise the chance of hitting the
    # signature itself.
    mutated = bytearray(tsr_der)
    mutated[-15] ^= 0xFF
    post_token = dict(pre_token)
    post_token["tsr_der_b64u"] = _b64u(bytes(mutated))
    post = validate_tsa_token(
        token=post_token,
        bundle_digest_hex=bundle_digest_hex,
        decided_at=decided_at,
        extra_trusted_roots_pem=root_cert.public_bytes(_ser.Encoding.PEM),
    )
    assert post.outcome == "invalid", (
        f"post-mutation must be rejected; got {post.outcome!r} reason={post.reason!r}"
    )
    assert post.reason in {
        "tsa_signature_invalid",
        "tsa_cert_chain_unknown_root",
    } or post.reason.startswith("tsr_decode_failed"), (
        f"unexpected post-mutation reason: {post.reason!r}"
    )
    assert post.code == RELAY_EVID_031


# ---------------------------------------------------------------------------
# VAL-V2M09-018: real Sigstore TSA token accepted (network-gated)
# ---------------------------------------------------------------------------


@pytest.mark.smoke
@pytest.mark.fulfills("VAL-V2M09-018")
@pytest.mark.skipif(
    not os.environ.get("RLY_TEST_ALLOW_NETWORK"),
    reason=(
        "VAL-V2M09-018 requires network egress to https://timestamp.sigstore.dev. "
        "Gated by RLY_TEST_ALLOW_NETWORK=1 per the contract assertion."
    ),
)
def test_real_sigstore_tsa_token_accepted() -> None:
    """Fetch a real RFC 3161 timestamp from Sigstore's public TSA, store
    its DER + the Sigstore-cert-bundled chain inside a structured token,
    and verify end-to-end through :func:`validate_tsa_token`. Result MUST
    be ``outcome="ok"`` with skew_seconds <= 300 s and gen_time parseable
    back to an ISO-8601 timestamp.

    The Sigstore TSA's cert chain is fetched alongside the timestamp
    response (via rfc3161_client's `cert_request=True` flag, default) and
    materialised through `extra_trusted_roots_pem` so the verifier
    chains correctly. We do NOT commit the chain to disk; per
    VAL-V2M09-020 + banned pattern #14 no TSA private-key material lands
    in the repo, and we extend that policy to "no TSA roots committed"
    via the network-gated fetch path.
    """
    import datetime as _dt
    import hashlib
    import urllib.error
    import urllib.request

    import rfc3161_client

    artifact = b"VAL-V2M09-018-fixture-artifact"
    imprint = hashlib.sha256(artifact).digest()

    req_builder = rfc3161_client.TimestampRequestBuilder()
    req_builder = req_builder.data(artifact).hash_algorithm(
        rfc3161_client.HashAlgorithm.SHA256,
    )
    req = req_builder.build()
    req_bytes = req.as_bytes()

    tsa_url = "https://timestamp.sigstore.dev/api/v1/timestamp"
    try:
        http_req = urllib.request.Request(
            tsa_url,
            data=req_bytes,
            headers={"Content-Type": "application/timestamp-query"},
            method="POST",
        )
        with urllib.request.urlopen(http_req, timeout=30) as resp:
            tsr_der = resp.read()
    except (urllib.error.URLError, TimeoutError) as exc:
        pytest.skip(f"sigstore TSA unreachable: {exc}")

    # Decode the TSR. Sigstore's response embeds only the TSA leaf cert
    # (no root); fetch the full TSA cert chain from Sigstore's published
    # /api/v1/timestamp/certchain endpoint (leaf + self-signed root in
    # PEM). The chain is used as ``extra_trusted_roots_pem`` so the
    # verifier can build a path from the leaf in the response up to the
    # self-signed root in the chain.
    ts_response = rfc3161_client.decode_timestamp_response(tsr_der)

    try:
        with urllib.request.urlopen(
            "https://timestamp.sigstore.dev/api/v1/timestamp/certchain",
            timeout=30,
        ) as chain_resp:
            extra_trusted_roots_pem = chain_resp.read()
    except (urllib.error.URLError, TimeoutError) as exc:
        pytest.skip(f"sigstore TSA certchain unreachable: {exc}")

    gen_time_iso_z = ts_response.tst_info.gen_time.astimezone(_dt.UTC).isoformat()
    gen_time_iso_z = gen_time_iso_z.replace("+00:00", "Z")

    bundle_digest_hex = imprint.hex()
    decided_at_dt = ts_response.tst_info.gen_time.astimezone(_dt.UTC)
    decided_at_iso_z = decided_at_dt.isoformat().replace("+00:00", "Z")

    token = {
        "version": 1,
        "policy_oid": "1.3.6.1.4.1.601.10.3.1",
        "message_imprint": {
            "hash_algorithm": "sha256",
            "hashed_message_hex": bundle_digest_hex,
        },
        "serial_number": "0",
        "gen_time": gen_time_iso_z,
        "tsa_signature_alg": "ES256",
        "tsa_signer_cert_subject": "fetched-from-sigstore",
        "tsr_der_b64u": _b64u(tsr_der),
    }
    result = validate_tsa_token(
        token=token,
        bundle_digest_hex=bundle_digest_hex,
        decided_at=decided_at_iso_z,
        chain_certs=None,
        extra_trusted_roots_pem=extra_trusted_roots_pem,
    )
    assert result.outcome == "ok", (result.outcome, result.reason)
    assert result.skew_seconds >= 0
    assert result.skew_seconds <= 300
    # gen_time parseable back to ISO-8601.
    _ = _dt.datetime.fromisoformat(result.gen_time[:-1] + "+00:00")


# ---------------------------------------------------------------------------
# VAL-V2M09-019: skew threshold parametrised
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M09-019")
@pytest.mark.parametrize(
    "skew_seconds, expected_outcome, expected_code",
    [
        (0, "ok", ""),
        (299, "ok", ""),
        (301, "skew", RELAY_EVID_038),
        (86400, "skew", RELAY_EVID_038),
        (-299, "ok", ""),
        (-301, "skew", RELAY_EVID_038),
    ],
)
def test_tsa_skew_threshold_parametrised(
    skew_seconds: int,
    expected_outcome: str,
    expected_code: str,
) -> None:
    """``validate_tsa_token`` MUST enforce the ±300 s skew window
    boundary-exactly. 0 s and ±299 s accept; ±301 s and ±86400 s reject
    with RELAY-EVID-038."""
    from cryptography.hazmat.primitives import serialization as _ser

    leaf_sk, leaf_cert, root_cert = _make_test_tsa_chain()
    bundle_digest_hex = "9a" * 32
    decided_at = "2026-05-15T12:00:00Z"
    gen_time = _shift_iso(decided_at, skew_seconds)

    tsr_der = _build_real_tsr_der(
        leaf_sk=leaf_sk,
        leaf_cert=leaf_cert,
        bundle_digest_hex=bundle_digest_hex,
        gen_time_iso_z=gen_time,
    )
    token = {
        "version": 1,
        "policy_oid": "1.3.6.1.4.1.601.10.3.1",
        "message_imprint": {
            "hash_algorithm": "sha256",
            "hashed_message_hex": bundle_digest_hex,
        },
        "serial_number": "424242",
        "gen_time": gen_time,
        "tsa_signature_alg": "ES256",
        "tsa_signer_cert_subject": leaf_cert.subject.rfc4514_string(),
        "tsr_der_b64u": _b64u(tsr_der),
    }
    result = validate_tsa_token(
        token=token,
        bundle_digest_hex=bundle_digest_hex,
        decided_at=decided_at,
        extra_trusted_roots_pem=root_cert.public_bytes(_ser.Encoding.PEM),
    )
    assert result.outcome == expected_outcome, (
        f"skew={skew_seconds}s expected {expected_outcome!r}, "
        f"got {result.outcome!r} (reason={result.reason!r})"
    )
    assert result.code == expected_code
    assert result.skew_seconds == abs(skew_seconds)


# ---------------------------------------------------------------------------
# Integration: validate_bundle wires the bundled chain + extra roots
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M09-005")
def test_validate_bundle_passes_extra_trusted_roots_through() -> None:
    """End-to-end: a bundle built with the ephemeral test root passes
    overall when ``ValidateBundleOptions.tsa_extra_trusted_roots_pem``
    is supplied; the same bundle fails without it (the test root is
    not in the wheel-bundled chain)."""
    built = build_bundle()

    # With the option: pass.
    output_ok = validate_bundle(
        bundle=built.bundle,
        jwks=built.jwks,
        options=ValidateBundleOptions(
            tsa_extra_trusted_roots_pem=built.tsa_extra_roots_pem,
        ),
    )
    assert output_ok["overall"] == "pass", output_ok
    assert output_ok["tsa_check"] == "ok"

    # Without the option: TSA fails with chain-unknown-root.
    output_bad = validate_bundle(
        bundle=built.bundle,
        jwks=built.jwks,
    )
    assert output_bad["overall"] == "fail"
    assert output_bad["tsa_check"] == "invalid"
