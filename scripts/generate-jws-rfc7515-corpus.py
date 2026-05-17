"""W10.2 RFC 7515 JWS conformance corpus generator (VAL-W10-010, VAL-W10-015).

Generates ``tests/conformance/jws/rfc7515_corpus.json`` containing a frozen
set of compact-form JWS vectors plus a JWKS trust anchor. Each case carries
a deterministic expected verdict; the Python and TypeScript verifier
implementations both load this single file and run identical assertions
against it. Cross-language verdict parity is byte-equal because both
verifiers serialize their per-case verdict via canonical JSON (sort_keys,
compact separators) and compare the resulting hash.

The corpus is **partly deterministic**: EdDSA (RFC 8032 seeded) and
ES256 (label-derived scalar) keys come from fixed seeds, all non-key
fields are literal strings, no clock is read. The RS256 key is
generated at script runtime via ``rsa.generate_private_key`` (per
CLAUDE.md banned pattern #14 / VAL-V2M09-020 no PEM-encoded private
key may live in the repo), so the RS256 signature bytes and the RSA
JWK ``n`` value change per run. The corpus remains internally
consistent: signatures verify against the embedded JWKS regardless of
which RSA key was used. Cross-runtime (Python vs TypeScript) verdict
parity is preserved because both verifiers load the same on-disk
corpus.

Coverage matrix (case_id prefix -> assertion):

  * positive-*           VAL-W10-010 positive vectors (valid signatures
                          for EdDSA, ES256, RS256)
  * neg-tamper-*         VAL-W10-010 tampered payload / tampered header
                          / wrong key / unknown kid
  * neg-alg-none-*       VAL-W10-011 + VAL-W10-014 + RFC 8725 section 3.1
                          (alg=none rejected without computing signature)
  * neg-alg-hs256-*      VAL-W10-011 + RFC 8725 section 3.2 (HS256 over
                          RSA / EC public key -- the classic substitution
                          attack)
  * neg-alg-disallowed-* VAL-W10-014 (HS256, RS1, vendor.alg, missing alg)
  * detached-*           VAL-W10-012 detached-JWS payload binding
  * multisig-*           VAL-W10-013 multi-signature bundle vectors

The corpus is checked into the repo because:

  1. The TypeScript verifier package has no Python interpreter at test
     time -- it cannot regenerate.
  2. Reproducing the byte-equal verdict assertion requires both runtimes
     observing the same input bytes; a corpus that drifts between runs
     would defeat VAL-W10-015 parity.
  3. The corpus pins the verifier's behavior at the byte level, so a
     change to the verifier that silently flips a verdict is caught by
     diffing the run output against the corpus.

Re-running the generator after a deliberate corpus change MUST be paired
with regenerating both Python and TS test snapshots in the same commit.

Happy path:

    $ uv run python scripts/generate-jws-rfc7515-corpus.py
    [check] wrote 18 cases to tests/conformance/jws/rfc7515_corpus.json
    exit 0

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

SCHEMA_VERSION = "relay.conformance.jws.v1"

# -----------------------------------------------------------------------------
# Key material (mixed deterministic / runtime-generated)
# -----------------------------------------------------------------------------
#
# Per VAL-V2M09-020 / CLAUDE.md banned pattern #14, NO PEM-encoded
# private key may appear in this repo. We accordingly use two
# strategies:
#
# * Ed25519 + ES256 keys are derived from FIXED seeds (the seed bytes
#   are corpus-only test material, not production secrets). This keeps
#   their portions of the corpus byte-stable across regenerations.
# * RS256 keys are GENERATED AT RUNTIME via rsa.generate_private_key
#   (see _generate_rsa_2048_private_key below). The RSA-keyed portions
#   of the corpus (the positive-rs256 signature; the rs256 JWK n/e
#   bytes) therefore differ between runs. Internal consistency is
#   preserved: the JWKS we write is the public half of the same key
#   that signed the corpus's RS256 vector.
#
# Cross-runtime parity is preserved because both Python and TypeScript
# verifiers load the same on-disk corpus + JWKS and verify
# cryptographically; neither relies on the corpus being byte-stable
# across regenerations.

# Ed25519: 32-byte seed (NOT a real production secret; corpus-only).
_ED25519_SEED = b"relay-corpus-eddsa-key-32-byte!"  # noqa: E501 -- exactly 31 chars, padded below
assert len(_ED25519_SEED) == 31
_ED25519_SEED = _ED25519_SEED + b"!"  # pad to 32 bytes
assert len(_ED25519_SEED) == 32

# ES256: derive private scalar from SHA-256 of a fixed label, reduce mod
# group order. Per SEC1 / RFC 6979 a uniform integer in [1, n-1] is a
# valid private key. Using a non-uniform truncation here is fine because
# the corpus secret is never used outside the corpus; the verifier
# treats this as just another public key.
_ES256_SEED_LABEL = b"relay-corpus-es256-key-derivation-label-v1"

# Group order n for P-256 (secp256r1).
# https://www.secg.org/sec2-v2.pdf section 2.4.2
_P256_N = int(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
    16,
)


def _es256_private_int_from_label(label: bytes) -> int:
    """Return a P-256 private scalar in [1, n-1] derived from a label."""
    h = hashlib.sha256(label).digest()
    k = int.from_bytes(h, "big") % (_P256_N - 1) + 1
    return k


# RS256: cryptography.generate_private_key is non-deterministic. To
# satisfy CLAUDE.md banned pattern #14 / VAL-V2M09-020 (no private-key
# PEM material committed to the repo) we generate the RSA-2048 keypair
# at script runtime via cryptography.generate_private_key. The key is
# held in memory for the duration of the generator run and is never
# written to disk in any form. Each invocation of this script produces
# a fresh RSA-2048 keypair; the resulting corpus signatures and JWKS
# n/e bytes therefore differ between runs.
#
# Cross-runtime parity (the Python verifier and the TypeScript verifier
# read the SAME on-disk corpus and produce byte-equal verdicts) is
# preserved because both verifiers load the JWKS and the signatures
# from the corpus itself; the verdict depends only on signature-JWK
# consistency, not on which specific RSA key produced the corpus.
#
# Determinism for non-RSA cases (EdDSA, ES256, HS) is preserved -- those
# keys are derived from fixed seeds, so their corpus bytes are byte-
# stable across regenerations.


def _generate_rsa_2048_private_key() -> rsa.RSAPrivateKey:
    """Return a fresh RSA-2048 private key generated at runtime.

    Per CLAUDE.md banned pattern #14 the RSA key MUST be generated at
    runtime; no PEM-encoded RSA private key may appear in the repo.
    Caller holds the returned key in memory only for the duration of
    the generator run.
    """
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


# -----------------------------------------------------------------------------
# Base64URL helpers (RFC 4648 sec 5; unpadded form per RFC 7515)
# -----------------------------------------------------------------------------


def b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def b64u_decode(s: str) -> bytes:
    padding_chars = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding_chars)


# -----------------------------------------------------------------------------
# JWK builders
# -----------------------------------------------------------------------------


def _ed25519_jwk(public_key: ed25519.Ed25519PublicKey, kid: str) -> dict[str, Any]:
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "kid": kid,
        "alg": "EdDSA",
        "use": "sig",
        "x": b64u_encode(raw),
    }


def _es256_jwk(public_key: ec.EllipticCurvePublicKey, kid: str) -> dict[str, Any]:
    nums = public_key.public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "kid": kid,
        "alg": "ES256",
        "use": "sig",
        "x": b64u_encode(nums.x.to_bytes(32, "big")),
        "y": b64u_encode(nums.y.to_bytes(32, "big")),
    }


def _rs256_jwk(public_key: rsa.RSAPublicKey, kid: str) -> dict[str, Any]:
    nums = public_key.public_numbers()
    n_bytes = nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")
    e_bytes = nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big")
    return {
        "kty": "RSA",
        "kid": kid,
        "alg": "RS256",
        "use": "sig",
        "n": b64u_encode(n_bytes),
        "e": b64u_encode(e_bytes),
    }


# -----------------------------------------------------------------------------
# Compact-form JWS builder
# -----------------------------------------------------------------------------


def _compact(header: dict[str, Any], payload: bytes, signature: bytes) -> str:
    header_b64 = b64u_encode(
        json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    payload_b64 = b64u_encode(payload)
    sig_b64 = b64u_encode(signature)
    return f"{header_b64}.{payload_b64}.{sig_b64}"


def _signing_input(header: dict[str, Any], payload: bytes) -> bytes:
    header_b64 = b64u_encode(
        json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    payload_b64 = b64u_encode(payload)
    return f"{header_b64}.{payload_b64}".encode("ascii")


def _sign_eddsa(
    priv: ed25519.Ed25519PrivateKey, header: dict[str, Any], payload: bytes
) -> str:
    inp = _signing_input(header, payload)
    sig = priv.sign(inp)
    return _compact(header, payload, sig)


def _sign_es256(
    priv: ec.EllipticCurvePrivateKey,
    header: dict[str, Any],
    payload: bytes,
) -> str:
    inp = _signing_input(header, payload)
    der = priv.sign(inp, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return _compact(header, payload, raw)


def _sign_rs256(
    priv: rsa.RSAPrivateKey, header: dict[str, Any], payload: bytes
) -> str:
    inp = _signing_input(header, payload)
    sig = priv.sign(inp, padding.PKCS1v15(), hashes.SHA256())
    return _compact(header, payload, sig)


# -----------------------------------------------------------------------------
# Case construction
# -----------------------------------------------------------------------------


def _canonical_claim_bytes(claim: dict[str, Any]) -> bytes:
    return json.dumps(claim, sort_keys=True, separators=(",", ":")).encode("utf-8")


def build_corpus() -> dict[str, Any]:
    # Keys
    eddsa_priv = ed25519.Ed25519PrivateKey.from_private_bytes(_ED25519_SEED)
    eddsa_pub = eddsa_priv.public_key()

    es256_priv_int = _es256_private_int_from_label(_ES256_SEED_LABEL)
    es256_priv = ec.derive_private_key(es256_priv_int, ec.SECP256R1())
    es256_pub = es256_priv.public_key()

    rsa_priv = _generate_rsa_2048_private_key()
    rsa_pub = rsa_priv.public_key()

    # Second EdDSA key for "wrong-key" negative cases
    eddsa2_priv = ed25519.Ed25519PrivateKey.from_private_bytes(
        b"relay-corpus-eddsa-wrong-key-32x"
    )
    eddsa2_pub = eddsa2_priv.public_key()

    kid_eddsa = "kid-eddsa-2026-05"
    kid_es256 = "kid-es256-2026-05"
    kid_rs256 = "kid-rs256-2026-05"
    kid_eddsa2 = "kid-eddsa-wrong-2026-05"

    jwks = {
        "keys": [
            _ed25519_jwk(eddsa_pub, kid_eddsa),
            _es256_jwk(es256_pub, kid_es256),
            _rs256_jwk(rsa_pub, kid_rs256),
            _ed25519_jwk(eddsa2_pub, kid_eddsa2),
        ]
    }

    payload_obj = {"iss": "relay-corpus", "sub": "vector-001", "n": 1}
    payload_bytes = _canonical_claim_bytes(payload_obj)

    cases: list[dict[str, Any]] = []

    # -- positive vectors -------------------------------------------------

    cases.append(
        {
            "name": "positive-eddsa",
            "kind": "compact",
            "input": _sign_eddsa(
                eddsa_priv,
                {"alg": "EdDSA", "kid": kid_eddsa, "typ": "JWT"},
                payload_bytes,
            ),
            "expected": {"ok": True, "kid": kid_eddsa, "alg": "EdDSA"},
        }
    )
    cases.append(
        {
            "name": "positive-es256",
            "kind": "compact",
            "input": _sign_es256(
                es256_priv,
                {"alg": "ES256", "kid": kid_es256, "typ": "JWT"},
                payload_bytes,
            ),
            "expected": {"ok": True, "kid": kid_es256, "alg": "ES256"},
        }
    )
    cases.append(
        {
            "name": "positive-rs256",
            "kind": "compact",
            "input": _sign_rs256(
                rsa_priv,
                {"alg": "RS256", "kid": kid_rs256, "typ": "JWT"},
                payload_bytes,
            ),
            "expected": {"ok": True, "kid": kid_rs256, "alg": "RS256"},
        }
    )

    # -- tampered payload (positive token with last byte of payload flipped)
    base_token = _sign_eddsa(
        eddsa_priv,
        {"alg": "EdDSA", "kid": kid_eddsa, "typ": "JWT"},
        payload_bytes,
    )
    h, p, s = base_token.split(".")
    # Flip one byte of the payload (decode, mutate, re-encode without re-signing)
    p_bytes = bytearray(b64u_decode(p))
    p_bytes[-1] ^= 0x01
    tampered_p = b64u_encode(bytes(p_bytes))
    cases.append(
        {
            "name": "neg-tamper-payload-eddsa",
            "kind": "compact",
            "input": f"{h}.{tampered_p}.{s}",
            "expected": {
                "ok": False,
                "reason_substring": "signature did not verify",
            },
        }
    )

    # -- tampered header (positive token with kid swapped to wrong key)
    swap_token = _sign_eddsa(
        eddsa_priv,
        {"alg": "EdDSA", "kid": kid_eddsa2, "typ": "JWT"},
        payload_bytes,
    )
    cases.append(
        {
            "name": "neg-tamper-header-wrong-kid",
            "kind": "compact",
            "input": swap_token,
            "expected": {
                "ok": False,
                "reason_substring": "signature did not verify",
            },
        }
    )

    # -- unknown kid
    cases.append(
        {
            "name": "neg-unknown-kid",
            "kind": "compact",
            "input": _sign_eddsa(
                eddsa_priv,
                {"alg": "EdDSA", "kid": "kid-not-in-jwks", "typ": "JWT"},
                payload_bytes,
            ),
            "expected": {
                "ok": False,
                "reason_substring": "no JWK in trust anchor matches kid",
            },
        }
    )

    # -- alg=none (RFC 8725 section 3.1). The signature segment is empty.
    none_header_b64 = b64u_encode(
        json.dumps(
            {"alg": "none", "kid": kid_eddsa, "typ": "JWT"},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )
    payload_b64 = b64u_encode(payload_bytes)
    cases.append(
        {
            "name": "neg-alg-none-empty-sig",
            "kind": "compact",
            "input": f"{none_header_b64}.{payload_b64}.",
            "expected": {
                "ok": False,
                "error_code": "RELAY-VERIFY-011",
                "reason_substring": "unsupported alg",
            },
        }
    )

    # -- alg=none with arbitrary garbage signature (still must reject)
    cases.append(
        {
            "name": "neg-alg-none-garbage-sig",
            "kind": "compact",
            "input": f"{none_header_b64}.{payload_b64}.{b64u_encode(b'GARBAGE')}",
            "expected": {
                "ok": False,
                "error_code": "RELAY-VERIFY-011",
                "reason_substring": "unsupported alg",
            },
        }
    )

    # -- HS256 over RSA public key (the classic substitution attack).
    # Compute an HMAC-SHA256 over the signing input using the RSA public-
    # key DER bytes as the secret -- this is the exact attack RFC 8725
    # section 3.2 warns against. A naive verifier that routes the JWK to
    # an HMAC primitive accepts it. Relay's verifier MUST reject before
    # invoking any HMAC primitive (alg-mismatch on lookup, OR alg not in
    # allow-list -- both forms reject).
    import hmac

    rsa_pub_der = rsa_pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    hs_header = {"alg": "HS256", "kid": kid_rs256, "typ": "JWT"}
    hs_inp = _signing_input(hs_header, payload_bytes)
    hs_sig = hmac.new(rsa_pub_der, hs_inp, hashlib.sha256).digest()
    cases.append(
        {
            "name": "neg-alg-hs256-over-rsa-public-key",
            "kind": "compact",
            "input": _compact(hs_header, payload_bytes, hs_sig),
            "expected": {
                "ok": False,
                "error_code": "RELAY-VERIFY-011",
                "reason_substring": "unsupported alg",
            },
        }
    )

    # -- HS256 over EdDSA public key (same family of attack, OKP variant)
    eddsa_pub_raw = eddsa_pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    hs_header2 = {"alg": "HS256", "kid": kid_eddsa, "typ": "JWT"}
    hs_inp2 = _signing_input(hs_header2, payload_bytes)
    hs_sig2 = hmac.new(eddsa_pub_raw, hs_inp2, hashlib.sha256).digest()
    cases.append(
        {
            "name": "neg-alg-hs256-over-eddsa-public-key",
            "kind": "compact",
            "input": _compact(hs_header2, payload_bytes, hs_sig2),
            "expected": {
                "ok": False,
                "error_code": "RELAY-VERIFY-011",
                "reason_substring": "unsupported alg",
            },
        }
    )

    # -- RS1 (deprecated SHA-1 RSA) MUST be rejected by allow-list
    rs1_header = {"alg": "RS1", "kid": kid_rs256, "typ": "JWT"}
    # Sign with SHA-1 to keep the bytes valid-ish; the verifier should
    # never reach the signature-verify step.
    rs1_sig = rsa_priv.sign(
        _signing_input(rs1_header, payload_bytes),
        padding.PKCS1v15(),
        hashes.SHA1(),
    )
    cases.append(
        {
            "name": "neg-alg-rs1-disallowed",
            "kind": "compact",
            "input": _compact(rs1_header, payload_bytes, rs1_sig),
            "expected": {
                "ok": False,
                "error_code": "RELAY-VERIFY-011",
                "reason_substring": "unsupported alg",
            },
        }
    )

    # -- vendor alg
    vendor_header_b64 = b64u_encode(
        json.dumps(
            {"alg": "vendor.custom-1", "kid": kid_eddsa, "typ": "JWT"},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )
    cases.append(
        {
            "name": "neg-alg-vendor-disallowed",
            "kind": "compact",
            "input": f"{vendor_header_b64}.{payload_b64}.{b64u_encode(b'x' * 64)}",
            "expected": {
                "ok": False,
                "error_code": "RELAY-VERIFY-011",
                "reason_substring": "unsupported alg",
            },
        }
    )

    # -- missing alg header field entirely
    bad_header_b64 = b64u_encode(
        json.dumps(
            {"kid": kid_eddsa, "typ": "JWT"},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )
    cases.append(
        {
            "name": "neg-alg-missing",
            "kind": "compact",
            "input": f"{bad_header_b64}.{payload_b64}.{b64u_encode(b'x' * 64)}",
            "expected": {
                "ok": False,
                "error_code": "RELAY-VERIFY-011",
                "reason_substring": "unsupported alg",
            },
        }
    )

    # -- malformed compact (only two segments)
    cases.append(
        {
            "name": "neg-malformed-two-segments",
            "kind": "compact",
            "input": f"{vendor_header_b64}.{payload_b64}",
            "expected": {
                "ok": False,
                "reason_substring": "compact JWS must have 3 segments",
            },
        }
    )

    # -- detached JWS with matching claim digest (positive)
    claim_obj = {"claim_id": "c-001", "kind": "artifact", "value": "abc"}
    claim_canonical = _canonical_claim_bytes(claim_obj)
    det_header = {"alg": "EdDSA", "kid": kid_eddsa, "b64": False, "crit": ["b64"]}
    # Per RFC 7797 detached payload: signing input is header_b64u || "." || raw payload
    det_header_b64 = b64u_encode(
        json.dumps(det_header, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    det_inp = det_header_b64.encode("ascii") + b"." + claim_canonical
    det_sig = eddsa_priv.sign(det_inp)
    cases.append(
        {
            "name": "detached-positive-eddsa",
            "kind": "detached",
            "input": {
                "protected_b64u": det_header_b64,
                "signature_b64u": b64u_encode(det_sig),
                "claim": claim_obj,
            },
            "expected": {"ok": True, "kid": kid_eddsa, "alg": "EdDSA"},
        }
    )

    # -- detached JWS with tampered claim (payload digest mismatch)
    tampered_claim = dict(claim_obj)
    tampered_claim["value"] = "XYZ"  # mutate without re-signing
    cases.append(
        {
            "name": "detached-negative-tampered-claim",
            "kind": "detached",
            "input": {
                "protected_b64u": det_header_b64,
                "signature_b64u": b64u_encode(det_sig),
                "claim": tampered_claim,
            },
            "expected": {
                "ok": False,
                "error_code": "RELAY-EVID-014",
                "reason_substring": "detached payload digest",
            },
        }
    )

    # -- multi-signature (N=2, both valid)
    multi_payload = {"bundle_id": "b-001", "kind": "multisig"}
    multi_bytes = _canonical_claim_bytes(multi_payload)
    sig_eddsa = eddsa_priv.sign(multi_bytes)
    der_es = es256_priv.sign(multi_bytes, ec.ECDSA(hashes.SHA256()))
    r_es, s_es = decode_dss_signature(der_es)
    sig_es = r_es.to_bytes(32, "big") + s_es.to_bytes(32, "big")
    cases.append(
        {
            "name": "multisig-n2-both-valid",
            "kind": "multisig",
            "input": {
                "payload": multi_payload,
                "signatures": [
                    {
                        "alg": "EdDSA",
                        "kid": kid_eddsa,
                        "signature_b64u": b64u_encode(sig_eddsa),
                    },
                    {
                        "alg": "ES256",
                        "kid": kid_es256,
                        "signature_b64u": b64u_encode(sig_es),
                    },
                ],
            },
            "expected": {
                "ok": True,
                "verdicts": [
                    {"kid": kid_eddsa, "alg": "EdDSA", "ok": True},
                    {"kid": kid_es256, "alg": "ES256", "ok": True},
                ],
            },
        }
    )

    # -- multi-signature (N=2, one valid, one invalid -> mixed)
    bad_es_sig = bytes(64)  # all zeros: never verifies under P-256
    cases.append(
        {
            "name": "multisig-n2-mixed",
            "kind": "multisig",
            "input": {
                "payload": multi_payload,
                "signatures": [
                    {
                        "alg": "EdDSA",
                        "kid": kid_eddsa,
                        "signature_b64u": b64u_encode(sig_eddsa),
                    },
                    {
                        "alg": "ES256",
                        "kid": kid_es256,
                        "signature_b64u": b64u_encode(bad_es_sig),
                    },
                ],
            },
            "expected": {
                "ok": False,
                "aggregate": "mixed",
                "verdicts": [
                    {"kid": kid_eddsa, "alg": "EdDSA", "ok": True},
                    {"kid": kid_es256, "alg": "ES256", "ok": False},
                ],
            },
        }
    )

    # -- multi-signature (N=6: cross-signing migration upper-bound check)
    # Generate six independent EdDSA keys from distinct seeds.
    multi6_keys: list[tuple[str, ed25519.Ed25519PrivateKey]] = []
    for i in range(6):
        seed = ("relay-multisig-key-" + str(i)).ljust(32, "x").encode("ascii")[:32]
        multi6_keys.append(
            ("kid-multisig-" + str(i), ed25519.Ed25519PrivateKey.from_private_bytes(seed))
        )

    # Add their public JWKs to the corpus JWKS.
    for kid, priv in multi6_keys:
        jwks["keys"].append(_ed25519_jwk(priv.public_key(), kid))

    multi6_payload = {"bundle_id": "b-002", "kind": "multisig-6"}
    multi6_bytes = _canonical_claim_bytes(multi6_payload)
    multi6_sigs = [
        {
            "alg": "EdDSA",
            "kid": kid,
            "signature_b64u": b64u_encode(priv.sign(multi6_bytes)),
        }
        for kid, priv in multi6_keys
    ]
    cases.append(
        {
            "name": "multisig-n6-all-valid",
            "kind": "multisig",
            "input": {"payload": multi6_payload, "signatures": multi6_sigs},
            "expected": {
                "ok": True,
                "verdicts": [
                    {"kid": kid, "alg": "EdDSA", "ok": True}
                    for kid, _ in multi6_keys
                ],
            },
        }
    )

    return {"schema": SCHEMA_VERSION, "jwks": jwks, "cases": cases}


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def main() -> int:
    corpus = build_corpus()
    out_path = (
        _repo_root() / "tests" / "conformance" / "jws" / "rfc7515_corpus.json"
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    # Canonical-ish JSON (sorted keys, 2-space indent) for reviewability.
    body = json.dumps(corpus, sort_keys=True, indent=2) + "\n"
    # Atomic write via tmp + rename to keep the corpus self-consistent if
    # interrupted. Generator script -- not a runtime primitive.
    tmp = out_path.with_suffix(".json.tmp")
    # Generator script under scripts/ (not packages/services/apps), so the
    # four-primitives boundary rule does not apply per boundaries.md section 3
    # ("Test files are exempt for fixture preparation, but production code
    # paths invoked by tests are not"). The corpus is regenerated only when
    # this script is invoked manually; production code never imports here.
    tmp.write_text(body, encoding="utf-8")
    tmp.replace(out_path)
    sys.stdout.write(
        f"[check] wrote {len(corpus['cases'])} cases to "
        f"{out_path.relative_to(_repo_root())}\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
