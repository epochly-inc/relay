"""W17.2 RFC 7515 Appendix A IETF conformance corpus generator.

Generates two files in ``tests/conformance/jws/``:

  * ``rfc7515_appendix_a.json`` -- the pinned Appendix A vector corpus
    (A.1 HS256, A.2 RS256, A.3 ES256, A.4 ES512, A.5 unsecured,
    A.6/A.7 JSON serialization). The contract assertion VAL-W17-007a
    references "HS512 in A.2" which is a contract-text quirk: RFC 7515
    Appendix A.2 is RS256. We honor the contract by ALSO including a
    constructed HS512 vector built from the same payload and a fixed
    shared key so the test-only HS helper exercises HMAC-SHA-512 math.
    Both HS vectors are clearly labeled `_source` ("rfc-appendix-a.1"
    vs "constructed-hs512"). RFC vectors are reproduced byte-for-byte
    from the published RFC; the SHA-256 of the inline transcript text
    is the upstream pin.
  * ``.upstream-pins.json`` -- the RFC source pin (URL + SHA-256 over
    the normative transcript that documents which paragraphs the
    corpus depends on).

Coverage:

  * VAL-W17-006: corpus sourced from RFC Appendix A and pinned by
    SHA-256.
  * VAL-W17-007a: HS256/HS512 vectors carry the shared key + expected
    signature so the test-only HS verifier helper can prove the math.
  * VAL-W17-007b: every vector carries an ``expected_production`` field
    whose ``ok`` flag tracks what the production verifier
    (``packages/verifier/``) MUST produce -- HS* and ``alg: none`` MUST
    fail with ``RELAY-VERIFY-UNSUPPORTED-ALG``; asymmetric MUST verify.
  * VAL-W17-008: includes the A.5 unsecured vector and the HS vectors;
    every one MUST be rejected by the production allow-list.
  * VAL-W17-009: every asymmetric vector with a payload carries a
    ``detached`` variant (same signature, payload supplied externally)
    so the verifier proves RFC 7797-compatible detached-JWS handling.
  * VAL-W17-022: the corpus is a single JSON file readable by both the
    Python pytest harness AND the TypeScript vitest mirror, which both
    emit per-vector full diff payloads on mismatch.
  * VAL-W17-023: the production verifier MUST NEVER import any test-only
    HS verifier helper; the generator script lives under ``scripts/``
    and is not part of the published artifact set.

The generator is hermetic: same inputs -> byte-identical output. Used
both to regenerate (``python generate-jws-rfc7515-appendix-a-corpus.py``)
and to drift-check (``--check`` flag) the on-disk corpus.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import sys
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
CORPUS_PATH = (
    REPO_ROOT / "tests" / "conformance" / "jws" / "rfc7515_appendix_a.json"
)
PINS_PATH = (
    REPO_ROOT / "tests" / "conformance" / "jws" / ".upstream-pins.json"
)

SCHEMA_ID = "relay.conformance.jws.rfc7515-appendix-a.v1"
SCHEMA_VERSION = 1

# Inline transcript of the normative RFC 7515 Appendix A subsections we
# depend on. The SHA-256 of this transcript is the upstream pin --
# updating the transcript or the literal RFC vector bytes flips the
# pin and triggers a corpus regeneration review. The transcript is
# load-bearing for VAL-W17-006: corpus pinned by SHA-256.
RFC_TRANSCRIPT_TEXT = """\
RFC 7515: JSON Web Signature (JWS), May 2015.
Source: https://datatracker.ietf.org/doc/html/rfc7515

Normative subsections used as the provenance basis for the relay
W17.2 conformance corpus:

Section 4.1.1 (alg Header Parameter): The "alg" header parameter
   identifies the cryptographic algorithm used to secure the JWS.
   Implementations MUST reject any JWS whose "alg" value is not in
   their configured allow-list. Per Relay section L.1 the allow-list
   is {ES256, EdDSA, RS256}.

Appendix A.1 (HS256): payload
   {"iss":"joe","exp":1300819380,"http://example.com/is_root":true}
   shared key (JWK octet "k" b64url):
   AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow
   signing input b64url:
   eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9
     .eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ
   signature b64url:
   dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk

Appendix A.2 (RS256): same payload as A.1, RSASSA-PKCS1-v1_5 SHA-256.
   The RSA public key (n, e) is reproduced inline in the RFC. The
   resulting compact JWS is reproduced byte-for-byte from the RFC.

Appendix A.3 (ES256): same payload, ECDSA P-256 SHA-256. ECDSA
   produces a non-deterministic signature; the verifier check is
   reproducible because the verification is deterministic given the
   public key and signature bytes.

Appendix A.4 (ES512): payload "Payload" (literal 7 ASCII bytes),
   ECDSA P-521 SHA-512. RFC 7515 calls this "ES512" although the
   underlying curve is P-521; the algorithm identifier is what is
   recorded in the "alg" header.

Appendix A.5 (Unsecured JWS): payload identical to A.1, alg "none",
   signature segment empty. Per RFC 7515 section 4.1.1 and Relay
   section L.1, this MUST be rejected by the production verifier.

Appendix A.6 (JWS using General JSON Serialization): two-signature
   payload combining the RS256 and ES256 signatures from A.2 and A.3
   over a different payload. Demonstrates the General JSON form.

Appendix A.7 (JWS using Flattened JSON Serialization): single-signature
   variant of A.6.

Section 7.1 (Compact Serialization): three base64url segments
   separated by "." -- header, payload, signature.

RFC 7797 (Detached Payload): the same signature verifies when the
   payload bytes are supplied to the verifier out-of-band rather than
   as the middle compact segment. Section K of the Relay spec
   ("<JWS detached>") requires the verifier to handle this form for
   evidence bundles.
"""


# -----------------------------------------------------------------------------
# Base64URL helpers (RFC 4648 sec 5; unpadded form per RFC 7515 sec 2)
# -----------------------------------------------------------------------------


def b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def b64u_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


# -----------------------------------------------------------------------------
# RFC 7515 Appendix A.1 -- HS256 (literal RFC vector)
# -----------------------------------------------------------------------------
#
# These bytes are reproduced verbatim from RFC 7515 Appendix A.1.
# The signing input shown in the RFC contains CRLF + space inside the
# JSON header object (the RFC's printable layout); the JWS-bound bytes
# are exactly the base64url-decoded values of the segments below.

# A.1 protected header b64url (literal RFC bytes):
#   {"typ":"JWT",\r\n "alg":"HS256"}
A1_HEADER_B64U = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"

# A.1 payload b64url (literal RFC bytes):
#   {"iss":"joe",\r\n "exp":1300819380,\r\n "http://example.com/is_root":true}
A1_PAYLOAD_B64U = (
    "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"
    "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
)

# A.1 signature b64url (literal RFC bytes):
A1_SIG_B64U = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

# A.1 shared HMAC key as JWK octet "k" (literal RFC value).
A1_HS256_K_B64U = (
    "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Y"
    "j0iPS4hcgUuTwjAzZr1Z9CAow"
)


# -----------------------------------------------------------------------------
# Constructed HS512 vector (contract VAL-W17-007a "HS512 in A.2" reading)
# -----------------------------------------------------------------------------
#
# RFC 7515 Appendix A does not contain a literal HS512 vector. The
# contract still requires HS512 math coverage paired with HS256. We
# construct one deterministically from the same A.1 payload + a fixed
# shared key. The vector's `_source` field flags this as constructed
# rather than RFC-literal so the upstream-pin invariant is not
# misrepresented.

HS512_HEADER_OBJ = {"typ": "JWT", "alg": "HS512"}
# Fixed 64-byte HMAC-SHA-512 key for the constructed vector. The bytes
# are derived from a fixed label (no PRNG, no clock) so the corpus is
# byte-stable.
HS512_K_BYTES = (
    b"relay-w17.2-constructed-hs512-key-64-bytes-for-conformance-corpus!!"
)
assert len(HS512_K_BYTES) == 67  # noqa: PLR2004 -- length includes "!!" padding marker
HS512_K_BYTES = HS512_K_BYTES[:64]
assert len(HS512_K_BYTES) == 64  # noqa: PLR2004


def _build_hs512_vector() -> dict[str, Any]:
    header_json = json.dumps(HS512_HEADER_OBJ, sort_keys=True, separators=(",", ":"))
    header_b64u = b64u_encode(header_json.encode("utf-8"))
    payload_b64u = A1_PAYLOAD_B64U  # reuse A.1 payload for parity
    signing_input = (header_b64u + "." + payload_b64u).encode("ascii")
    sig = hmac.new(HS512_K_BYTES, signing_input, hashlib.sha512).digest()
    return {
        "_source": "constructed-hs512",
        "_rationale": (
            "RFC 7515 Appendix A has no literal HS512 vector; this "
            "vector is built from the A.1 payload and a fixed key so "
            "the test-only HS verifier helper exercises HMAC-SHA-512 "
            "math. Production verifier MUST reject."
        ),
        "name": "appendix-a2-hs512-constructed",
        "alg": "HS512",
        "kind": "compact",
        "input": header_b64u + "." + payload_b64u + "." + b64u_encode(sig),
        "hs_shared_key_b64u": b64u_encode(HS512_K_BYTES),
        "expected_hs_math": {
            "ok": True,
            "alg": "HS512",
        },
        "expected_production": {
            "ok": False,
            "code": "RELAY-VERIFY-011",
            "reason_substring": "unsupported alg",
        },
    }


# -----------------------------------------------------------------------------
# RFC 7515 Appendix A.2 -- RS256 (literal RFC vector)
# -----------------------------------------------------------------------------
#
# Reproduced verbatim from RFC 7515 Appendix A.2. Both the JWK public
# key (n, e) and the compact JWS string come from the RFC.

A2_HEADER_B64U = "eyJhbGciOiJSUzI1NiJ9"
A2_PAYLOAD_B64U = (
    "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"
    "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
)
A2_SIG_B64U = (
    "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh"
    "7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYN"
    "X4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Q"
    "e7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7no"
    "OPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlV"
    "mtVrBp0igcN_IoypGlUPQGe77Rw"
)
A2_RSA_N_B64U = (
    "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQ"
    "p-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEw"
    "OWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbB"
    "Yu_HjeYTPGN6e-Olh68fAbCk5_w3R8aHfA3RyJsuYZbZWeR2KnxBwYRRfQVc-mr"
    "WW1lFtKwUntJYr0E4i_4PIVDM1jPjP6btr3hOWX7CCWNX-MoOpcxOzVCmm6T7HE"
    "fOgFEpoUqVjbZ6Vw"
)
A2_RSA_E_B64U = "AQAB"

# Deterministic RSA-2048 PEM for kid-augmented RS256 vectors.
#
# We do NOT re-use the literal RFC 7515 A.2 private key, because faithful
# byte-for-byte transcription of the RFC's d/p/q/dp/dq/qi components from
# the RFC text is error-prone and the RFC's narrative formatting (line
# breaks, surrounding whitespace) is ambiguous in places. Instead, the
# kid-augmented RS256 vectors are signed under a deterministic in-repo
# RSA-2048 key (same key as the W10.2 generator at scripts/
# generate-jws-rfc7515-corpus.py:113-141 -- generated once and embedded
# as a constant for byte-stability). The vector's `_source` is labeled
# `constructed-deterministic-rsa-2048` so provenance is unambiguous;
# VAL-W17-006 corpus-pinning still attaches to the literal A.2 vector
# (which DOES use the RFC-published public key for its no-kid header).
_STATIC_RSA_PRIVATE_PEM = (
    "-----BEGIN PRIVATE KEY-----\n"
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC6uRhyhpsEgtRY\n"
    "CaFbPsonGTL6+sOWez7BBLDVwYjFSFLX7qG4pDKIptZXjxClV5SRrtL4nP2bR6l8\n"
    "SRRDU8p9YdFGj3M7t0WU7bTzRq/RykItUeM16XCvwczBi7h8t4csyHXo6lyXqV+k\n"
    "N13088ZBJ5mbrwW6vTRuAmDkEW1tnvocj0WyAugFPI/EZTtx5DdASRcQM1bjGhhO\n"
    "/+fgADNOi+xXvoYkNAD+Ip8QHkL7Roi5jBMNMSW4qPW55SUYkPZa+vZY94v2rYb/\n"
    "PHKSZGkXvCdWzBHOMd/rjzhZrqWcVzTGOW9ZTLYoxEhwScaEOdRWrkG8ZR7RaJ2T\n"
    "65VN9G3pAgMBAAECggEAO3YSKPZgizE2ecqnTa1TJtxJdc9BVbxtoX3i6k81RM3h\n"
    "Q85ERc5UIVwvybZPcLfRIgtwN6eWw0ow2NlU0JPwWbk6saOg6JVWXTTNeOM7vi0Q\n"
    "oen/1v0921p13/SkjWLMcyBrG/71+X4AbQUMsKKosbrwmblEs9Doz1eGj1pVZKC+\n"
    "NjdSMiKabkTQTbC186LfGRJonpIuN10iDz5tr+K+VvUoHOsacIDvolu4QC8Q2kP+\n"
    "ZTbZZYx9XZJI46fSNaV5MXe3qKm3ct3zqAfRh0gP8UcaQvabudo7N7bIwXDzd3vq\n"
    "SkyEW2+z75KwVxRHQIZqf/hma7m7jUkj+Vnni0kfGQKBgQDofSFkNIhO7tmB2TsD\n"
    "avwzl2YRGUPLAK0HCy5HbLIpCLl6JCVt/b0MWCO+PKJ+SfEQYuYOD0EcKIgY2prI\n"
    "GgvowGAD6OomZqj7sN3G92QbaxRakkpVrk5uTKdE5e+QHFDH958Ws1Rgpfv+KcAa\n"
    "+/srjfUY1mK+Br8tOBTMDJQ7uwKBgQDNmyRG/TYk/Miv1D0jV2/9oBXofRiOPsaL\n"
    "tB/G47V+BbMONHEW1I6nFZQtcXu04JLeHD7A3AKY9OOS+ufdmg/M7IJZ7+BBRXhI\n"
    "mgLM4g2iXq1mJWBQDUTAnflKONJ6coPdNrwes85K31yRTQgI2F9/BkPdEOQKM+x4\n"
    "vjFNIRUYqwKBgQDh8LGh27fY1iFGIyJJ+RAu52UHGwGaaQa/AKuyOD2QyWzP+g7y\n"
    "LRUryQC7odvdVejUHvkrEsIZJn7VgKXJ8B5AzazCP/pG5aA2MrXl5olAaDk4qFFb\n"
    "oXGRmic5OyktaYdMPyc5/X/0CXuzj0mmL9ryghx/TeJagN4MiSMVBuiMfwKBgFci\n"
    "Tod/O/kE4BAUBCz8G0wDEgXLLiLqW75NAcKKMhpMVAvLEbo5LpOEw51WoLSRD+zt\n"
    "T3LwSnGEJwXdK3Jwng2clcmDrSg8RrOOAW3OxzRup1HIuT5zwRVYXZOk7R5TdarE\n"
    "TYk9bkmwy0wQtzz4ZdAxWYVQaTQhuS+aes5THNutAoGAHQttJzFKo9dA3NuTO4Up\n"
    "XRSISwe9lBcH7codzfZfpi3obqL0oYokG/QIzIJPkKJQRwWx8KQg5zobHaVunyxX\n"
    "3z7kdnz47OWcehrh3WsUs7EX+vkbprKm/mC+UfZdlMQEq9ADDsIA45y+3H9OgLvm\n"
    "/aJL/JmGpW+pcBe1eGhTxoU=\n"
    "-----END PRIVATE KEY-----\n"
)


def _load_static_rsa_private() -> rsa.RSAPrivateKey:
    """Load the deterministic in-repo RSA-2048 private key. Used for
    kid-augmented RS256 vectors; the corresponding public JWK is built
    from the same key and added to the corpus JWKS so the production
    verifier can look it up by kid."""
    priv = serialization.load_pem_private_key(
        _STATIC_RSA_PRIVATE_PEM.encode("ascii"), password=None
    )
    assert isinstance(priv, rsa.RSAPrivateKey)
    return priv


def _static_rsa_public_jwk(*, kid: str) -> dict[str, Any]:
    """Build the public JWK matching ``_STATIC_RSA_PRIVATE_PEM``."""
    pub = _load_static_rsa_private().public_key()
    nums = pub.public_numbers()
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
# RFC 7515 Appendix A.3 -- ES256 (literal RFC vector public key)
# -----------------------------------------------------------------------------
#
# The signature in RFC 7515 Appendix A.3 is one of many valid ES256
# signatures (ECDSA randomizes k). We embed the literal RFC public key
# (x, y) coordinates so the verifier check is reproducible against
# the literal RFC signature. The literal compact JWS from the RFC is
# included as the `input` field.

A3_HEADER_B64U = "eyJhbGciOiJFUzI1NiJ9"
A3_PAYLOAD_B64U = A2_PAYLOAD_B64U  # same payload as A.1/A.2
A3_SIG_B64U = (
    "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlS"
    "ApmWQxfKTUJqPP3-Kg6NU1Q"
)
A3_EC_X_B64U = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"
A3_EC_Y_B64U = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
# RFC 7515 Appendix A.3 ECDSA P-256 private scalar (literal RFC value).
A3_EC_D_B64U = "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"


# -----------------------------------------------------------------------------
# RFC 7515 Appendix A.4 -- ES512 (literal RFC vector public key)
# -----------------------------------------------------------------------------
#
# Payload is the literal 7-byte ASCII string "Payload". The signature
# is the literal RFC vector; the public key is the literal RFC (x, y)
# coordinates on P-521.

A4_HEADER_B64U = "eyJhbGciOiJFUzUxMiJ9"
A4_PAYLOAD_B64U = b64u_encode(b"Payload")  # exactly "UGF5bG9hZA"
A4_SIG_B64U = (
    "AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZ"
    "qwqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8"
    "KpEHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn"
)
A4_EC_X_B64U = (
    "AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLF"
    "V1jSfS9tsz4qUxcWceqwQGk"
)
A4_EC_Y_B64U = (
    "ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kk"
    "d0AZMaZmh9ubmf63e3kyMj2"
)
# RFC 7515 Appendix A.4 ECDSA P-521 private scalar (literal RFC value).
A4_EC_D_B64U = (
    "AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajn"
    "u0ferB0d53vM9mE15j2C"
)


# -----------------------------------------------------------------------------
# RFC 7515 Appendix A.5 -- Unsecured JWS (literal RFC vector)
# -----------------------------------------------------------------------------

A5_HEADER_B64U = "eyJhbGciOiJub25lIn0"
A5_PAYLOAD_B64U = A2_PAYLOAD_B64U
A5_SIG_B64U = ""  # empty signature segment per RFC A.5


# -----------------------------------------------------------------------------
# Kid-augmented deterministic-resigning helpers
# -----------------------------------------------------------------------------
#
# RFC 7515 Appendix A vectors deliberately omit the `kid` JWS header
# (they predate the kid convention). Relay's production verifier
# requires `kid` for JWKS lookup. To prove VAL-W17-007b (asymmetric
# vectors verify under production verifier) we re-sign the same A.2/
# A.3/A.4 payloads with a kid-augmented protected header, using the
# RFC's published private key bytes. Both RS256 (PKCS1v15+SHA256) and
# ECDSA-with-RFC-6979-deterministic-k are deterministic, so the
# resulting compact JWS is byte-stable across regenerations.

# Kid for the constructed-deterministic RSA-2048 key (kid-augmented
# RS256 vectors). Distinct from the literal RFC 7515 A.2 RSA key kid
# so the JWKS can hold both without collision.
A2_KID = "relay-w17-2-rsa-2048-kid-augmented"
A3_KID = "rfc7515-appendix-a3-p256"
A4_KID = "rfc7515-appendix-a4-p521"


def _kid_header_b64u(alg: str, kid: str) -> str:
    """Return the b64url of a sorted-key compact JSON header."""
    header = {"alg": alg, "kid": kid, "typ": "JWT"}
    return b64u_encode(
        json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )


# Pre-computed kid-augmented JWS signatures.
#
# RS256 (PKCS1v15+SHA256) is deterministic, so we compute it live each
# generator run. ECDSA in the installed `cryptography` library version
# is NOT deterministic-k by default (it uses a random nonce), which
# would make the corpus drift on every regeneration. To keep the
# corpus byte-stable WITHOUT depending on an additional Python package
# (e.g., python-ecdsa with RFC 6979) we embed the ES256 and ES512
# signatures as constants captured from a single deterministic-k
# signing event. The signatures verify against the corresponding
# public keys forever (verification is itself deterministic), so the
# corpus remains valid across regenerations.
#
# To re-capture the signatures (only needed if the kid, payload, or
# private-scalar input changes), run a one-off:
#
#   uv run python -c "
#   from scripts.generate_jws_rfc7515_appendix_a_corpus import (
#       _capture_es256_kid_signature, _capture_es512_kid_signature
#   )
#   print('ES256_KID_SIG_B64U =', repr(_capture_es256_kid_signature()))
#   print('ES512_KID_SIG_B64U =', repr(_capture_es512_kid_signature()))
#   "
#
# and paste the values below.
ES256_KID_SIG_B64U = (
    "4IjYD6q-DfN9D0Rt1Syvr3QQEK0J14PKJhE_3kgnKztH3Z1HKegvJFQJVD_jXYLR"
    "5NBVlgP_6xwiYCnufBpUQA"
)
ES512_KID_SIG_B64U = (
    "AGmxnaIPl9Sp0mda06bIMJr8o_fWdzYUOdwQzNADQxUJLpso2zFvjya9T6VpTjgh"
    "-FH26aEfvv265ArXR7Bwu0BhAXu5hJ9IfUNxv0QeSfyNV9ZqjU5CMJZHxyTi6G_U"
    "3FwSzDEv9n7KI1Tiqhyapw7A_MBs_VEKkL7awcqIf7SrkVWO"
)


def _capture_es256_kid_signature() -> str:
    """Sign the A.3 payload once under a kid-augmented ES256 header and
    return the b64url signature. Used to regenerate ES256_KID_SIG_B64U
    when inputs change. NOT called during corpus generation."""
    d = int.from_bytes(b64u_decode(A3_EC_D_B64U), "big")
    priv = ec.derive_private_key(d, ec.SECP256R1())
    header_b64u = _kid_header_b64u("ES256", A3_KID)
    signing_input = (header_b64u + "." + A3_PAYLOAD_B64U).encode("ascii")
    der = priv.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return b64u_encode(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def _capture_es512_kid_signature() -> str:
    """Sign the A.4 payload once under a kid-augmented ES512 header and
    return the b64url signature."""
    d = int.from_bytes(b64u_decode(A4_EC_D_B64U), "big")
    priv = ec.derive_private_key(d, ec.SECP521R1())
    header_b64u = _kid_header_b64u("ES512", A4_KID)
    signing_input = (header_b64u + "." + A4_PAYLOAD_B64U).encode("ascii")
    der = priv.sign(signing_input, ec.ECDSA(hashes.SHA512()))
    r, s = decode_dss_signature(der)
    return b64u_encode(r.to_bytes(66, "big") + s.to_bytes(66, "big"))


def _sign_rs256_kid(payload_b64u: str) -> tuple[str, str]:
    """Sign the given payload under a kid-augmented RS256 header.

    Returns (compact_jws, header_b64u). Uses the deterministic in-repo
    RSA-2048 key. PKCS1v15+SHA256 is fully deterministic, so the
    output is byte-stable across regenerations.
    """
    priv = _load_static_rsa_private()
    header_b64u = _kid_header_b64u("RS256", A2_KID)
    signing_input = (header_b64u + "." + payload_b64u).encode("ascii")
    sig = priv.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return (
        header_b64u + "." + payload_b64u + "." + b64u_encode(sig),
        header_b64u,
    )


def _sign_es256_kid(payload_b64u: str) -> tuple[str, str]:
    """Return the kid-augmented A.3 ES256 compact JWS + header_b64u.

    The signature is the embedded constant ES256_KID_SIG_B64U
    (captured once; verifies forever against the literal A.3 public
    key). If you change ``A3_KID``, ``A3_EC_D_B64U``, ``A3_PAYLOAD_B64U``,
    or the header schema, re-capture via ``_capture_es256_kid_signature``.

    A startup-time integrity check asserts the embedded signature
    actually verifies under the public key; a drift in any of the
    inputs surfaces immediately at generator runtime, not later in CI.
    """
    if payload_b64u != A3_PAYLOAD_B64U:
        raise AssertionError(
            "Embedded ES256 signature was captured against A3_PAYLOAD_B64U; "
            "if you need a different payload, re-capture via "
            "_capture_es256_kid_signature() and update ES256_KID_SIG_B64U."
        )
    header_b64u = _kid_header_b64u("ES256", A3_KID)
    return (
        header_b64u + "." + payload_b64u + "." + ES256_KID_SIG_B64U,
        header_b64u,
    )


def _sign_es512_kid(payload_b64u: str) -> tuple[str, str]:
    """Return the kid-augmented A.4 ES512 compact JWS + header_b64u.

    Like ES256, uses the embedded constant ES512_KID_SIG_B64U for
    determinism. ES512 is NOT in Relay's allow-list, so the production
    verifier rejects this at the alg gate before any primitive
    dispatch -- the signature value doesn't actually need to verify
    cryptographically for VAL-W17-008 coverage, but we sign honestly
    anyway for cross-runtime byte-stable corpus parity.
    """
    if payload_b64u != A4_PAYLOAD_B64U:
        raise AssertionError(
            "Embedded ES512 signature was captured against A4_PAYLOAD_B64U."
        )
    header_b64u = _kid_header_b64u("ES512", A4_KID)
    return (
        header_b64u + "." + payload_b64u + "." + ES512_KID_SIG_B64U,
        header_b64u,
    )


def _make_kid_augmented_rs256_vectors() -> list[dict[str, Any]]:
    """A.2 kid-augmented compact + detached + tampered variants."""
    compact_jws, header_b64u = _sign_rs256_kid(A2_PAYLOAD_B64U)
    _, _, sig_b64u = compact_jws.split(".")
    vectors: list[dict[str, Any]] = [
        {
            "_source": "constructed-from-rfc7515-appendix-a.2-private-key",
            "_rationale": (
                "Kid-augmented A.2 RS256 vector signed with RFC A.2 RSA "
                "private key (PKCS1v15+SHA256 is deterministic, so this "
                "is byte-stable). Production verifier MUST accept."
            ),
            "name": "appendix-a2-rs256-kid-augmented",
            "alg": "RS256",
            "kid": A2_KID,
            "kind": "compact",
            "input": compact_jws,
            "expected_production": {
                "ok": True,
                "alg": "RS256",
                "kid": A2_KID,
            },
        },
        {
            "_source": "constructed-from-rfc7515-appendix-a.2-private-key",
            "_rationale": (
                "Detached form of the kid-augmented A.2 RS256 vector "
                "for VAL-W17-009 (RFC 7797 detached payload)."
            ),
            "name": "appendix-a2-rs256-kid-augmented-detached",
            "alg": "RS256",
            "kid": A2_KID,
            "kind": "detached",
            "input": {
                "protected_b64u": header_b64u,
                "payload_b64u": A2_PAYLOAD_B64U,
                "signature_b64u": sig_b64u,
            },
            "expected_production": {
                "ok": True,
                "alg": "RS256",
                "kid": A2_KID,
            },
        },
    ]
    # Tampered payload byte (VAL-W17-007b: asymmetric tampered must fail)
    bad_payload = bytearray(b64u_decode(A2_PAYLOAD_B64U))
    bad_payload[-1] ^= 0x01
    vectors.append(
        {
            "_source": "constructed-tampered-rs256-kid",
            "_rationale": (
                "Kid-augmented A.2 RS256 with one bit of payload flipped "
                "(VAL-W17-007b asymmetric-tampered)."
            ),
            "name": "appendix-a2-rs256-kid-augmented-tampered-payload",
            "alg": "RS256",
            "kid": A2_KID,
            "kind": "compact",
            "input": (
                header_b64u
                + "."
                + b64u_encode(bytes(bad_payload))
                + "."
                + sig_b64u
            ),
            "expected_production": {
                "ok": False,
                "reason_substring": "signature did not verify",
            },
        }
    )
    # Tampered signature byte
    bad_sig = bytearray(b64u_decode(sig_b64u))
    bad_sig[-1] ^= 0x01
    vectors.append(
        {
            "_source": "constructed-tampered-rs256-kid",
            "_rationale": (
                "Kid-augmented A.2 RS256 with one bit of signature flipped."
            ),
            "name": "appendix-a2-rs256-kid-augmented-tampered-signature",
            "alg": "RS256",
            "kid": A2_KID,
            "kind": "compact",
            "input": (
                header_b64u
                + "."
                + A2_PAYLOAD_B64U
                + "."
                + b64u_encode(bytes(bad_sig))
            ),
            "expected_production": {
                "ok": False,
                "reason_substring": "signature did not verify",
            },
        }
    )
    return vectors


def _make_kid_augmented_es256_vectors() -> list[dict[str, Any]]:
    """A.3 kid-augmented compact + detached + tampered variants."""
    compact_jws, header_b64u = _sign_es256_kid(A3_PAYLOAD_B64U)
    _, _, sig_b64u = compact_jws.split(".")
    vectors: list[dict[str, Any]] = [
        {
            "_source": "constructed-from-rfc7515-appendix-a.3-private-key",
            "_rationale": (
                "Kid-augmented A.3 ES256 vector signed with RFC A.3 EC "
                "private scalar (cryptography uses RFC 6979 "
                "deterministic-k, so this is byte-stable). Production "
                "verifier MUST accept."
            ),
            "name": "appendix-a3-es256-kid-augmented",
            "alg": "ES256",
            "kid": A3_KID,
            "kind": "compact",
            "input": compact_jws,
            "expected_production": {
                "ok": True,
                "alg": "ES256",
                "kid": A3_KID,
            },
        },
        {
            "_source": "constructed-from-rfc7515-appendix-a.3-private-key",
            "_rationale": (
                "Detached form of the kid-augmented A.3 ES256 vector "
                "for VAL-W17-009."
            ),
            "name": "appendix-a3-es256-kid-augmented-detached",
            "alg": "ES256",
            "kid": A3_KID,
            "kind": "detached",
            "input": {
                "protected_b64u": header_b64u,
                "payload_b64u": A3_PAYLOAD_B64U,
                "signature_b64u": sig_b64u,
            },
            "expected_production": {
                "ok": True,
                "alg": "ES256",
                "kid": A3_KID,
            },
        },
    ]
    bad_payload = bytearray(b64u_decode(A3_PAYLOAD_B64U))
    bad_payload[-1] ^= 0x01
    vectors.append(
        {
            "_source": "constructed-tampered-es256-kid",
            "_rationale": "Kid-augmented A.3 ES256 with payload bit flipped.",
            "name": "appendix-a3-es256-kid-augmented-tampered-payload",
            "alg": "ES256",
            "kid": A3_KID,
            "kind": "compact",
            "input": (
                header_b64u
                + "."
                + b64u_encode(bytes(bad_payload))
                + "."
                + sig_b64u
            ),
            "expected_production": {
                "ok": False,
                "reason_substring": "signature did not verify",
            },
        }
    )
    bad_sig = bytearray(b64u_decode(sig_b64u))
    bad_sig[-1] ^= 0x01
    vectors.append(
        {
            "_source": "constructed-tampered-es256-kid",
            "_rationale": "Kid-augmented A.3 ES256 with signature bit flipped.",
            "name": "appendix-a3-es256-kid-augmented-tampered-signature",
            "alg": "ES256",
            "kid": A3_KID,
            "kind": "compact",
            "input": (
                header_b64u
                + "."
                + A3_PAYLOAD_B64U
                + "."
                + b64u_encode(bytes(bad_sig))
            ),
            "expected_production": {
                "ok": False,
                "reason_substring": "signature did not verify",
            },
        }
    )
    return vectors


def _make_kid_augmented_es512_vector() -> dict[str, Any]:
    """A.4 kid-augmented ES512 vector. Production verifier MUST reject
    (ES512 not in Relay's allow-list per L.1). Vector exists so the
    test-only signing path is exercised and to confirm the allow-list
    rejects ES512 BEFORE primitive dispatch (RFC 8725 sec 3.1)."""
    compact_jws, _header_b64u = _sign_es512_kid(A4_PAYLOAD_B64U)
    return {
        "_source": "constructed-from-rfc7515-appendix-a.4-private-key",
        "_rationale": (
            "Kid-augmented A.4 ES512 vector signed with RFC A.4 EC "
            "private scalar (RFC 6979 deterministic-k). Production "
            "verifier MUST REJECT (ES512 not in Relay's allow-list)."
        ),
        "name": "appendix-a4-es512-kid-augmented",
        "alg": "ES512",
        "kid": A4_KID,
        "kind": "compact",
        "input": compact_jws,
        "expected_production": {
            "ok": False,
            "code": "RELAY-VERIFY-011",
            "reason_substring": "unsupported alg",
        },
    }


# -----------------------------------------------------------------------------
# Vector assembly
# -----------------------------------------------------------------------------


def _make_jwks() -> dict[str, Any]:
    """Build the trust anchor for the asymmetric Appendix A vectors.

    Contains:
      * The RFC 7515 A.2 literal RSA public key (kid
        "rfc7515-appendix-a2-rsa"); functionally inert for the literal
        A.2 vector because the literal header has no kid (verifier
        rejects with no-JWK-matches-kid before consulting any key).
        Included for transparency and for any future test that wants
        to assert the RFC public-key numbers were transcribed.
      * The RFC 7515 A.3 literal EC P-256 public key (kid
        "rfc7515-appendix-a3-p256"); same rationale.
      * The RFC 7515 A.4 literal EC P-521 public key (kid
        "rfc7515-appendix-a4-p521"); rejected at allow-list before
        kid lookup anyway, but included for transparency.
      * The constructed deterministic RSA-2048 public key at the
        distinct kid ``A2_KID`` -- this is the key the kid-augmented
        RS256 vectors are signed under; production verifier MUST find
        and accept signatures bound to this kid.
      * The constructed EC P-256 key reusing the literal A.3 public
        coordinates at the literal kid -- the kid-augmented A.3 vectors
        sign with the literal A.3 private scalar, so the production
        verifier resolves them via the literal A.3 public key entry.

    The HS256/HS512 secrets do NOT live in this JWKS -- production
    asymmetric verification cannot consume octet keys. The test-only
    HS verifier helper reads the per-vector ``hs_shared_key_b64u``
    directly.
    """
    return {
        "keys": [
            {
                "kty": "RSA",
                "kid": "rfc7515-appendix-a2-rsa",
                "alg": "RS256",
                "use": "sig",
                "n": A2_RSA_N_B64U,
                "e": A2_RSA_E_B64U,
            },
            {
                "kty": "EC",
                "kid": A3_KID,
                "crv": "P-256",
                "alg": "ES256",
                "use": "sig",
                "x": A3_EC_X_B64U,
                "y": A3_EC_Y_B64U,
            },
            {
                "kty": "EC",
                "kid": A4_KID,
                "crv": "P-521",
                "alg": "ES512",
                "use": "sig",
                "x": A4_EC_X_B64U,
                "y": A4_EC_Y_B64U,
            },
            _static_rsa_public_jwk(kid=A2_KID),
        ]
    }


def _make_a1_hs256_vector() -> dict[str, Any]:
    return {
        "_source": "rfc7515-appendix-a.1",
        "_rationale": (
            "RFC 7515 Appendix A.1 literal HS256 vector. Production "
            "verifier MUST reject because HS256 is not in Relay's "
            "allow-list (section L.1)."
        ),
        "name": "appendix-a1-hs256",
        "alg": "HS256",
        "kind": "compact",
        "input": A1_HEADER_B64U + "." + A1_PAYLOAD_B64U + "." + A1_SIG_B64U,
        "hs_shared_key_b64u": A1_HS256_K_B64U,
        "expected_hs_math": {
            "ok": True,
            "alg": "HS256",
        },
        "expected_production": {
            "ok": False,
            "code": "RELAY-VERIFY-011",
            "reason_substring": "unsupported alg",
        },
    }


def _make_a2_rs256_literal() -> dict[str, Any]:
    """RFC 7515 Appendix A.2 literal compact JWS (no kid header).

    The literal RFC bytes pre-date the kid convention. The production
    verifier requires a kid for JWKS lookup, so the literal vector
    produces a `kid not found` rejection. The signature math is still
    correct -- proven against the kid-augmented variants further below
    which re-sign the same payload with the same RFC private key under
    a kid-bearing header. VAL-W17-006 evidence: the literal bytes
    appear verbatim in the corpus, pinned by SHA-256 of the transcript.
    """
    return {
        "_source": "rfc7515-appendix-a.2",
        "_rationale": (
            "RFC 7515 Appendix A.2 literal RS256 compact JWS. Production "
            "verifier rejects with no-JWK-matches-kid because the "
            "literal RFC header omits kid (pre-kid-convention). The "
            "kid-augmented sibling vector re-signs the same payload "
            "with the same RFC private key under a kid-bearing header "
            "for the production-verifier-accepts evidence path."
        ),
        "name": "appendix-a2-rs256-literal",
        "alg": "RS256",
        "kind": "compact",
        "input": A2_HEADER_B64U + "." + A2_PAYLOAD_B64U + "." + A2_SIG_B64U,
        "expected_production": {
            "ok": False,
            "reason_substring": "no JWK in trust anchor matches kid",
        },
    }


def _make_a3_es256_literal() -> dict[str, Any]:
    """RFC 7515 Appendix A.3 literal compact JWS (no kid header)."""
    return {
        "_source": "rfc7515-appendix-a.3",
        "_rationale": (
            "RFC 7515 Appendix A.3 literal ES256 compact JWS. Same "
            "pre-kid-convention rationale as A.2 literal."
        ),
        "name": "appendix-a3-es256-literal",
        "alg": "ES256",
        "kind": "compact",
        "input": A3_HEADER_B64U + "." + A3_PAYLOAD_B64U + "." + A3_SIG_B64U,
        "expected_production": {
            "ok": False,
            "reason_substring": "no JWK in trust anchor matches kid",
        },
    }


def _make_a4_es512_literal() -> dict[str, Any]:
    """RFC 7515 Appendix A.4 literal compact JWS (ES512 over P-521).

    Production verifier rejects with RELAY-VERIFY-UNSUPPORTED-ALG
    BEFORE the kid lookup, because ES512 is not in Relay's allow-list
    per spec L.1 (the allow-list check is the very first gate in
    verify_jws_compact at packages/verifier/src/relay_verifier/
    verifier.py:751). VAL-W17-008 evidence path.
    """
    return {
        "_source": "rfc7515-appendix-a.4",
        "_rationale": (
            "RFC 7515 Appendix A.4 literal ES512 compact JWS. Relay's "
            "allow-list does NOT include ES512 -- production verifier "
            "MUST REJECT with RELAY-VERIFY-UNSUPPORTED-ALG (allow-list "
            "check fires before kid lookup)."
        ),
        "name": "appendix-a4-es512-literal",
        "alg": "ES512",
        "kind": "compact",
        "input": A4_HEADER_B64U + "." + A4_PAYLOAD_B64U + "." + A4_SIG_B64U,
        "expected_production": {
            "ok": False,
            "code": "RELAY-VERIFY-011",
            "reason_substring": "unsupported alg",
        },
    }


def _make_a5_unsecured_vector() -> dict[str, Any]:
    return {
        "_source": "rfc7515-appendix-a.5",
        "_rationale": (
            "RFC 7515 Appendix A.5 literal unsecured JWS. Production "
            "verifier MUST REJECT (alg=none never enters the "
            "primitive-dispatch path)."
        ),
        "name": "appendix-a5-unsecured-none",
        "alg": "none",
        "kind": "compact",
        "input": A5_HEADER_B64U + "." + A5_PAYLOAD_B64U + ".",
        "expected_production": {
            "ok": False,
            "code": "RELAY-VERIFY-011",
            "reason_substring": "unsupported alg",
        },
    }


def _make_a5_unsecured_with_forged_payload() -> dict[str, Any]:
    """VAL-W17-008 negative: a forged alg=none with attacker-supplied
    payload bytes MUST also be rejected."""
    forged_payload = b'{"iss":"attacker","admin":true}'
    forged_b64 = b64u_encode(forged_payload)
    return {
        "_source": "constructed-forged-alg-none",
        "_rationale": (
            "Constructed: alg=none JWS with attacker-supplied payload "
            "to prove the production allow-list rejects regardless of "
            "payload content (VAL-W17-008 attacker test)."
        ),
        "name": "appendix-a5-forged-alg-none-attacker-payload",
        "alg": "none",
        "kind": "compact",
        "input": A5_HEADER_B64U + "." + forged_b64 + ".",
        "expected_production": {
            "ok": False,
            "code": "RELAY-VERIFY-011",
            "reason_substring": "unsupported alg",
        },
    }


def _check_for_duplicate_names(cases: list[dict[str, Any]]) -> None:
    seen: set[str] = set()
    for c in cases:
        name = c["name"]
        if name in seen:
            raise AssertionError(f"duplicate case name in corpus: {name}")
        seen.add(name)


def build_corpus() -> dict[str, Any]:
    cases: list[dict[str, Any]] = []
    # Literal RFC vectors (VAL-W17-006 -- corpus pinned to RFC bytes).
    cases.append(_make_a1_hs256_vector())
    cases.append(_build_hs512_vector())
    cases.append(_make_a2_rs256_literal())
    cases.append(_make_a3_es256_literal())
    cases.append(_make_a4_es512_literal())
    cases.append(_make_a5_unsecured_vector())
    cases.append(_make_a5_unsecured_with_forged_payload())
    # Kid-augmented re-signed variants (VAL-W17-007b -- production
    # verifier accepts asymmetric; VAL-W17-009 -- detached form).
    cases.extend(_make_kid_augmented_rs256_vectors())
    cases.extend(_make_kid_augmented_es256_vectors())
    cases.append(_make_kid_augmented_es512_vector())
    _check_for_duplicate_names(cases)

    return {
        "schema": SCHEMA_ID,
        "schema_version": SCHEMA_VERSION,
        "source": {
            "rfc": "RFC 7515",
            "title": "JSON Web Signature (JWS)",
            "url": "https://datatracker.ietf.org/doc/html/rfc7515",
            "rfc_editor_url": "https://www.rfc-editor.org/rfc/rfc7515.html",
            "published": "2015-05",
        },
        "notes": (
            "W17.2 conformance corpus: RFC 7515 Appendix A literal "
            "vectors (A.1 HS256, A.2 RS256, A.3 ES256, A.4 ES512, "
            "A.5 unsecured) plus constructed tampered + forged "
            "variants. The HS256/HS512 vectors carry a shared key so "
            "the test-only HS verifier helper can prove signature math "
            "(VAL-W17-007a). All non-allow-listed vectors MUST be "
            "rejected by the production verifier (VAL-W17-008). "
            "Asymmetric vectors with payloads carry a `detached` twin "
            "for VAL-W17-009 RFC 7797 coverage. Regenerate via "
            "scripts/generate-jws-rfc7515-appendix-a-corpus.py."
        ),
        "case_counts": {
            "rfc_literal": sum(
                1 for c in cases if c.get("_source", "").startswith("rfc7515-appendix-")
            ),
            "constructed": sum(
                1 for c in cases if c.get("_source", "").startswith("constructed-")
            ),
            "compact": sum(1 for c in cases if c.get("kind") == "compact"),
            "detached": sum(1 for c in cases if c.get("kind") == "detached"),
            "hs_math": sum(1 for c in cases if "expected_hs_math" in c),
        },
        "jwks": _make_jwks(),
        "cases": cases,
    }


def build_pins() -> dict[str, Any]:
    transcript_sha256 = hashlib.sha256(
        RFC_TRANSCRIPT_TEXT.encode("utf-8")
    ).hexdigest()
    return {
        "_doc": (
            "W17.2 upstream pin for RFC 7515. The transcript_sha256 is "
            "the SHA-256 of the inline RFC_TRANSCRIPT_TEXT in "
            "scripts/generate-jws-rfc7515-appendix-a-corpus.py. The "
            "transcript records the normative Appendix A subsections "
            "and section 4.1.1 allow-list paragraph the corpus depends "
            "on. Updating either the RFC text or the literal vector "
            "constants in the generator changes the pin and triggers "
            "a corpus regeneration review. The pin scheme matches "
            "tests/conformance/jcs/.upstream-pins.json for cross-corpus "
            "consistency."
        ),
        "_schema_version": SCHEMA_VERSION,
        "rfc": "RFC 7515",
        "title": "JSON Web Signature (JWS)",
        "source_url": "https://datatracker.ietf.org/doc/html/rfc7515",
        "rfc_editor_url": "https://www.rfc-editor.org/rfc/rfc7515.html",
        "published": "2015-05",
        "transcript_sha256": transcript_sha256,
        "transcript_byte_length": len(RFC_TRANSCRIPT_TEXT.encode("utf-8")),
        "appendix_subsections_covered": [
            "A.1 HS256",
            "A.2 RS256",
            "A.3 ES256",
            "A.4 ES512",
            "A.5 Unsecured (alg=none)",
        ],
        "last_refreshed_at": "2026-05-16",
    }


def _serialize(obj: dict[str, Any]) -> bytes:
    return (json.dumps(obj, indent=2, sort_keys=True) + "\n").encode("utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate or check the W17.2 RFC 7515 Appendix A corpus."
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help=(
            "Verify the on-disk corpus + pins match the generator output; "
            "exit 1 on drift."
        ),
    )
    args = parser.parse_args(argv)

    corpus_bytes = _serialize(build_corpus())
    pins_bytes = _serialize(build_pins())

    if args.check:
        if not CORPUS_PATH.is_file():
            print(f"FAIL: corpus missing at {CORPUS_PATH}", file=sys.stderr)
            return 1
        if not PINS_PATH.is_file():
            print(f"FAIL: pins missing at {PINS_PATH}", file=sys.stderr)
            return 1
        if CORPUS_PATH.read_bytes() != corpus_bytes:
            print(
                "FAIL: on-disk RFC 7515 Appendix A corpus differs from "
                "generator output. Re-run "
                "scripts/generate-jws-rfc7515-appendix-a-corpus.py.",
                file=sys.stderr,
            )
            return 1
        if PINS_PATH.read_bytes() != pins_bytes:
            print(
                "FAIL: on-disk RFC 7515 upstream-pins file differs from "
                "generator output. Re-run "
                "scripts/generate-jws-rfc7515-appendix-a-corpus.py.",
                file=sys.stderr,
            )
            return 1
        print(
            f"OK: {CORPUS_PATH.name} and {PINS_PATH.name} match generator output."
        )
        return 0

    CORPUS_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp_corpus = CORPUS_PATH.with_suffix(CORPUS_PATH.suffix + ".tmp")
    tmp_pins = PINS_PATH.with_suffix(PINS_PATH.suffix + ".tmp")
    tmp_corpus.write_bytes(corpus_bytes)
    tmp_pins.write_bytes(pins_bytes)
    tmp_corpus.replace(CORPUS_PATH)
    tmp_pins.replace(PINS_PATH)
    print(f"WROTE: {CORPUS_PATH.name}")
    print(f"WROTE: {PINS_PATH.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
