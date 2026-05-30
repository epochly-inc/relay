"""Test-only HMAC-SHA256 / HMAC-SHA512 JWS verifier helper.

This module is build-time isolated under ``tests/conformance/`` per
VAL-W17-023: it MUST NEVER be imported from any module under
``packages/verifier/`` or any other production source path. A CI
grep-guard test (``test_w17_2_hs_helper_isolation.py``) enforces the
non-import invariant on every PR.

Rationale (VAL-W17-007a + C-GAP-003):

  * Relay's production verifier MUST reject HS256/HS512 inputs per
    spec L.1 (allow-list is ES256, EdDSA, RS256). VAL-W17-007b
    asserts that production behavior.
  * RFC 7515 Appendix A.1 (and the W17.2 constructed HS512 vector
    paired with it) are symmetric-keyed; verifying them mathematically
    requires HMAC primitives. To prove the RFC math is implemented
    correctly without giving production verifiers an HS code path,
    this helper lives ONLY under ``tests/conformance/`` and is invoked
    ONLY by the W17.2 conformance test runner.

API:

  * :func:`verify_hs_compact` -- verify a compact-form JWS whose alg
    header is HS256 or HS512, given the shared key (raw bytes), returns
    True iff the HMAC matches the signature segment.

The helper accepts ONLY HS256 and HS512. Any other alg (including
production-allowed algs like RS256, ES256, EdDSA) raises
``UnsupportedHsAlgError`` -- this helper is for HMAC verification
exclusively, and refusing to delegate enforces the boundary.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
from typing import Final

# Public surface (test-only).
__all__ = [
    "UnsupportedHsAlgError",
    "verify_hs_compact",
]


# Allowed algs for THIS helper. Production verifier allow-list is
# disjoint from this set (L.1 disallows HS*); the two allow-lists are
# enforced separately, by separate code, in separate import trees.
_ALLOWED_HS_ALGS: Final[frozenset[str]] = frozenset({"HS256", "HS512"})


class UnsupportedHsAlgError(ValueError):
    """Raised when ``verify_hs_compact`` is called for a non-HS alg.

    The helper deliberately refuses to verify RS256/ES256/EdDSA -- those
    belong to the production verifier and routing them through this
    helper would defeat the boundary VAL-W17-023 enforces.
    """


def _b64u_decode(s: str) -> bytes:
    """Decode unpadded base64url per RFC 4648 sec 5 / RFC 7515 sec 2."""
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _decode_protected_header(header_b64u: str) -> dict[str, object]:
    raw = _b64u_decode(header_b64u)
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise ValueError("JWS protected header must be a JSON object")
    return parsed


def verify_hs_compact(token: str, shared_key: bytes) -> bool:
    """Verify a compact JWS whose ``alg`` is HS256 or HS512.

    Returns True iff:
      * the header is well-formed JSON with ``alg`` in {HS256, HS512},
      * the signature segment base64url-decodes cleanly,
      * the HMAC over ``signing_input = header_b64u || '.' || payload_b64u``
        with ``shared_key`` matches the signature bytes.

    Raises :class:`UnsupportedHsAlgError` if alg is anything other than
    HS256/HS512 -- a deliberate refusal to forward to the production
    verifier (preserves the VAL-W17-023 boundary).

    Uses :func:`hmac.compare_digest` for constant-time comparison.
    """
    segments = token.split(".")
    if len(segments) != 3:
        return False
    header_b64u, payload_b64u, sig_b64u = segments

    try:
        header = _decode_protected_header(header_b64u)
    except (ValueError, binascii.Error, json.JSONDecodeError):
        return False

    alg = header.get("alg")
    if not isinstance(alg, str):
        return False
    if alg not in _ALLOWED_HS_ALGS:
        raise UnsupportedHsAlgError(
            f"_test_only_hs_verifier refuses alg {alg!r}; "
            "only HS256/HS512 are accepted (production allow-list "
            "{ES256, EdDSA, RS256} is enforced by packages/verifier/)."
        )

    try:
        signature = _b64u_decode(sig_b64u)
    except (ValueError, binascii.Error):
        return False

    signing_input = (header_b64u + "." + payload_b64u).encode("ascii")
    digestmod = hashlib.sha256 if alg == "HS256" else hashlib.sha512
    expected = hmac.new(shared_key, signing_input, digestmod).digest()
    # Constant-time compare to avoid timing side channels even though
    # this is test-only code (defensive habit).
    return hmac.compare_digest(expected, signature)
