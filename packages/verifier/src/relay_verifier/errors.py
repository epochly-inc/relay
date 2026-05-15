"""Typed errors for the Relay offline verifier (W10.1).

Defines a small, closed exception hierarchy used by the trust-anchor
loader. Each concrete error carries a stable wire code under the
``RELAY-VERIFY-*`` namespace so machine consumers can branch on the code
string without parsing message text.

Hierarchy:

    RelayVerifierError                -- base; never raised directly
      |- RelayJWKSUnavailableError    -- VAL-W10-008: no JWKS source
      |- RelayBundledJWKSMissingError -- bundled asset absent (corrupt install)
      |- RelayConfigInvalidError      -- VAL-W10-006: malformed config file

Wire codes follow the spec section B.6 ``RELAY-<SUBSYSTEM>-NNN`` convention.
The numeric tail is stable; renaming an existing code requires a manifest
amendment.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from typing import Final

# -----------------------------------------------------------------------------
# Wire codes (stable; do not renumber)
# -----------------------------------------------------------------------------

RELAY_VERIFY_JWKS_UNAVAILABLE: Final[str] = "RELAY-VERIFY-001"
"""VAL-W10-008: live JWKS unreachable, no cache, no bundled JWKS.

Surfaced by :class:`RelayJWKSUnavailableError`. Maps to a non-zero CLI
exit code; the caller MUST NOT silently fall back to a less-trusted
source (CLAUDE.md "no silent failures").
"""

RELAY_VERIFY_BUNDLED_MISSING: Final[str] = "RELAY-VERIFY-002"
"""Bundled JWKS asset absent from the wheel.

Distinct from :data:`RELAY_VERIFY_JWKS_UNAVAILABLE` because the bundled
asset is shipped inside the package; its absence indicates a corrupt
install or a hand-deleted asset rather than a runtime network/cache
miss. Surfaced by :class:`RelayBundledJWKSMissingError`.
"""

RELAY_VERIFY_CONFIG_INVALID: Final[str] = "RELAY-VERIFY-003"
"""VAL-W10-006: config file present but malformed (parse error, wrong
value type, missing required field). Surfaced by
:class:`RelayConfigInvalidError`. The caller MUST exit non-zero and MUST
NOT silently fall back to the default URL -- an operator who supplied a
config explicitly stated their intent."""

RELAY_VERIFY_ALG_MISMATCH: Final[str] = "RELAY-VERIFY-010"
"""VAL-W10-011: JWS header ``alg`` is HS256 (or any symmetric MAC alg)
but the ``kid`` resolves to an asymmetric public JWK (kty=EC or kty=OKP
or kty=RSA). Surfacing this distinctly defeats the RFC 8725 section 3
RSA-public-key-as-HMAC-secret attack: a verifier that naively forwarded
the public-key bytes as an HMAC secret would accept attacker-forged
HMACs over a stolen public key.

Contract narrative spells this as ``RELAY-VERIFY-ALG-MISMATCH``; the
wire code is the canonical ``RELAY-VERIFY-NNN`` form. The two strings
are equivalent for contract-citation purposes (contract.md spells
``or equivalent``)."""

RELAY_VERIFY_UNSUPPORTED_ALG: Final[str] = "RELAY-VERIFY-011"
"""VAL-W10-014: JWS header ``alg`` is not in the allow-list
``{EdDSA, ES256, RS256}``. Includes ``none``, ``HS256``, ``RS1``,
unknown vendor algorithms, and any other identifier outside the closed
set. Rejection MUST occur BEFORE any signature-verification primitive
is invoked; the ``none`` alg in particular MUST never reach a verify
call (RFC 8725 section 3.1).

Contract narrative spells this as ``RELAY-VERIFY-UNSUPPORTED-ALG``."""

RELAY_VERIFY_DETACHED_PAYLOAD_MISMATCH: Final[str] = "RELAY-VERIFY-012"
"""VAL-W10-012: detached-JWS payload digest does not match the digest
of the claim it is bound to. The verifier recomputes the JCS canonical
bytes of the claim payload, hashes them, and compares to the digest
recorded in the signature record. A signature that verifies against
arbitrary bytes but whose payload no longer matches the stored claim
MUST be rejected: a tampered claim with a re-signed signature is the
attack this defeats.

Contract: VAL-W10-012 names ``RELAY-EVID-014`` as the public-facing
error code for evidence-bundle integrity failures. This local wire code
identifies the specific underlying cause; both are emitted in the
``details`` of an envelope so consumers branching on the public code
can still inspect the structured cause."""


# -----------------------------------------------------------------------------
# Exception hierarchy
# -----------------------------------------------------------------------------


class RelayVerifierError(Exception):
    """Base for all verifier errors.

    Carries a stable ``code`` string (one of the ``RELAY-VERIFY-*`` wire
    codes) and a human-readable ``message``. ``details`` is an optional
    structured dict that callers may include in stderr envelopes.

    Subclasses set ``code`` as a class attribute; instances inherit the
    code from the subclass unless explicitly overridden.
    """

    code: str = "RELAY-VERIFY-000"

    def __init__(
        self,
        message: str,
        *,
        details: dict[str, object] | None = None,
        code: str | None = None,
    ) -> None:
        super().__init__(message)
        self.message: str = message
        self.details: dict[str, object] = dict(details) if details else {}
        if code is not None:
            # Explicit per-instance override; rare but allowed for
            # callers that want to specialize the code without
            # introducing a new subclass.
            self.code = code

    def __repr__(self) -> str:
        return f"{type(self).__name__}(code={self.code!r}, message={self.message!r})"


class RelayJWKSUnavailableError(RelayVerifierError):
    """Raised when no JWKS source is available (live, cache, or bundled).

    Surfaces VAL-W10-008. The caller MUST exit non-zero. The error's
    ``details`` carries the attempted ``trust_anchor`` URL, the cache
    path that was checked, and whether the bundled asset was checked,
    so an operator can identify which fallback is missing.
    """

    code: str = RELAY_VERIFY_JWKS_UNAVAILABLE


class RelayBundledJWKSMissingError(RelayVerifierError):
    """Raised when the wheel-bundled JWKS asset is absent or unreadable.

    Distinct from :class:`RelayJWKSUnavailableError` because the bundled
    JWKS is a packaging guarantee; its absence indicates a damaged
    install rather than a runtime fallback failure.
    """

    code: str = RELAY_VERIFY_BUNDLED_MISSING


class RelayConfigInvalidError(RelayVerifierError):
    """Raised when a BYO-trust-anchor config file is malformed.

    Surfaces VAL-W10-006 negative path: a config file that parses as
    TOML but lacks the expected ``trust_anchor_url`` key, or assigns it
    to a non-string value, or assigns it to a string that is not a
    syntactically valid URL.
    """

    code: str = RELAY_VERIFY_CONFIG_INVALID


__all__ = [
    "RELAY_VERIFY_ALG_MISMATCH",
    "RELAY_VERIFY_BUNDLED_MISSING",
    "RELAY_VERIFY_CONFIG_INVALID",
    "RELAY_VERIFY_DETACHED_PAYLOAD_MISMATCH",
    "RELAY_VERIFY_JWKS_UNAVAILABLE",
    "RELAY_VERIFY_UNSUPPORTED_ALG",
    "RelayBundledJWKSMissingError",
    "RelayConfigInvalidError",
    "RelayJWKSUnavailableError",
    "RelayVerifierError",
]
