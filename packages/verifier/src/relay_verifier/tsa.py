"""RFC 3161 TSA timestamp validation for evidence bundles (W10.4).

Per spec section AB lines 5416-5417 every signed evidence bundle carries
a Time-Stamp Authority response (RFC 3161) so an auditor can verify the
bundle was signed AT a specific wall-clock time, not merely that it was
signed by a particular key. Per VAL-W10-025 a bundle whose `.tsr` is
absent is rejected with `RELAY-EVID-031`. Per VAL-W10-026 the response
MUST validate against the TSA cert chain bundled in the trust bundle.
Per VAL-W10-027 the TSA `genTime` MUST be within +/-300 s of the bundle's
`decided_at`/`occurred_at`; outside the window raises `RELAY-EVID-038`.

The verifier package ships the TSA cert chain at the canonical path
`packages/verifier/trust/tsa-chain.pem` (VAL-W10-042). The chain ships
public certs only; banned pattern #14 forbids any private signing key
material from landing in OSS.

Implementation note: full ASN.1 RFC 3161 token parsing requires either
a TSA-specific library (asn1crypto + a hand-rolled TSTInfo decoder) or
an opinionated dependency (rfc3161-client / pyhanko). The structured
pre-parsed token shape below is a stepping-stone toward that wiring.

FAIL-CLOSED: per CLAUDE.md keystone invariant #2 ("Pass without
evidence is not a pass.") this module's ``validate_tsa_token`` MUST
NOT report ``outcome="ok"`` based on a presence-only check of
``tsa_signature_b64u``. Until the cryptographic CMS SignerInfo
signature is verified against the TSA cert chain bundled at
``packages/verifier/src/relay_verifier/tsa_chain/tsa-chain.pem``,
the function fail-closes via the module-level
``TSA_CRYPTO_IMPLEMENTED`` flag (currently ``False``). A token whose
structural checks pass but whose signature has not been
cryptographically verified is reported as ``outcome="invalid"`` with
``reason`` starting ``"TSA cryptographic signature verification"``.
Flipping the flag to ``True`` without the accompanying verifier is a
P1 keystone-invariant regression and is guarded by
``packages/verifier/tests/test_tsa_crypto_failclosed.py``.

The structured token shape (mirrors ASN.1 RFC 3161 sec 2.4.2 TSTInfo):

    {
      "version": 1,
      "policy_oid": "1.3.6.1.4.1.601.10.3.1",   # TSA policy OID
      "message_imprint": {
        "hash_algorithm": "sha256",
        "hashed_message_hex": "<sha256 of bundle bytes>",
      },
      "serial_number": "<integer>",
      "gen_time": "2026-05-15T12:34:56Z",       # RFC 3339 UTC
      "tsa_signature_alg": "ES256" | "EdDSA" | "RS256",
      "tsa_signer_cert_subject": "<X.500 DN>",
      "tsa_signature_b64u": "<base64url signature over message_imprint>",
    }

The verifier checks:

  1. message_imprint.hashed_message_hex matches a recomputed
     SHA-256(bundle_canonical_bytes).
  2. gen_time is within +/-300 s of decided_at.
  3. The TSA signature verifies against a cert in the bundled chain.
  4. The cert chain itself parses as PEM, has notAfter in the future
     (cert chain not expired), and meets minimum key strength
     (RSA >= 2048 / ECDSA >= P-256 / Ed25519).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any, Final

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

# Single-source +/-300 s skew bound per spec section L.5 line 4479 + AB
# line 5690. The same constant is used for VAL-W10-027 (TSA genTime vs
# decided_at) AND VAL-W10-034 (auditor clock skew tolerance) AND
# VAL-W10-031 (key not_before grace window). Changing this constant is a
# spec-amendment-level decision; no individual call-site should override
# it.
CLOCK_SKEW_TOLERANCE_SECONDS: Final[int] = 300

# Wire codes raised by this module.
RELAY_EVID_031: Final[str] = "RELAY-EVID-031"
"""TSA timestamp missing (VAL-W10-025)."""

RELAY_EVID_038: Final[str] = "RELAY-EVID-038"
"""Backdated/forward-dated evidence: TSA genTime outside +/-300 s of
decided_at (VAL-W10-027)."""

# Canonical packaged path for the TSA cert chain shipped with the
# verifier wheel. The directory is a hatch-include target in
# packages/verifier/pyproject.toml so it lands inside the installed
# package.
TSA_CHAIN_DIRNAME: Final[str] = "tsa_chain"
TSA_CHAIN_FILENAME: Final[str] = "tsa-chain.pem"

# Minimum key strengths per VAL-W10-042. Mirrors the L.1 algorithm
# allow-list rejection of weaker primitives.
MIN_RSA_BITS: Final[int] = 2048

# Cryptographic TSA signature verification feature flag. MUST remain
# False until ``validate_tsa_token`` verifies the CMS SignerInfo
# signature in the RFC 3161 TimeStampResp against the bundled TSA
# cert chain (asn1crypto / rfc3161-client). With the flag at False
# the function fail-closes when a token is present; flipping it to
# True without wiring the real verifier is a P1 keystone-invariant
# regression guarded by
# ``test_tsa_crypto_failclosed.py::test_tsa_crypto_flag_is_false``.
TSA_CRYPTO_IMPLEMENTED: Final[bool] = False


# -----------------------------------------------------------------------------
# Result types
# -----------------------------------------------------------------------------


@dataclass
class TSAValidationResult:
    """Aggregate verdict for a TSA timestamp on a bundle.

    `outcome` is one of: "ok", "invalid", "missing", "skew".
    `reason` carries a human-readable detail. `code` carries the wire
    code when one applies (RELAY-EVID-031 / RELAY-EVID-038); "" on ok.
    `gen_time` echoes the parsed token genTime (or "" when missing).
    `skew_seconds` is the absolute delta between gen_time and
    decided_at; -1 when not computed.
    """

    outcome: str = "missing"
    reason: str = ""
    code: str = ""
    gen_time: str = ""
    skew_seconds: int = -1


@dataclass(frozen=True)
class TSACertSummary:
    """Summary of one cert in the TSA trust chain (VAL-W10-042)."""

    subject: str
    issuer: str
    not_before: str
    not_after: str
    key_alg: str
    key_strength_bits: int
    is_self_signed: bool


@dataclass
class TSAChainCheck:
    """Result of inspecting the bundled TSA cert chain."""

    chain_path: str
    cert_count: int
    certs: list[TSACertSummary]
    chain_ok: bool
    reason: str = ""


# -----------------------------------------------------------------------------
# Time helpers
# -----------------------------------------------------------------------------


def _parse_iso_z(s: str) -> _dt.datetime:
    """Parse an RFC 3339 UTC timestamp ending in 'Z' to a datetime.

    Raises :class:`ValueError` on malformed input. Accepts both
    seconds-resolution and fractional-second forms; both are emitted by
    the canonical bundle producer.
    """
    if not isinstance(s, str) or not s:
        raise ValueError(f"timestamp must be a non-empty string, got {s!r}")
    if not s.endswith("Z"):
        raise ValueError(f"timestamp must end with 'Z' (UTC), got {s!r}")
    # Python's fromisoformat accepts the form once we replace the trailing
    # Z with +00:00 (3.11+). 3.12+ tolerates the Z suffix directly but
    # we normalise for forward-compat.
    return _dt.datetime.fromisoformat(s[:-1] + "+00:00")


def _abs_seconds_delta(a: _dt.datetime, b: _dt.datetime) -> int:
    delta = a - b
    return abs(int(delta.total_seconds()))


# -----------------------------------------------------------------------------
# TSA token validation
# -----------------------------------------------------------------------------


def validate_tsa_token(
    *,
    token: dict[str, Any] | None,
    bundle_digest_hex: str,
    decided_at: str,
    chain_certs: list[x509.Certificate] | None = None,
) -> TSAValidationResult:
    """Validate a parsed RFC 3161 TSTInfo token against the bundle.

    See module docstring for the structured token shape. Returns a
    `TSAValidationResult`. Failure modes:

      * `token is None` -> outcome="missing", code=RELAY-EVID-031
        (VAL-W10-025).
      * message_imprint mismatch -> outcome="invalid", code=""
        (VAL-W10-026 alternate path).
      * gen_time outside +/-300 s -> outcome="skew",
        code=RELAY-EVID-038 (VAL-W10-027).
      * unparsable gen_time -> outcome="invalid".
      * tsa_signature_b64u empty/missing -> outcome="invalid".
      * cert chain provided AND tsa_signer_cert_subject not present in
        chain -> outcome="invalid".

    The TSA signature itself is verified by the bundle producer at
    issue time; this verifier validates the structural binding (digest
    matches, time is within tolerance, signer is a known TSA cert).
    Cryptographic signature verification of the TSA's CMS SignerInfo
    requires asn1crypto+pyhanko which the OSS verifier wheel does not
    pull in (banned-pattern-14 + dep-minimisation rationale in module
    docstring). Auditors who require deeper TSA verification can BYO a
    full RFC 3161 client by extending `chain_certs` with the TSA's
    cert and validating SignerInfo themselves.

    The cert-subject membership check is the contract-required validation
    surface (VAL-W10-026 says "validate against the TSA certificate
    chain bundled in the trust bundle"); a tampered .tsr produces a
    mismatched subject (or a mismatched message_imprint) and is rejected.
    """
    result = TSAValidationResult()

    if token is None:
        result.outcome = "missing"
        result.reason = "no TSA token (.tsr) attached to bundle"
        result.code = RELAY_EVID_031
        return result

    if not isinstance(token, dict):
        result.outcome = "invalid"
        result.reason = (
            f"TSA token must be a structured object, got {type(token).__name__}"
        )
        return result

    # 1. message_imprint binds the bundle bytes to the timestamp.
    msg_imprint = token.get("message_imprint")
    if not isinstance(msg_imprint, dict):
        result.outcome = "invalid"
        result.reason = "TSA token missing or malformed 'message_imprint'"
        return result
    declared_digest = msg_imprint.get("hashed_message_hex")
    declared_alg = msg_imprint.get("hash_algorithm")
    if declared_alg != "sha256":
        result.outcome = "invalid"
        result.reason = (
            f"TSA message_imprint must use sha256, got {declared_alg!r}"
        )
        return result
    if declared_digest != bundle_digest_hex:
        result.outcome = "invalid"
        result.reason = (
            "TSA message_imprint digest does not match recomputed bundle "
            f"digest (declared={declared_digest!r}, recomputed="
            f"{bundle_digest_hex!r})"
        )
        return result

    # 2. gen_time within +/-300 s of decided_at.
    gen_time_str = token.get("gen_time")
    if not isinstance(gen_time_str, str) or not gen_time_str:
        result.outcome = "invalid"
        result.reason = "TSA token missing 'gen_time'"
        return result
    result.gen_time = gen_time_str
    try:
        gen_time = _parse_iso_z(gen_time_str)
    except ValueError as exc:
        result.outcome = "invalid"
        result.reason = f"TSA gen_time unparsable: {exc}"
        return result
    try:
        decided = _parse_iso_z(decided_at)
    except ValueError as exc:
        result.outcome = "invalid"
        result.reason = f"bundle decided_at unparsable: {exc}"
        return result
    skew = _abs_seconds_delta(gen_time, decided)
    result.skew_seconds = skew
    if skew > CLOCK_SKEW_TOLERANCE_SECONDS:
        result.outcome = "skew"
        result.reason = (
            f"TSA gen_time skew {skew}s exceeds +/-{CLOCK_SKEW_TOLERANCE_SECONDS}s "
            f"tolerance (gen_time={gen_time_str}, decided_at={decided_at})"
        )
        result.code = RELAY_EVID_038
        return result

    # 3. TSA signature presence (structural pre-check; full crypto
    # verify gated on TSA_CRYPTO_IMPLEMENTED below).
    tsa_sig = token.get("tsa_signature_b64u")
    if not isinstance(tsa_sig, str) or not tsa_sig:
        result.outcome = "invalid"
        result.reason = "TSA token missing 'tsa_signature_b64u'"
        return result

    # 4. Subject membership in chain (VAL-W10-026 structural pre-check).
    if chain_certs is not None and len(chain_certs) > 0:
        signer_subject = token.get("tsa_signer_cert_subject")
        if not isinstance(signer_subject, str) or not signer_subject:
            result.outcome = "invalid"
            result.reason = "TSA token missing 'tsa_signer_cert_subject'"
            return result
        chain_subjects = {cert.subject.rfc4514_string() for cert in chain_certs}
        if signer_subject not in chain_subjects:
            result.outcome = "invalid"
            result.reason = (
                f"TSA signer subject {signer_subject!r} not present in bundled "
                f"trust chain ({len(chain_certs)} certs checked)"
            )
            return result

    # 5. Cryptographic TSA signature verification (FAIL-CLOSED).
    # Per CLAUDE.md keystone invariant #2 ("Pass without evidence is
    # not a pass.") we MUST NOT report outcome="ok" until the CMS
    # SignerInfo signature inside the RFC 3161 TimeStampResp has been
    # cryptographically verified against the bundled TSA cert chain
    # (signature MUST verify under one of the chain certs' public keys
    # over the DER-encoded TSTInfo; chain MUST link to a self-signed
    # root that is itself trusted; the signer cert MUST be valid at
    # gen_time). Until asn1crypto (or rfc3161-client) is wired and
    # called here, the flag stays False and EVERY token whose
    # cryptographic signature has not been verified is rejected.
    if not TSA_CRYPTO_IMPLEMENTED:
        result.outcome = "invalid"
        result.reason = (
            "TSA cryptographic signature verification is not implemented "
            "in this build; refusing to claim outcome='ok'. The structural "
            "checks (message_imprint match, gen_time within window, "
            "signer-subject membership) passed, but the CMS SignerInfo "
            "signature in the RFC 3161 token has not been verified "
            "against the TSA cert chain. Tracking issue: P1 verifier "
            "crypto gap."
        )
        return result

    # Unreachable while the flag is False. When wired, this block will
    # call into asn1crypto's tsp.TimeStampResp -> SignedData ->
    # SignerInfo verification path, validating the signature over the
    # TSTInfo bytes under the public key of one of chain_certs.
    result.outcome = "ok"  # pragma: no cover - unreachable today
    return result  # pragma: no cover - unreachable today


# -----------------------------------------------------------------------------
# Cert chain inspection (VAL-W10-042)
# -----------------------------------------------------------------------------


def _classify_public_key(pub_key: Any) -> tuple[str, int]:
    """Return (alg_label, strength_bits) for a public key."""
    if isinstance(pub_key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    if isinstance(pub_key, ec.EllipticCurvePublicKey):
        return f"ECDSA-{pub_key.curve.name}", pub_key.key_size
    if isinstance(pub_key, rsa.RSAPublicKey):
        return "RSA", pub_key.key_size
    return type(pub_key).__name__, 0


def _is_self_signed(cert: x509.Certificate) -> bool:
    """Heuristic self-signed check: subject == issuer."""
    return (
        cert.subject.rfc4514_string() == cert.issuer.rfc4514_string()
    )


def load_tsa_chain_pem_bytes(pem_bytes: bytes) -> list[x509.Certificate]:
    """Parse PEM bytes into a list of X.509 certs."""
    certs = x509.load_pem_x509_certificates(pem_bytes)
    return list(certs)


def load_bundled_tsa_chain() -> tuple[Path, bytes]:
    """Locate and read the verifier-bundled TSA chain PEM file.

    Returns (path, raw_bytes). Raises FileNotFoundError if the bundled
    asset is missing (i.e., a damaged install).
    """
    pkg_resources = resources.files("relay_verifier").joinpath(TSA_CHAIN_DIRNAME)
    chain_file = pkg_resources.joinpath(TSA_CHAIN_FILENAME)
    if not chain_file.is_file():
        raise FileNotFoundError(
            f"bundled TSA chain not found at packaged path "
            f"{TSA_CHAIN_DIRNAME}/{TSA_CHAIN_FILENAME}"
        )
    raw = chain_file.read_bytes()
    # Convert to a real Path for downstream consumers that want the
    # filesystem location (test assertions, error messages).
    return Path(str(chain_file)), raw


def inspect_tsa_chain(pem_bytes: bytes, *, chain_path: str = "") -> TSAChainCheck:
    """Inspect a TSA cert chain per VAL-W10-042.

    Validates: cert_count >= 1, every notAfter in the future, every
    public key meets the minimum strength threshold, and the chain links
    via subject==issuer hops up to a self-signed root.

    Returns a `TSAChainCheck` describing what was found; `chain_ok` is
    True iff every check passed.
    """
    summaries: list[TSACertSummary] = []
    try:
        certs = load_tsa_chain_pem_bytes(pem_bytes)
    except ValueError as exc:
        return TSAChainCheck(
            chain_path=chain_path,
            cert_count=0,
            certs=[],
            chain_ok=False,
            reason=f"chain PEM parse failed: {exc}",
        )

    if not certs:
        return TSAChainCheck(
            chain_path=chain_path,
            cert_count=0,
            certs=[],
            chain_ok=False,
            reason="chain contains zero certificates (VAL-W10-042 requires >= 1)",
        )

    now = _dt.datetime.now(tz=_dt.UTC)
    issues: list[str] = []
    for cert in certs:
        alg, bits = _classify_public_key(cert.public_key())
        # not_valid_after_utc is the cryptography 42+ API; fall back to
        # the deprecated property for older installs (the dep is pinned
        # >= 42 in pyproject.toml so the new API is always available).
        not_after = cert.not_valid_after_utc
        not_before = cert.not_valid_before_utc
        summary = TSACertSummary(
            subject=cert.subject.rfc4514_string(),
            issuer=cert.issuer.rfc4514_string(),
            not_before=not_before.isoformat().replace("+00:00", "Z"),
            not_after=not_after.isoformat().replace("+00:00", "Z"),
            key_alg=alg,
            key_strength_bits=bits,
            is_self_signed=_is_self_signed(cert),
        )
        summaries.append(summary)
        if not_after <= now:
            issues.append(
                f"cert {summary.subject!r} expired at {summary.not_after}"
            )
        # Strength check.
        if alg == "RSA" and bits < MIN_RSA_BITS:
            issues.append(
                f"cert {summary.subject!r} RSA key bits={bits} below "
                f"MIN_RSA_BITS={MIN_RSA_BITS}"
            )
        elif alg.startswith("ECDSA-") and not alg.startswith(
            ("ECDSA-secp256", "ECDSA-secp384", "ECDSA-secp521")
        ):
            issues.append(
                f"cert {summary.subject!r} ECDSA curve {alg} below P-256"
            )
        elif bits == 0:
            issues.append(
                f"cert {summary.subject!r} unsupported key type {alg}"
            )

    # Chain linkage: every non-root cert's issuer must equal the next
    # cert's subject. Single self-signed cert is accepted as a
    # 1-hop chain.
    if len(certs) >= 2:
        for i, cert in enumerate(certs[:-1]):
            parent = certs[i + 1]
            if cert.issuer.rfc4514_string() != parent.subject.rfc4514_string():
                issues.append(
                    f"chain link broken at index {i}: "
                    f"issuer {cert.issuer.rfc4514_string()!r} != "
                    f"parent subject {parent.subject.rfc4514_string()!r}"
                )
    # Final cert in chain must be self-signed (the trust root).
    if not _is_self_signed(certs[-1]):
        issues.append(
            f"chain root cert {certs[-1].subject.rfc4514_string()!r} is not "
            "self-signed (issuer != subject)"
        )

    return TSAChainCheck(
        chain_path=chain_path,
        cert_count=len(certs),
        certs=summaries,
        chain_ok=not issues,
        reason="; ".join(issues),
    )


__all__ = [
    "CLOCK_SKEW_TOLERANCE_SECONDS",
    "MIN_RSA_BITS",
    "RELAY_EVID_031",
    "RELAY_EVID_038",
    "TSA_CHAIN_DIRNAME",
    "TSA_CHAIN_FILENAME",
    "TSA_CRYPTO_IMPLEMENTED",
    "TSACertSummary",
    "TSAChainCheck",
    "TSAValidationResult",
    "inspect_tsa_chain",
    "load_bundled_tsa_chain",
    "load_tsa_chain_pem_bytes",
    "validate_tsa_token",
]
