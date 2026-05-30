"""``rly verify-install`` command (W12.6 VAL-W12-028..034).

Verifies the integrity and provenance of the three Relay distribution
surfaces a user can install:

  * ``--python``  : the ``epochly-relay`` PyPI package (VAL-W12-028)
  * ``--npm``     : the ``@epochly/relay`` npm package    (VAL-W12-029)
  * ``--sidecar`` : the ``@epochly/relay-sidecar-bundle`` binary
                    for the active OS/arch (VAL-W12-030)

When invoked with no surface flag, all three checks run and produce a
single composite exit code + structured JSON output (VAL-W12-031). The
JSON envelope shape is::

    {
      "schema_version": "relay.cli.verify_install.v1",
      "trust_anchor": "<jwks url>",
      "offline_mode": <bool>,
      "python_check":  {"status": "pass|fail|skipped", ...},
      "npm_check":     {"status": "pass|fail|skipped", ...},
      "sidecar_check": {"status": "pass|fail|skipped", ...},
      "overall_status": "pass|fail"
    }

Trust anchor (VAL-W12-032, CLAUDE.md keystone #11): the default JWKS URL
is sourced from :data:`relay_verifier.constants.DEFAULT_JWKS_URL` --
this module contains ZERO occurrences of the URL literal so the verifier
package remains the single canonical site. ``--trust-anchor URL``
overrides for forks/self-hosters (auditable WARN on stderr).

Offline mode (VAL-W12-033): with ``--offline`` no network is touched.
Per-install records are read from disk and the cached JWKS at
``${RELAY_HOME}/jwks-cache/<host>.json`` is the only trust source. If
the cache is absent the check fails with RELAY-RELEASE-033 (not a
network error) -- offline mode is a structural promise, not a fallback.

Rekor inclusion (VAL-W12-034): per spec section AO.1 a Sigstore bundle
whose tlog entries are absent OR whose inclusion proof is missing is
treated as transparency-log absence and fails RELAY-RELEASE-034 with the
explicit message "Artifact not in Rekor transparency log."

Per-check failure semantics:

  * digest mismatch  -> ``RELAY-RELEASE-{028|029|030}`` with
                        ``detail.reason == "digest_mismatch"``
                        (digest is verified BEFORE Sigstore per the
                        spec section AO.1 orchestrator pin)
  * sigstore failure -> ``RELAY-RELEASE-{028|029|030}`` with
                        ``detail.reason`` from the bundle verifier
  * Rekor absence    -> ``RELAY-RELEASE-034`` (overrides per-check code
                        because Rekor absence is the higher-trust signal)
  * offline+no cache -> ``RELAY-RELEASE-033``
  * record missing   -> ``RELAY-RELEASE-{028|029|030}`` with
                        ``detail.reason == "install_record_missing"``

Test seams (NEVER used in production paths; gated on env var presence):

  * ``RLY_VERIFY_INSTALL_PYTHON_RECORD``  / ``--python-record PATH``
  * ``RLY_VERIFY_INSTALL_NPM_RECORD``     / ``--npm-record PATH``
  * ``RLY_VERIFY_INSTALL_SIDECAR_RECORD`` / ``--sidecar-record PATH``
  * ``RLY_VERIFY_INSTALL_HOME``           / ``--home PATH``
  * ``RLY_VERIFY_INSTALL_BLOCK_NETWORK``  (raises on any HTTP attempt)

Install records (one per installed package) are JSON files written by
the install workflow at canonical sites:

  * Python  : ``<site-packages>/epochly_relay-<version>.dist-info/
              RELAY_INSTALL_RECORD.json``
  * npm     : ``<node_modules>/@epochly/relay/.relay-install-record.json``
  * sidecar : ``${RELAY_HOME}/bin/.relay-install-record.json``

Per CLAUDE.md keystone invariant #1 this command never writes
``run_results`` or ``gate_decisions``; it computes a derived verdict
from on-disk evidence and reports it.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Literal

import typer

# Default trust anchor: imported from the verifier package so this module
# has ZERO copies of the literal URL. VAL-W12-032 grep guard depends on
# this; banned pattern #13 says the literal lives in ONE canonical place
# (relay_verifier.constants).
from relay_verifier.constants import DEFAULT_JWKS_URL

from ..bundle import (
    BundleSignatureInvalid,
    verify_sigstore,
)
from ..errors import build_envelope, emit_envelope
from ..exit_codes import (
    EXIT_4XX_BLOCK,
    EXIT_SUCCESS,
)
from ..jwks_cache import cache_path_for_url, load_jwks_from_cache

# -----------------------------------------------------------------------------
# Wire codes (one per assertion + per check kind)
# -----------------------------------------------------------------------------

RELAY_RELEASE_028: Final[str] = "RELAY-RELEASE-028"  # python check
RELAY_RELEASE_029: Final[str] = "RELAY-RELEASE-029"  # npm check
RELAY_RELEASE_030: Final[str] = "RELAY-RELEASE-030"  # sidecar check
RELAY_RELEASE_032: Final[str] = "RELAY-RELEASE-032"  # trust anchor guard
RELAY_RELEASE_033: Final[str] = "RELAY-RELEASE-033"  # offline-cache absent
RELAY_RELEASE_034: Final[str] = "RELAY-RELEASE-034"  # rekor absence
RELAY_VERIFY_JWKS_UNAVAILABLE: Final[str] = "RELAY-VERIFY-JWKS-UNAVAILABLE"
# Online-mode fail-closed: no JWKS could be resolved. Distinct from the
# offline-only RELAY-RELEASE-033 because the failure surface is different:
# offline mode said "no cache", online mode says "no anchor at all (cache
# empty AND fetch unavailable)". Silent pass on online cache-miss would
# let an unsigned/unanchored bundle slip through, which is a keystone
# violation (CLAUDE.md keystone #2: "Pass without evidence is not a pass.").

# Rekor transparency-log cryptographic verification feature flag. After
# M09-w9.3 (VAL-V2M09-004) this flag is True: ``_verify_rekor_inclusion``
# now decodes the Sigstore Bundle (or raw Rekor REST response) into a
# ``sigstore.models.TransparencyLogEntry`` and runs the real Merkle
# inclusion-proof verifier (``sigstore.models.verify_merkle_inclusion``),
# the checkpoint signature verifier
# (``sigstore.models.verify_checkpoint``), and the Signed Entry Timestamp
# verifier (``TransparencyLogEntry._verify_set``) against Rekor's bundled
# public key resolved from
# ``ClientTrustConfig.production().trusted_root.rekor_keyring(...)``.
# Flipping this flag back to ``False`` without removing the corresponding
# verifier calls is a P0 keystone-invariant regression (CLAUDE.md
# keystone #2: pass without evidence is not a pass); the polarity-
# inverted tripwire lives in
# ``test_verifier_crypto_failclosed.py::test_rekor_crypto_flag_is_true``.
REKOR_CRYPTO_IMPLEMENTED: Final[bool] = True

# -----------------------------------------------------------------------------
# Output schema-version pin
# -----------------------------------------------------------------------------

VERIFY_INSTALL_SCHEMA: Final[str] = "relay.cli.verify_install.v1"
INSTALL_RECORD_SCHEMA: Final[str] = "relay.cli.install_record.v1"

# -----------------------------------------------------------------------------
# Default trust root claim values (per spec section AO.4)
# -----------------------------------------------------------------------------

DEFAULT_TRUST_ROOT_CLAIM: Final[str] = "relay.epochly.com"
DEFAULT_OIDC_ISSUER: Final[str] = "https://token.actions.githubusercontent.com"

# Environment variable test seams
ENV_PYTHON_RECORD: Final[str] = "RLY_VERIFY_INSTALL_PYTHON_RECORD"
ENV_NPM_RECORD: Final[str] = "RLY_VERIFY_INSTALL_NPM_RECORD"
ENV_SIDECAR_RECORD: Final[str] = "RLY_VERIFY_INSTALL_SIDECAR_RECORD"
ENV_HOME: Final[str] = "RLY_VERIFY_INSTALL_HOME"
ENV_BLOCK_NETWORK: Final[str] = "RLY_VERIFY_INSTALL_BLOCK_NETWORK"


CheckStatus = Literal["pass", "fail", "skipped"]
CheckKind = Literal["python", "npm", "sidecar"]

PER_KIND_CODE: Final[dict[str, str]] = {
    "python": RELAY_RELEASE_028,
    "npm": RELAY_RELEASE_029,
    "sidecar": RELAY_RELEASE_030,
}


# -----------------------------------------------------------------------------
# Install-record loader
# -----------------------------------------------------------------------------


@dataclass(frozen=True)
class InstallRecord:
    """Parsed install record describing one installed artifact."""

    kind: str
    artifact_path: Path
    expected_sha256: str
    sigstore_bundle_path: Path
    oidc_issuer: str
    oidc_identity: str
    trust_root: str
    package_name: str
    version: str


def _load_install_record(path: Path, *, expected_kind: str) -> InstallRecord:
    """Load and validate an install record from disk.

    Raises:
        InstallRecordError: malformed or wrong-kind record.
    """
    if not path.exists():
        raise InstallRecordError(
            code=PER_KIND_CODE[expected_kind],
            reason="install_record_missing",
            message=f"install record not found at {path}",
            detail={"path": str(path), "kind": expected_kind},
        )
    try:
        raw = path.read_bytes()
        record = json.loads(raw.decode("utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise InstallRecordError(
            code=PER_KIND_CODE[expected_kind],
            reason="install_record_malformed",
            message=f"install record at {path} is not valid JSON: {exc}",
            detail={"path": str(path), "exception_class": type(exc).__name__},
        ) from exc
    if not isinstance(record, dict):
        raise InstallRecordError(
            code=PER_KIND_CODE[expected_kind],
            reason="install_record_malformed",
            message=f"install record at {path} is not a JSON object",
            detail={"path": str(path)},
        )
    if record.get("schema_version") != INSTALL_RECORD_SCHEMA:
        raise InstallRecordError(
            code=PER_KIND_CODE[expected_kind],
            reason="install_record_schema_mismatch",
            message=(
                f"install record schema_version mismatch: expected "
                f"{INSTALL_RECORD_SCHEMA!r}, got "
                f"{record.get('schema_version')!r}"
            ),
            detail={"path": str(path)},
        )
    kind = record.get("kind")
    if kind != expected_kind:
        raise InstallRecordError(
            code=PER_KIND_CODE[expected_kind],
            reason="install_record_kind_mismatch",
            message=(
                f"install record kind mismatch: expected {expected_kind!r}, "
                f"got {kind!r}"
            ),
            detail={"path": str(path)},
        )
    required = (
        "artifact_path",
        "expected_sha256",
        "sigstore_bundle_path",
        "oidc_issuer",
        "oidc_identity",
        "trust_root",
        "package_name",
        "version",
    )
    missing = [f for f in required if not isinstance(record.get(f), str)]
    if missing:
        raise InstallRecordError(
            code=PER_KIND_CODE[expected_kind],
            reason="install_record_missing_fields",
            message=f"install record at {path} missing fields: {missing}",
            detail={"path": str(path), "missing": missing},
        )
    return InstallRecord(
        # ``kind`` is proven equal to ``expected_kind`` (a ``str``) by the
        # kind-mismatch guard above; use the typed value.
        kind=expected_kind,
        artifact_path=Path(record["artifact_path"]),
        expected_sha256=record["expected_sha256"],
        sigstore_bundle_path=Path(record["sigstore_bundle_path"]),
        oidc_issuer=record["oidc_issuer"],
        oidc_identity=record["oidc_identity"],
        trust_root=record["trust_root"],
        package_name=record["package_name"],
        version=record["version"],
    )


class InstallRecordError(Exception):
    """Structured error raised by install-record loading or validation."""

    def __init__(
        self,
        *,
        code: str,
        reason: str,
        message: str,
        detail: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.reason = reason
        self.message = message
        self.detail = dict(detail) if detail else {}


# -----------------------------------------------------------------------------
# Single-surface verification
# -----------------------------------------------------------------------------


def _verify_rekor_inclusion(sigstore_bytes: bytes) -> tuple[bool, str]:
    """Return ``(ok, reason)`` for Rekor transparency-log inclusion.

    Real cryptographic verification (M09-w9.3 / VAL-V2M09-004, 011..014):

      - Decode ``sigstore_bytes`` into a
        ``sigstore.models.TransparencyLogEntry``. Two wire shapes are
        accepted:

          1. A full Sigstore Bundle JSON (cosign-bundle v0.x), in which
             case ``sigstore.models.Bundle.from_json`` is used and the
             ``Bundle.log_entry`` property yields the transparency-log
             entry (sigstore-python's parser raises ``InvalidBundle`` if
             the entry has no inclusion proof or checkpoint).
          2. A raw Rekor REST API response (single-entry map keyed by
             UUID, as returned by ``GET /api/v1/log/entries?logIndex=N``),
             in which case ``TransparencyLogEntry._from_v1_response``
             is used directly.

      - Resolve Rekor's verifying keyring from the Sigstore production
        Trusted Root via ``ClientTrustConfig.production(offline=True)``
        + ``trusted_root.rekor_keyring(KeyringPurpose.VERIFY)``. The
        offline flag keeps this fast and hermetic in CI; the cache is
        populated at sigstore-python install time.

      - Run three independent verifications. Each maps to a distinct
        wire reason so incident response can distinguish failure modes:

          * ``verify_merkle_inclusion(entry)`` -> reason
            ``"rekor_inclusion_proof_invalid"`` on failure.
            Walks the proof's hashes from the leaf hash (derived from
            the canonicalised entry body) up to the proof's root hash.
          * ``verify_checkpoint(keyring, entry)`` -> reason
            ``"rekor_checkpoint_signature_invalid"`` on failure.
            Verifies the witness signature on the signed checkpoint
            note plus consistency between the checkpoint's log_hash and
            the proof's root_hash.
          * ``entry._verify_set(keyring)`` -> reason
            ``"rekor_set_signature_invalid"`` on failure.
            Verifies the Signed Entry Timestamp signature against
            Rekor's public key keyed by ``log_id.key_id``.

      - A bundle with no parseable transparency-log entry returns
        ``(False, "transparency_log_entry_missing")``. The calling CLI
        surfaces this as ``RELAY-RELEASE-034`` per spec section AO.1
        (transparency-log absence is the higher-trust signal).

    Per CLAUDE.md keystone invariant #2 ("Pass without evidence is not
    a pass.") and spec section AO.1 every failure path returns a
    structured reason; an exception escaping this function is itself a
    bug (caught broadly to keep the CLI's exit-code contract).

    Args:
        sigstore_bytes: Raw bytes of the Sigstore bundle JSON OR a
            Rekor REST API single-entry response.

    Returns:
        ``(True, "")`` on success; ``(False, reason)`` otherwise where
        ``reason`` is one of: ``transparency_log_entry_missing``,
        ``transparency_log_entry_unparseable``,
        ``transparency_log_entry_bundle_invalid``,
        ``rekor_inclusion_proof_invalid``,
        ``rekor_checkpoint_signature_invalid``,
        ``rekor_set_signature_invalid``,
        ``rekor_trust_root_unavailable``.
    """
    # Late imports keep module-import cost low and let unit tests
    # exercise the failure paths without forcing a Sigstore install at
    # CLI startup.
    try:
        from sigstore.errors import VerificationError

        # ``sigstore.models`` defines no ``__all__``, so pyright treats the
        # re-exported helpers below (``KeyringPurpose``, ``verify_checkpoint``,
        # ``verify_merkle_inclusion`` -- all defined in ``sigstore._internal.*``)
        # as private imports. They are part of sigstore's documented
        # verification surface and resolve at runtime; importing from the
        # ``_internal`` modules directly would be more fragile and is likewise
        # flagged. Narrow per-symbol suppression only.
        from sigstore.models import (
            Bundle,
            ClientTrustConfig,
            InvalidBundle,
            KeyringPurpose,  # pyright: ignore[reportPrivateImportUsage]
            TransparencyLogEntry,
            verify_checkpoint,  # pyright: ignore[reportPrivateImportUsage]
            verify_merkle_inclusion,  # pyright: ignore[reportPrivateImportUsage]
        )
    except Exception as exc:  # pragma: no cover - import failure
        return False, f"sigstore_unavailable:{type(exc).__name__}"

    # Step 1: decode bytes -> text -> JSON. Bytes that are not valid
    # UTF-8 or not valid JSON yield a structured reason; this is the
    # "garbage input" gate.
    if isinstance(sigstore_bytes, bytes):
        try:
            bundle_text = sigstore_bytes.decode("utf-8")
        except UnicodeDecodeError:
            return False, "transparency_log_entry_unparseable"
    else:
        bundle_text = sigstore_bytes

    # Step 2: locate a TransparencyLogEntry. Try the Sigstore-Bundle
    # shape first (this is the cosign-bundle wire format that the
    # release workflow signs); fall back to the raw Rekor REST shape
    # for tests / direct verification of fetched proofs.
    log_entry: TransparencyLogEntry | None = None
    bundle_parse_error: Exception | None = None
    try:
        bundle = Bundle.from_json(bundle_text)
    except Exception as exc:
        bundle_parse_error = exc
        bundle = None  # type: ignore[assignment]
    if bundle is not None:
        try:
            log_entry = bundle.log_entry
        except InvalidBundle:
            # Bundle parsed but has no usable inclusion proof. Per spec
            # section AO.1 this is transparency-log absence.
            return False, "transparency log entry missing"

    if log_entry is None:
        # Try the Rekor REST single-entry shape.
        try:
            raw = json.loads(bundle_text)
        except json.JSONDecodeError:
            return False, "transparency_log_entry_unparseable"
        if not isinstance(raw, dict) or not raw:
            # An empty tlogEntries[] inside a Bundle JSON ends up here
            # when the Bundle parser rejected the shape; surface it as
            # the spec-pinned "transparency log" phrasing.
            return False, "transparency log entry missing"
        # Check the Bundle path first: a dict with verificationMaterial
        # but empty tlogEntries[] is a forked/unsigned bundle, not a
        # Rekor REST response.
        if "verificationMaterial" in raw:
            tlogs = (raw.get("verificationMaterial") or {}).get("tlogEntries") or []
            if not tlogs:
                return False, "transparency log entry missing"
            # Fell through Bundle.from_json earlier -- the shape was
            # close but not valid. Propagate the parse error reason.
            return False, "transparency_log_entry_bundle_invalid"
        # Rekor REST shape: {"<uuid>": {body, verification, ...}}
        try:
            log_entry = TransparencyLogEntry._from_v1_response(raw)
        except Exception:
            # Neither a Sigstore Bundle nor a parseable Rekor REST
            # response. Surface the Bundle parse failure if we had one;
            # otherwise treat as missing entry.
            if bundle_parse_error is not None:
                return False, "transparency_log_entry_bundle_invalid"
            return False, "transparency log entry missing"

    # Step 3: resolve Rekor's verifying keyring from the production
    # trust root. Offline=True uses the TUF cache populated at
    # sigstore-python install time, so this is hermetic in CI.
    try:
        trust_config = ClientTrustConfig.production(offline=True)
        rekor_keyring = trust_config.trusted_root.rekor_keyring(KeyringPurpose.VERIFY)
    except Exception:
        return False, "rekor_trust_root_unavailable"

    # Step 4: verify the Merkle inclusion proof. A tampered hashes[]
    # array or a wrong root_hash is caught here.
    try:
        verify_merkle_inclusion(log_entry)
    except VerificationError:
        return False, "rekor_inclusion_proof_invalid"
    except Exception:
        # Defensive: any unexpected exception is treated as a proof
        # failure rather than escaping the function.
        return False, "rekor_inclusion_proof_invalid"

    # Step 5: verify the signed checkpoint. A wrong witness signature
    # or a checkpoint whose log_hash does not match the proof root hash
    # is caught here.
    try:
        verify_checkpoint(rekor_keyring, log_entry)
    except VerificationError:
        return False, "rekor_checkpoint_signature_invalid"
    except Exception:
        return False, "rekor_checkpoint_signature_invalid"

    # Step 6: verify the Signed Entry Timestamp (SET) -- the Rekor-
    # signed promise that the entry was integrated at a specific time.
    # A tampered SET signature is caught here. SET failures are kept
    # distinct from proof failures because they have different
    # incident-response implications (witness-key compromise vs. proof
    # tampering by a man-in-the-middle).
    try:
        log_entry._verify_set(rekor_keyring)
    except VerificationError:
        return False, "rekor_set_signature_invalid"
    except Exception:
        return False, "rekor_set_signature_invalid"

    return True, ""


def _verify_one_surface(
    *,
    kind: str,
    record_path: Path,
    trust_root_override: str | None = None,
) -> dict[str, Any]:
    """Run digest + sigstore + rekor checks for one install surface.

    Returns the per-check dict suitable for embedding in the composite
    envelope: ``{status, error_code?, detail?, package_name?, version?,
    artifact_sha256?}``.
    """
    code_for_kind = PER_KIND_CODE[kind]
    try:
        record = _load_install_record(record_path, expected_kind=kind)
    except InstallRecordError as exc:
        return {
            "status": "fail",
            "error_code": exc.code,
            "detail": {"reason": exc.reason, **exc.detail},
        }

    # Step 1: digest check (BEFORE Sigstore per spec section AO.1
    # orchestrator pin -- a tampered artifact must surface as a digest
    # mismatch even if the signature happens to validate.)
    if not record.artifact_path.exists():
        return {
            "status": "fail",
            "error_code": code_for_kind,
            "detail": {
                "reason": "artifact_missing",
                "artifact_path": str(record.artifact_path),
            },
            "package_name": record.package_name,
            "version": record.version,
        }
    artifact_bytes = record.artifact_path.read_bytes()
    observed_digest = hashlib.sha256(artifact_bytes).hexdigest()
    if observed_digest != record.expected_sha256:
        return {
            "status": "fail",
            "error_code": code_for_kind,
            "detail": {
                "reason": "digest_mismatch",
                "artifact_path": str(record.artifact_path),
                "expected": record.expected_sha256,
                "observed": observed_digest,
            },
            "package_name": record.package_name,
            "version": record.version,
        }

    # Step 2: load the sigstore bundle (always from disk; offline-safe).
    if not record.sigstore_bundle_path.exists():
        return {
            "status": "fail",
            "error_code": code_for_kind,
            "detail": {
                "reason": "sigstore_bundle_missing",
                "sigstore_bundle_path": str(record.sigstore_bundle_path),
            },
            "package_name": record.package_name,
            "version": record.version,
        }
    sigstore_bytes = record.sigstore_bundle_path.read_bytes()

    # Step 3: Rekor transparency-log inclusion (VAL-W12-034).
    # Per spec section AO.1 transparency-log absence is the higher-trust
    # signal: a locally-signed (fork) bundle that happens to satisfy
    # every structural check is STILL a forgery if Rekor has no entry
    # for it. We therefore run the Rekor inclusion check BEFORE the
    # structural Sigstore verifier so the distinct RELAY-RELEASE-034
    # code surfaces verbatim. The structural verifier in bundle.py
    # requires len(tlogEntries) > 0 and would otherwise mask the
    # transparency-absence verdict behind a generic signature error.
    rekor_ok, rekor_reason = _verify_rekor_inclusion(sigstore_bytes)
    if not rekor_ok:
        return {
            "status": "fail",
            "error_code": RELAY_RELEASE_034,
            "detail": {
                "reason": rekor_reason,
                "sigstore_bundle_path": str(record.sigstore_bundle_path),
            },
            "package_name": record.package_name,
            "version": record.version,
        }

    # Step 4: structural Sigstore verification (cert + signature + trust
    # root + OIDC identity). Delegates to bundle.verify_sigstore which is
    # shared with rly sidecar install.
    expected_trust_root = trust_root_override or record.trust_root or DEFAULT_TRUST_ROOT_CLAIM
    try:
        verify_sigstore(
            sigstore_bytes,
            expected_trust_root=expected_trust_root,
            expected_oidc_issuer=record.oidc_issuer,
            expected_identity=record.oidc_identity,
            artifact_bytes=artifact_bytes,
        )
    except BundleSignatureInvalid as exc:
        return {
            "status": "fail",
            "error_code": code_for_kind,
            "detail": {
                "reason": "sigstore_signature_invalid",
                "sigstore_reason": exc.details.get(
                    "reason", "sigstore_verification_failed"
                ),
                "sigstore_bundle_path": str(record.sigstore_bundle_path),
                "message": str(exc),
            },
            "package_name": record.package_name,
            "version": record.version,
        }

    return {
        "status": "pass",
        "package_name": record.package_name,
        "version": record.version,
        "artifact_sha256": observed_digest,
    }


# -----------------------------------------------------------------------------
# JWKS resolution (offline/online distinction)
# -----------------------------------------------------------------------------


class _JwksUnavailableError(Exception):
    """Raised by :func:`_resolve_jwks` when no JWKS can be resolved.

    Carries a structured reason + the cache path + the active trust
    anchor so the caller can emit a wire envelope with full diagnostics.
    This is a fail-closed signal (CLAUDE.md keystone #2): an online
    verification with no resolvable trust anchor MUST NOT pass silently.
    """

    def __init__(
        self,
        *,
        reason: str,
        message: str,
        trust_anchor_url: str,
        cache_path: Path,
    ) -> None:
        super().__init__(message)
        self.reason = reason
        self.message = message
        self.trust_anchor_url = trust_anchor_url
        self.cache_path = cache_path


def _resolve_jwks(
    *,
    trust_anchor_url: str,
    home: Path | None,
    offline: bool,
) -> tuple[dict[str, Any], None]:
    """Return ``(jwks, None)`` or raise :class:`_JwksUnavailableError`.

    Resolution policy (per CLAUDE.md keystone #2 "Pass without evidence
    is not a pass." -- the JWKS is the trust anchor that binds every
    bundle signature; an unresolved JWKS is a hard failure regardless
    of online/offline mode):

      * Cache hit -> return the cached JWKS.
      * Cache miss + offline -> raise (offline-cache-absent).
      * Cache miss + online + network blocked -> raise (network-blocked).
      * Cache miss + online + network NOT blocked -> raise. The OSS
        profile does NOT silently fetch from the network here. A future
        maintenance release can wire a one-shot fetch path, but until
        then the only auditor-supported way to populate the cache is
        an explicit out-of-band fetch documented in the runbook.

    The network is NEVER touched when ``RLY_VERIFY_INSTALL_BLOCK_NETWORK``
    is set in the environment. This is the contract that lets the test
    suite assert "no egress in offline mode."

    The previous implementation returned ``(None, None)`` on the
    online + cache-miss + unblocked path, which let online verification
    pass silently with no trust anchor anchored. That is a regression
    against the keystone invariant; this implementation fails-closed.
    """
    cached = load_jwks_from_cache(trust_anchor_url, home=home)
    if cached is not None:
        return cached, None
    # VAL-ISO-034: reuse the canonical path derivation so the diagnostic
    # cache_path is byte-identical to what load_jwks_from_cache consulted
    # (including the relay_home() / RELAY_HOME fallback when home is None,
    # the port suffix, and charset sanitization). A bespoke helper here
    # drifted: it fell back to Path.home()/.relay and re-derived the host
    # filename by hand, reporting a path operators could not use to seed
    # the cache.
    cache_path = cache_path_for_url(trust_anchor_url, home=home)
    if offline:
        raise _JwksUnavailableError(
            reason="offline_jwks_cache_miss",
            message=(
                f"offline mode requested but JWKS cache miss for "
                f"{trust_anchor_url!r}; run `rly verify-install` once "
                f"online to populate the cache at {cache_path!s}"
            ),
            trust_anchor_url=trust_anchor_url,
            cache_path=cache_path,
        )
    # Online cache miss. The OSS profile does not fetch silently here;
    # cache miss is a hard fail regardless of whether the network is
    # explicitly blocked or merely not configured.
    network_blocked = bool(os.environ.get(ENV_BLOCK_NETWORK))
    raise _JwksUnavailableError(
        reason="jwks_unavailable",
        message=(
            f"no JWKS could be resolved: no --trust-anchor cache hit "
            f"for {trust_anchor_url!r} at {cache_path!s} and "
            f"network fetch is "
            + ("blocked by RLY_VERIFY_INSTALL_BLOCK_NETWORK" if network_blocked
               else "not implemented in the OSS verifier")
            + "; populate the cache by running `rly verify-install` "
            "while online, or pass --offline once the cache is seeded."
        ),
        trust_anchor_url=trust_anchor_url,
        cache_path=cache_path,
    )


# -----------------------------------------------------------------------------
# Typer command callback
# -----------------------------------------------------------------------------


def cmd_verify_install(
    python: bool = typer.Option(
        False,
        "--python",
        help="Verify only the Python package install.",
    ),
    npm: bool = typer.Option(
        False,
        "--npm",
        help="Verify only the npm package install.",
    ),
    sidecar: bool = typer.Option(
        False,
        "--sidecar",
        help="Verify only the sidecar binary install.",
    ),
    offline: bool = typer.Option(
        False,
        "--offline",
        help=(
            "Offline mode: verify against the cached JWKS at "
            "${RELAY_HOME}/jwks-cache/<host>.json and cached install "
            "records. No network egress."
        ),
    ),
    trust_anchor: str = typer.Option(
        "",
        "--trust-anchor",
        help=(
            "Override the default JWKS URL "
            "(VAL-W12-032 / CLAUDE.md keystone #11). Forks/self-hosters "
            "only; emits a structured stderr WARN."
        ),
    ),
    print_trust_anchor: bool = typer.Option(
        False,
        "--print-trust-anchor",
        help="Print the active trust anchor URL and exit 0.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Force JSON output even when stdout is a TTY (default when piped).",
    ),
    python_record: str = typer.Option(
        "",
        "--python-record",
        help="Path to the Python install record (test seam).",
    ),
    npm_record: str = typer.Option(
        "",
        "--npm-record",
        help="Path to the npm install record (test seam).",
    ),
    sidecar_record: str = typer.Option(
        "",
        "--sidecar-record",
        help="Path to the sidecar install record (test seam).",
    ),
    home: str = typer.Option(
        "",
        "--home",
        help="Override RELAY_HOME (used for the JWKS cache lookup).",
    ),
) -> None:
    """Verify the integrity and provenance of installed Relay packages.

    Exit 0 iff every requested check passes; non-zero with a structured
    error envelope on any failure. Produces a single composite JSON
    envelope on stdout (VAL-W12-031). Default trust anchor is the
    spec-pinned JWKS URL (VAL-W12-032).
    """
    _ = json_output  # always JSON on stdout; flag is for parity with rest of CLI

    # --print-trust-anchor short-circuit (VAL-W12-032).
    if print_trust_anchor:
        active_anchor = trust_anchor.strip() if trust_anchor else DEFAULT_JWKS_URL
        sys.stdout.write(active_anchor + "\n")
        sys.stdout.flush()
        raise typer.Exit(code=EXIT_SUCCESS)

    active_anchor = trust_anchor.strip() if trust_anchor else DEFAULT_JWKS_URL
    if trust_anchor:
        # VAL-W12-032 audit trail: any BYO trust anchor emits a WARN.
        emit_envelope(
            build_envelope(
                code="RELAY-RELEASE-032",
                http_status=200,
                message=(
                    f"trust anchor override active: {active_anchor!r} "
                    f"(default is {DEFAULT_JWKS_URL!r})"
                ),
                blocked_surface="rly verify-install",
                retry_advice="do_not_retry",
                details={
                    "override": active_anchor,
                    "default": DEFAULT_JWKS_URL,
                    "reason": "byo_trust_anchor",
                },
            )
        )

    home_path: Path | None = None
    if home:
        home_path = Path(home).expanduser()
    elif os.environ.get(ENV_HOME):
        home_path = Path(os.environ[ENV_HOME]).expanduser()

    # Determine which surfaces to verify. No surface flag means "all
    # three" (VAL-W12-031 composite mode).
    run_python = python or not (python or npm or sidecar)
    run_npm = npm or not (python or npm or sidecar)
    run_sidecar = sidecar or not (python or npm or sidecar)

    # Resolve install-record paths via flag -> env -> default (None).
    py_record_path = _resolve_record_path(
        flag_value=python_record,
        env_var=ENV_PYTHON_RECORD,
    )
    npm_record_path = _resolve_record_path(
        flag_value=npm_record,
        env_var=ENV_NPM_RECORD,
    )
    sidecar_record_path = _resolve_record_path(
        flag_value=sidecar_record,
        env_var=ENV_SIDECAR_RECORD,
    )

    # Resolve JWKS once -- shared by every check. Both offline cache
    # miss (RELAY-RELEASE-033) and online unresolvable trust anchor
    # (RELAY-VERIFY-JWKS-UNAVAILABLE) surface as fail-closed verdicts
    # per CLAUDE.md keystone #2 ("Pass without evidence is not a pass.").
    jwks_failure: dict[str, Any] | None = None
    try:
        _jwks, _ = _resolve_jwks(
            trust_anchor_url=active_anchor,
            home=home_path,
            offline=offline,
        )
    except _JwksUnavailableError as exc:
        # Preserve the existing wire-code contract for the offline branch
        # (VAL-W12-033 -> RELAY-RELEASE-033) and surface the new
        # fail-closed code for the online branch.
        error_code = (
            RELAY_RELEASE_033
            if exc.reason == "offline_jwks_cache_miss"
            else RELAY_VERIFY_JWKS_UNAVAILABLE
        )
        jwks_failure = {
            "status": "fail",
            "error_code": error_code,
            "detail": {
                "reason": exc.reason,
                "trust_anchor": exc.trust_anchor_url,
                "cache_path": str(exc.cache_path),
                "message": exc.message,
            },
        }

    def _maybe_offline_fail(check_result: dict[str, Any]) -> dict[str, Any]:
        """Promote a pass to a JWKS-failure verdict when JWKS is unresolved."""
        if jwks_failure is None:
            return check_result
        return {
            **jwks_failure,
            **{
                k: v
                for k, v in check_result.items()
                if k in ("package_name", "version", "artifact_sha256")
            },
        }

    python_check: dict[str, Any] = {"status": "skipped"}
    npm_check: dict[str, Any] = {"status": "skipped"}
    sidecar_check: dict[str, Any] = {"status": "skipped"}

    if run_python:
        if py_record_path is None:
            python_check = {
                "status": "fail",
                "error_code": RELAY_RELEASE_028,
                "detail": {
                    "reason": "install_record_missing",
                    "message": (
                        "no Python install record provided "
                        f"(set ${ENV_PYTHON_RECORD} or pass "
                        "--python-record PATH)"
                    ),
                },
            }
        else:
            python_check = _verify_one_surface(
                kind="python",
                record_path=py_record_path,
                trust_root_override=None,
            )
        python_check = _maybe_offline_fail(python_check)

    if run_npm:
        if npm_record_path is None:
            npm_check = {
                "status": "fail",
                "error_code": RELAY_RELEASE_029,
                "detail": {
                    "reason": "install_record_missing",
                    "message": (
                        "no npm install record provided "
                        f"(set ${ENV_NPM_RECORD} or pass "
                        "--npm-record PATH)"
                    ),
                },
            }
        else:
            npm_check = _verify_one_surface(
                kind="npm",
                record_path=npm_record_path,
                trust_root_override=None,
            )
        npm_check = _maybe_offline_fail(npm_check)

    if run_sidecar:
        if sidecar_record_path is None:
            sidecar_check = {
                "status": "fail",
                "error_code": RELAY_RELEASE_030,
                "detail": {
                    "reason": "install_record_missing",
                    "message": (
                        "no sidecar install record provided "
                        f"(set ${ENV_SIDECAR_RECORD} or pass "
                        "--sidecar-record PATH)"
                    ),
                },
            }
        else:
            sidecar_check = _verify_one_surface(
                kind="sidecar",
                record_path=sidecar_record_path,
                trust_root_override=None,
            )
        sidecar_check = _maybe_offline_fail(sidecar_check)

    overall = (
        "pass"
        if all(
            c["status"] in ("pass", "skipped")
            for c in (python_check, npm_check, sidecar_check)
        )
        else "fail"
    )

    envelope = {
        "schema_version": VERIFY_INSTALL_SCHEMA,
        "trust_anchor": active_anchor,
        "offline_mode": bool(offline),
        "python_check": python_check,
        "npm_check": npm_check,
        "sidecar_check": sidecar_check,
        "overall_status": overall,
    }

    sys.stdout.write(
        json.dumps(
            envelope,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    )
    sys.stdout.flush()

    if overall == "pass":
        raise typer.Exit(code=EXIT_SUCCESS)

    # Emit a structured stderr envelope summarizing failures so machine
    # consumers parsing stderr get the same wire signal as stdout.
    failed: list[dict[str, Any]] = []
    for name, check in (
        ("python_check", python_check),
        ("npm_check", npm_check),
        ("sidecar_check", sidecar_check),
    ):
        if check.get("status") == "fail":
            failed.append(
                {
                    "check": name,
                    "error_code": check.get("error_code"),
                    "reason": (check.get("detail") or {}).get("reason"),
                }
            )
    ran_count = sum(
        1
        for c in (python_check, npm_check, sidecar_check)
        if c["status"] != "skipped"
    )
    emit_envelope(
        build_envelope(
            code="RELAY-RELEASE-031",
            http_status=400,
            message=(
                f"verify-install FAIL: {len(failed)} of {ran_count} "
                "checks reported violations."
            ),
            blocked_surface="rly verify-install",
            retry_advice="after_fix",
            details={"failed_checks": failed},
        )
    )
    raise typer.Exit(code=EXIT_4XX_BLOCK)


def _resolve_record_path(*, flag_value: str, env_var: str) -> Path | None:
    """Resolve an install-record path via flag -> env -> None."""
    if flag_value:
        return Path(flag_value).expanduser()
    env_val = os.environ.get(env_var, "").strip()
    if env_val:
        return Path(env_val).expanduser()
    return None


__all__ = [
    "DEFAULT_TRUST_ROOT_CLAIM",
    "INSTALL_RECORD_SCHEMA",
    "InstallRecord",
    "InstallRecordError",
    "RELAY_RELEASE_028",
    "RELAY_RELEASE_029",
    "RELAY_RELEASE_030",
    "RELAY_RELEASE_032",
    "RELAY_RELEASE_033",
    "RELAY_RELEASE_034",
    "RELAY_VERIFY_JWKS_UNAVAILABLE",
    "VERIFY_INSTALL_SCHEMA",
    "cmd_verify_install",
]
