"""Sidecar bundle install pipeline (W5.2 VAL-W5-015..018).

Resolves the pinned ``packages/cli/src/sidecar_install/bundle_manifest.json``
file, downloads the per-host bundle from the manifest-declared HTTPS URL,
verifies SHA-256 digest first, then verifies the Sigstore signature (keyless
cosign-bundle), and installs the verified bytes into
``${RELAY_HOME}/bin/relay-sidecar-<version>`` via
:func:`local_atomic_file_write` (CLAUDE.md keystone invariant #8).

VAL-W5-015: refuse any URL not present in the pinned manifest. There is no
``--url`` flag on ``rly sidecar install``; callers cannot redirect.
VAL-W5-016: Sigstore signature is verified before the bundle is moved to its
install path. On failure: delete download, exit 1 with
``RELAY-CLI-SIDECAR-SIGNATURE-INVALID``.
VAL-W5-017: SHA-256 digest is verified independently. On mismatch: delete
download, exit 1 with ``RELAY-CLI-SIDECAR-DIGEST-MISMATCH``.
VAL-W5-018: install path is written through the atomic primitive; direct
``open(install_path, 'wb')`` is banned.

REAL CRYPTOGRAPHIC VERIFICATION (M09 / VAL-V2M09-001..010, 022):
``verify_sigstore`` invokes the upstream ``sigstore-python`` package
(``sigstore.verify.Verifier`` + ``sigstore.models.Bundle.verify_artifact``)
against the Sigstore public-good trust root by default. The module-level
``VERIFIER_SIGSTORE_CRYPTO_IMPLEMENTED`` flag is ``True`` to reflect
that cryptographic verification is wired. Sigstore exception subclasses
(``sigstore.errors.VerificationError`` and friends) are translated by
``_translate_sigstore_error`` into ``BundleSignatureInvalid`` with a
distinct ``details["reason"]`` per subclass so auditors can distinguish
identity / cert-chain / signature / transparency-log failure modes.

Per CLAUDE.md keystone invariant #2 ("Pass without evidence is not a
pass.") the function does NOT short-circuit any check on structural
JSON-shape grounds; every code path either calls the real verifier or
fail-closes with a structured reason. Per banned pattern #13 the
default trust anchor remains ``relay.epochly.com``; changing it is a
board-level decision, not a routine PR.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import platform
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Literal

# httpx is added to the CLI dependency set in pyproject.toml; the import
# happens at module import time but the global httpx state is not
# touched until ``download_bundle`` is called.
import httpx
from relay_sidecar.lockfile import relay_home
from relay_sidecar.primitives import local_atomic_file_write

# -----------------------------------------------------------------------------
# Wire codes (referenced verbatim from contract.md VAL-W5-015..018)
# -----------------------------------------------------------------------------

RELAY_CLI_SIDECAR_SIGNATURE_INVALID: Final[str] = "RELAY-CLI-SIDECAR-SIGNATURE-INVALID"
RELAY_CLI_SIDECAR_DIGEST_MISMATCH: Final[str] = "RELAY-CLI-SIDECAR-DIGEST-MISMATCH"
RELAY_CLI_USAGE_014: Final[str] = "RELAY-CLI-USAGE-014"
RELAY_CLI_SIDECAR_BUNDLE_UNAVAILABLE: Final[str] = "RELAY-CLI-SIDECAR-BUNDLE-UNAVAILABLE"
RELAY_CLI_SIDECAR_ARCH_UNSUPPORTED: Final[str] = "RELAY-CLI-SIDECAR-ARCH-UNSUPPORTED"
RELAY_CLI_SIDECAR_MANIFEST_MALFORMED: Final[str] = "RELAY-CLI-SIDECAR-MANIFEST-MALFORMED"

# Default canonical manifest path. Overridable for tests via the
# RELAY_CLI_SIDECAR_BUNDLE_MANIFEST environment variable.
ENV_BUNDLE_MANIFEST_PATH: Final[str] = "RELAY_CLI_SIDECAR_BUNDLE_MANIFEST"

# Default trust root. Per CLAUDE.md banned pattern #13 the OSS verifier
# defaults to the Relay-managed JWKS host; changing this default is a
# board-level decision, not a routine code edit.
DEFAULT_TRUST_ROOT: Final[str] = "relay.epochly.com"

# Cryptographic Sigstore verification feature flag. ``True`` after
# M09 / VAL-V2M09-003: ``verify_sigstore`` now invokes
# ``sigstore.verify.Verifier.verify_artifact`` against the parsed
# ``sigstore.models.Bundle``. Flipping this flag back to ``False`` is
# only acceptable if the corresponding real verifier call is removed in
# the same commit (paired by the polarity-inverted guard test
# ``test_w9_sigstore_verifier.py::test_sigstore_crypto_flag_is_true``).
VERIFIER_SIGSTORE_CRYPTO_IMPLEMENTED: Final[bool] = True

# Manifest schema version (matches what we ship in
# packages/cli/src/sidecar_install/bundle_manifest.json).
MANIFEST_SCHEMA_VERSION: Final[str] = "relay.cli.sidecar_install_manifest.v1"

# Supported OS/arch tuples (mirrors packages/sdk-typescript/src/bin/types.ts
# SUPPORTED_OS_ARCH). 4 cells: macos-arm64, linux-x86_64, linux-arm64,
# windows-x86_64.
#
# Intel macOS (darwin/x64) is intentionally absent: the release matrix
# builds only macos-arm64 (macos-x86_64 dropped 2026-05-28 by board-level
# decision; see CHANGELOG v0.1.16), and Rosetta 2 translates x86_64 ->
# arm64 (Intel binaries on Apple Silicon), not arm64 -> x86_64, so the
# arm64 binary cannot run on an Intel Mac. Advertising darwin/x64 here
# would let install_bundle pass the matrix check and then fail with the
# confusing "manifest does not enumerate a bundle for (darwin, x64)" (or,
# worse, fetch the nonexistent darwin/x64 asset). Omitting it surfaces a
# clean arch-unsupported error before any network call instead.
SupportedOs = Literal["darwin", "linux", "win32"]
SupportedArch = Literal["x64", "arm64"]
SUPPORTED_OS_ARCH: Final[tuple[tuple[str, str], ...]] = (
    ("darwin", "arm64"),
    ("linux", "x64"),
    ("linux", "arm64"),
    ("win32", "x64"),
)

# HTTPS download timeouts (seconds). Conservative; bundles are small but
# the manifest is typically fetched once per install.
DEFAULT_HTTP_TIMEOUT_S: Final[float] = 30.0


# -----------------------------------------------------------------------------
# Typed exceptions
# -----------------------------------------------------------------------------


class BundleInstallError(Exception):
    """Base class for bundle-install failures.

    Carries the wire ``code`` token (e.g. ``RELAY-CLI-SIDECAR-DIGEST-MISMATCH``)
    so the CLI can convert it into the canonical error envelope verbatim.
    Also carries a structured ``details`` dict for envelope details.
    """

    def __init__(
        self,
        code: str,
        message: str,
        *,
        details: dict[str, Any] | None = None,
        http_status: int = 500,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = dict(details) if details else {}
        self.http_status = http_status


class BundleDigestMismatch(BundleInstallError):
    """Raised when the downloaded bundle's SHA-256 disagrees with the manifest."""

    def __init__(self, message: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__(
            RELAY_CLI_SIDECAR_DIGEST_MISMATCH,
            message,
            details=details,
            http_status=400,
        )


class BundleSignatureInvalid(BundleInstallError):
    """Raised when the cosign-bundle signature verification fails."""

    def __init__(self, message: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__(
            RELAY_CLI_SIDECAR_SIGNATURE_INVALID,
            message,
            details=details,
            http_status=400,
        )


class BundleManifestMalformed(BundleInstallError):
    """Raised when the pinned bundle_manifest.json is missing or malformed."""

    def __init__(self, message: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__(
            RELAY_CLI_SIDECAR_MANIFEST_MALFORMED,
            message,
            details=details,
            http_status=500,
        )


class BundleArchUnsupported(BundleInstallError):
    """Raised when the host (os, arch) is not in the supported matrix.

    The matrix has 4 cells (macos-arm64, linux-x86_64, linux-arm64,
    windows-x86_64); Intel macOS (darwin/x64) is unsupported.
    """

    def __init__(self, message: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__(
            RELAY_CLI_SIDECAR_ARCH_UNSUPPORTED,
            message,
            details=details,
            http_status=400,
        )


class BundleUnavailable(BundleInstallError):
    """Raised when the bundle download fails (network / non-200)."""

    def __init__(self, message: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__(
            RELAY_CLI_SIDECAR_BUNDLE_UNAVAILABLE,
            message,
            details=details,
            http_status=503,
        )


class BundleUsageError(BundleInstallError):
    """Raised when the user passes a forbidden flag (e.g. ``--url``)."""

    def __init__(self, message: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__(
            RELAY_CLI_USAGE_014,
            message,
            details=details,
            http_status=400,
        )


# -----------------------------------------------------------------------------
# Manifest dataclasses
# -----------------------------------------------------------------------------


@dataclass(frozen=True)
class BundleEntry:
    os: str
    arch: str
    url: str
    expected_digest: str
    size_bytes: int
    sigstore_url: str


@dataclass(frozen=True)
class BundleManifest:
    schema_version: str
    sidecar_version: str
    trust_root: str
    expected_oidc_issuer: str
    expected_identity: str
    manifest_url: str
    bundles: tuple[BundleEntry, ...]

    def find(self, host_os: str, host_arch: str) -> BundleEntry:
        for entry in self.bundles:
            if entry.os == host_os and entry.arch == host_arch:
                return entry
        raise BundleArchUnsupported(
            f"manifest does not enumerate a bundle for ({host_os}, {host_arch})",
            details={
                "host_os": host_os,
                "host_arch": host_arch,
                "available": [(b.os, b.arch) for b in self.bundles],
            },
        )


# -----------------------------------------------------------------------------
# Manifest loading
# -----------------------------------------------------------------------------


def default_manifest_path() -> Path:
    """Resolve the canonical pinned manifest path.

    Resolution order (first match wins):
      1. ``RELAY_CLI_SIDECAR_BUNDLE_MANIFEST`` env var (test seam) -> use verbatim.
      2. ``packages/cli/src/sidecar_install/bundle_manifest.json`` relative to
         this module.
    """
    override = os.environ.get(ENV_BUNDLE_MANIFEST_PATH, "").strip()
    if override:
        return Path(override).expanduser()
    # bundle.py lives at packages/cli/src/relay_cli/bundle.py
    # The manifest lives at packages/cli/src/sidecar_install/bundle_manifest.json
    return Path(__file__).resolve().parent.parent / "sidecar_install" / "bundle_manifest.json"


def load_bundle_manifest(path: Path | None = None) -> BundleManifest:
    """Load and parse the pinned bundle manifest.

    Raises:
        BundleManifestMalformed: file is missing, not JSON, missing required
            fields, has an unknown schema version, or contains an entry with
            a non-HTTPS URL.
    """
    candidate = path if path is not None else default_manifest_path()
    if not candidate.exists():
        raise BundleManifestMalformed(
            f"pinned bundle manifest not found at {candidate}",
            details={"path": str(candidate)},
        )
    try:
        raw = candidate.read_text(encoding="utf-8")
    except OSError as exc:
        raise BundleManifestMalformed(
            f"could not read pinned bundle manifest at {candidate}: {exc}",
            details={"path": str(candidate)},
        ) from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise BundleManifestMalformed(
            f"pinned bundle manifest at {candidate} is not valid JSON: {exc}",
            details={"path": str(candidate)},
        ) from exc
    if not isinstance(data, dict):
        raise BundleManifestMalformed(
            f"pinned bundle manifest at {candidate} root is not an object",
            details={"path": str(candidate), "observed_type": type(data).__name__},
        )

    def _require_str(key: str) -> str:
        v = data.get(key)
        if not isinstance(v, str) or not v:
            raise BundleManifestMalformed(
                f"pinned bundle manifest at {candidate} missing required string field '{key}'",
                details={"path": str(candidate), "field": key},
            )
        return v

    schema_version = _require_str("schema_version")
    if schema_version != MANIFEST_SCHEMA_VERSION:
        raise BundleManifestMalformed(
            f"pinned bundle manifest schema_version is {schema_version!r}; "
            f"expected {MANIFEST_SCHEMA_VERSION!r}",
            details={
                "path": str(candidate),
                "observed": schema_version,
                "expected": MANIFEST_SCHEMA_VERSION,
            },
        )
    sidecar_version = _require_str("sidecar_version")
    trust_root = _require_str("trust_root")
    expected_oidc_issuer = _require_str("expected_oidc_issuer")
    expected_identity = _require_str("expected_identity")
    manifest_url = _require_str("manifest_url")
    if not manifest_url.startswith("https://"):
        raise BundleManifestMalformed(
            f"pinned bundle manifest manifest_url must be HTTPS; got {manifest_url!r}",
            details={"path": str(candidate), "manifest_url": manifest_url},
        )
    bundles_raw = data.get("bundles")
    if not isinstance(bundles_raw, list) or not bundles_raw:
        raise BundleManifestMalformed(
            f"pinned bundle manifest at {candidate} 'bundles' must be a non-empty list",
            details={"path": str(candidate)},
        )
    bundles: list[BundleEntry] = []
    for idx, entry in enumerate(bundles_raw):
        if not isinstance(entry, dict):
            raise BundleManifestMalformed(
                f"pinned bundle manifest entry {idx} is not an object",
                details={"path": str(candidate), "index": idx},
            )
        e_os = entry.get("os")
        e_arch = entry.get("arch")
        e_url = entry.get("url")
        e_digest = entry.get("expected_digest")
        e_size = entry.get("size_bytes")
        e_sig = entry.get("sigstore_url")
        if e_os not in ("darwin", "linux", "win32"):
            raise BundleManifestMalformed(
                f"pinned bundle manifest entry {idx} has invalid 'os' {e_os!r}",
                details={"path": str(candidate), "index": idx, "os": e_os},
            )
        if e_arch not in ("x64", "arm64"):
            raise BundleManifestMalformed(
                f"pinned bundle manifest entry {idx} has invalid 'arch' {e_arch!r}",
                details={"path": str(candidate), "index": idx, "arch": e_arch},
            )
        if not isinstance(e_url, str) or not e_url.startswith("https://"):
            raise BundleManifestMalformed(
                f"pinned bundle manifest entry {idx} 'url' must be HTTPS; got {e_url!r}",
                details={"path": str(candidate), "index": idx, "url": e_url},
            )
        if not isinstance(e_digest, str) or len(e_digest) != 64 or any(
            c not in "0123456789abcdef" for c in e_digest
        ):
            raise BundleManifestMalformed(
                f"pinned bundle manifest entry {idx} 'expected_digest' "
                f"must be 64 lowercase hex; got {e_digest!r}",
                details={"path": str(candidate), "index": idx, "expected_digest": e_digest},
            )
        if not isinstance(e_size, int) or e_size <= 0:
            raise BundleManifestMalformed(
                f"pinned bundle manifest entry {idx} 'size_bytes' "
                f"must be a positive integer; got {e_size!r}",
                details={"path": str(candidate), "index": idx, "size_bytes": e_size},
            )
        if not isinstance(e_sig, str) or not e_sig.startswith("https://"):
            raise BundleManifestMalformed(
                f"pinned bundle manifest entry {idx} 'sigstore_url' must be HTTPS; got {e_sig!r}",
                details={"path": str(candidate), "index": idx, "sigstore_url": e_sig},
            )
        bundles.append(
            BundleEntry(
                os=e_os,
                arch=e_arch,
                url=e_url,
                expected_digest=e_digest,
                size_bytes=e_size,
                sigstore_url=e_sig,
            )
        )
    return BundleManifest(
        schema_version=schema_version,
        sidecar_version=sidecar_version,
        trust_root=trust_root,
        expected_oidc_issuer=expected_oidc_issuer,
        expected_identity=expected_identity,
        manifest_url=manifest_url,
        bundles=tuple(bundles),
    )


# -----------------------------------------------------------------------------
# Host detection
# -----------------------------------------------------------------------------


def detect_host_os() -> str:
    """Return one of 'darwin', 'linux', 'win32'."""
    if sys.platform.startswith("darwin"):
        return "darwin"
    if sys.platform.startswith("linux"):
        return "linux"
    if sys.platform.startswith("win"):
        return "win32"
    return sys.platform


def detect_host_arch() -> str:
    """Return one of 'x64', 'arm64' or the raw machine string for refusal."""
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64", "x64"):
        return "x64"
    if machine in ("arm64", "aarch64"):
        return "arm64"
    return machine


# -----------------------------------------------------------------------------
# Network fetchers (with test seams)
# -----------------------------------------------------------------------------


def default_fetch_bytes(url: str, *, timeout: float = DEFAULT_HTTP_TIMEOUT_S) -> bytes:
    """Fetch ``url`` over HTTPS and return the response body as bytes.

    Refuses non-HTTPS URLs (defense-in-depth: the manifest validator
    already enforces this; refusing here too keeps the contract local).
    """
    if not url.startswith("https://"):
        raise BundleUnavailable(
            f"bundle URL must be HTTPS; got {url!r}",
            details={"url": url, "reason": "non_https"},
        )
    try:
        with httpx.Client(timeout=httpx.Timeout(timeout)) as client:
            resp = client.get(url, follow_redirects=False)
    except httpx.HTTPError as exc:
        raise BundleUnavailable(
            f"network error fetching {url}: {exc}",
            details={"url": url, "reason": "network_error", "cause": str(exc)},
        ) from exc
    if resp.status_code != 200:
        raise BundleUnavailable(
            f"bundle fetch returned HTTP {resp.status_code} from {url}",
            details={"url": url, "reason": "non_200", "http_status": resp.status_code},
        )
    return bytes(resp.content)


def default_fetch_text(url: str, *, timeout: float = DEFAULT_HTTP_TIMEOUT_S) -> str:
    """Fetch ``url`` over HTTPS and return the response body as UTF-8 text."""
    return default_fetch_bytes(url, timeout=timeout).decode("utf-8")


# -----------------------------------------------------------------------------
# Verifiers
# -----------------------------------------------------------------------------


def verify_digest(payload: bytes, expected_sha256: str, *, url: str | None = None) -> str:
    """Compute the SHA-256 of ``payload`` and assert it matches.

    Raises :class:`BundleDigestMismatch` on mismatch. Returns the observed
    hex digest on success so the caller can record it in evidence.
    """
    observed = hashlib.sha256(payload).hexdigest()
    if observed != expected_sha256:
        details: dict[str, Any] = {
            "observed": observed,
            "expected": expected_sha256,
            "reason": "digest_mismatch",
        }
        if url is not None:
            details["url"] = url
        raise BundleDigestMismatch(
            f"bundle SHA-256 digest mismatch: observed {observed} expected {expected_sha256}",
            details=details,
        )
    return observed


def _translate_sigstore_error(exc: Exception) -> BundleSignatureInvalid:
    """Translate a ``sigstore.errors.*`` subclass into ``BundleSignatureInvalid``.

    Per VAL-V2M09-010, every sigstore exception subclass MUST translate
    to ``BundleSignatureInvalid`` with a distinct ``details["reason"]``
    so auditors can distinguish identity / cert-chain / transparency-log
    / signature failures. The wire code is the existing
    ``RELAY-CLI-SIDECAR-SIGNATURE-INVALID`` so the error envelope shape
    is preserved across the fail-closed -> real-crypto transition.

    The translation table is deliberately defined by ``isinstance``
    checks against the live sigstore module rather than by string
    matching on exception names; this keeps us resilient to sigstore
    surface changes between minor versions.
    """
    # Late-imported to avoid hard-failing module import when sigstore
    # is missing (e.g. during ``uv build`` without the optional
    # extra). At runtime, by the time ``_translate_sigstore_error`` is
    # called the caller has already imported sigstore.
    try:
        from sigstore import errors as ss_errors
    except Exception:  # pragma: no cover - defensive
        ss_errors = None  # type: ignore[assignment]

    msg = str(exc) or exc.__class__.__name__
    # Resolve a reason token. Order matters: more-specific subclasses
    # MUST be matched before their bases.
    reason = "verification_failed"
    if ss_errors is not None:
        # Cert chain validation failure (e.g. SAN identity mismatch,
        # untrusted Fulcio root, expired cert).
        cert_err = getattr(ss_errors, "CertValidationError", None)
        if cert_err is not None and isinstance(exc, cert_err):
            # Distinguish identity-mismatch from other cert-validation
            # failures by inspecting the message: sigstore's
            # CertValidationError carries the identity/SAN mismatch
            # diagnostic in its message.
            lower = msg.lower()
            if "subject" in lower or "san" in lower or "identity" in lower:
                reason = "identity_mismatch"
            else:
                reason = "cert_validation_failed"
        else:
            # TUF / trust-root metadata failure.
            root_err = getattr(ss_errors, "RootError", None)
            if root_err is not None and isinstance(exc, root_err):
                reason = "trust_root_invalid"
            else:
                metadata_err = getattr(ss_errors, "MetadataError", None)
                if metadata_err is not None and isinstance(exc, metadata_err):
                    reason = "trust_metadata_invalid"
                else:
                    tuf_err = getattr(ss_errors, "TUFError", None)
                    if tuf_err is not None and isinstance(exc, tuf_err):
                        reason = "tuf_metadata_invalid"
                    else:
                        net_err = getattr(ss_errors, "NetworkError", None)
                        if net_err is not None and isinstance(exc, net_err):
                            reason = "trust_root_unreachable"
                        else:
                            verif_err = getattr(
                                ss_errors, "VerificationError", None
                            )
                            if verif_err is not None and isinstance(
                                exc, verif_err
                            ):
                                lower = msg.lower()
                                if "signature" in lower:
                                    reason = "signature_invalid"
                                elif (
                                    "transparency" in lower
                                    or "rekor" in lower
                                    or "inclusion" in lower
                                ):
                                    reason = "transparency_log_invalid"
                                elif "identity" in lower or "san" in lower:
                                    reason = "identity_mismatch"
                                else:
                                    reason = "verification_failed"
    return BundleSignatureInvalid(
        f"Sigstore verification failed: {msg}",
        details={
            "reason": reason,
            "exception_type": exc.__class__.__name__,
            "message": msg,
        },
    )


def verify_sigstore(
    sigstore_bytes: bytes | str,
    *,
    expected_trust_root: str,
    expected_oidc_issuer: str,
    expected_identity: str,
    artifact_bytes: bytes | None = None,
    offline: bool = False,
) -> dict[str, Any]:
    """Cryptographically verify a Sigstore bundle (M09 / VAL-V2M09-006).

    Invokes ``sigstore.verify.Verifier.verify_artifact`` (via the
    upstream ``sigstore-python`` package, pinned ``>=3.6.0`` in
    ``packages/cli/pyproject.toml``) against the parsed
    ``sigstore.models.Bundle``. On success the Fulcio code-signing
    certificate chain has been validated against the trust root, the
    Rekor transparency-log inclusion proof has been verified against
    Rekor's bundled public key, the message signature has been verified
    against the artifact bytes using the public key in the Fulcio cert,
    AND the certificate's SAN extension matches ``expected_identity``
    minted from ``expected_oidc_issuer``.

    Args:
        sigstore_bytes: Raw bytes or text of the Sigstore bundle JSON
            (the cosign-bundle / Sigstore Bundle v0.x wire format).
        expected_trust_root: Trust-root identifier the bundle MUST bind
            to. The OSS default is ``relay.epochly.com``; per CLAUDE.md
            banned pattern #13 changing the default is a board-level
            decision. Today this identifier selects which
            ``sigstore.verify.Verifier`` factory is invoked
            (``production`` for the Sigstore public-good root,
            ``staging`` for the Sigstore staging instance). Unknown
            identifiers fall back to the production root with a
            ``trust_anchor`` field of the requested value so callers
            can carry it through to evidence binding.
        expected_oidc_issuer: OIDC issuer claim the signing
            certificate MUST have been minted from (e.g.
            ``https://token.actions.githubusercontent.com``).
        expected_identity: SAN-extension identity the certificate MUST
            attest to (e.g. the GitHub Actions workflow URL).
        artifact_bytes: The artifact whose signature is being verified.
            REQUIRED for real verification because Sigstore signatures
            bind to the artifact digest; an absent value yields a
            structured ``artifact_bytes_required`` failure rather than
            a misleading pass.

    Returns:
        A dict carrying the verification metadata: ``trust_anchor``,
        ``oidc_issuer``, ``identity``, ``log_index`` (when available),
        and ``cert_subject_alt_name``. Downstream call sites record
        this in evidence per CLAUDE.md keystone invariant #2.

    Raises:
        BundleSignatureInvalid: on any verification failure. The
            ``details["reason"]`` is one of: ``artifact_bytes_required``,
            ``bundle_parse_failed``, ``identity_mismatch``,
            ``cert_validation_failed``, ``signature_invalid``,
            ``transparency_log_invalid``, ``trust_root_invalid``,
            ``trust_metadata_invalid``, ``trust_root_unreachable``,
            ``verification_failed``.
    """
    if not VERIFIER_SIGSTORE_CRYPTO_IMPLEMENTED:  # pragma: no cover
        # Defensive guard: if someone flips the flag back to False
        # without removing this call, fail-close with the historical
        # reason so the test suite catches the regression.
        raise BundleSignatureInvalid(
            "Sigstore cryptographic verification flag is False; refusing "
            "to make a verification claim.",
            details={
                "reason": "sigstore_crypto_not_implemented",
                "implemented": False,
                "fail_closed": True,
            },
        )

    if artifact_bytes is None:
        raise BundleSignatureInvalid(
            "verify_sigstore requires artifact_bytes to verify the message "
            "signature against the artifact digest; cosign-bundle signatures "
            "bind to the artifact and cannot be verified without it.",
            details={
                "reason": "artifact_bytes_required",
                "expected_trust_root": expected_trust_root,
            },
        )

    # Parse the Sigstore bundle. This is the structural decode step;
    # the cryptographic verification happens in verify_artifact below.
    try:
        from sigstore.models import Bundle  # type: ignore[import-not-found]
    except Exception as exc:  # pragma: no cover - import failure
        raise BundleSignatureInvalid(
            f"sigstore package is not importable: {exc}",
            details={"reason": "sigstore_unavailable", "cause": str(exc)},
        ) from exc

    if isinstance(sigstore_bytes, bytes):
        try:
            bundle_text = sigstore_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise BundleSignatureInvalid(
                f"sigstore bundle is not valid UTF-8: {exc}",
                details={"reason": "bundle_parse_failed", "cause": str(exc)},
            ) from exc
    else:
        bundle_text = sigstore_bytes

    try:
        bundle = Bundle.from_json(bundle_text)
    except Exception as exc:
        raise BundleSignatureInvalid(
            f"sigstore bundle parse failed: {exc}",
            details={"reason": "bundle_parse_failed", "cause": str(exc)},
        ) from exc

    # Build the identity policy. The two-arg form (identity + issuer)
    # is the standard keyless-cosign verification policy.
    try:
        from sigstore.verify import Verifier  # type: ignore[import-not-found]
        from sigstore.verify.policy import Identity  # type: ignore[import-not-found]
    except Exception as exc:  # pragma: no cover - import failure
        raise BundleSignatureInvalid(
            f"sigstore.verify import failed: {exc}",
            details={"reason": "sigstore_unavailable", "cause": str(exc)},
        ) from exc

    policy = Identity(identity=expected_identity, issuer=expected_oidc_issuer)

    # Select the trust root. relay.epochly.com is the OSS default and
    # is operated by the Relay project (per CLAUDE.md banned pattern
    # #13); it does NOT (today) operate an independent Fulcio/Rekor
    # so verification is delegated to the Sigstore public-good roots.
    # The explicit string ``staging`` selects the Sigstore staging
    # endpoint, useful for CI without burning production-log entries.
    trust_root_label = expected_trust_root or DEFAULT_TRUST_ROOT
    # offline=True builds the Verifier from the TUF cache populated at
    # sigstore-python install time -- NO network. Under --offline this is
    # load-bearing: Verifier.production() (offline=False) refreshes the trust
    # root over the network, which would break the offline default-deny
    # promise ("offline mode is a structural promise, not a fallback").
    try:
        verifier = (
            Verifier.staging(offline=offline)
            if trust_root_label == "staging"
            else Verifier.production(offline=offline)
        )
    except Exception as exc:
        # Could not bootstrap trust root (e.g. TUF / network failure).
        # Translate so callers see the structured reason.
        raise _translate_sigstore_error(exc) from exc

    # Cryptographic verification. ``verify_artifact`` raises on failure
    # (sigstore.errors.VerificationError subclass) and returns None on
    # success.
    try:
        from sigstore import errors as ss_errors  # type: ignore[import-not-found]
    except Exception as exc:  # pragma: no cover - import failure
        raise BundleSignatureInvalid(
            f"sigstore.errors import failed: {exc}",
            details={"reason": "sigstore_unavailable", "cause": str(exc)},
        ) from exc

    try:
        verifier.verify_artifact(artifact_bytes, bundle, policy)
    except ss_errors.Error as exc:
        raise _translate_sigstore_error(exc) from exc
    except Exception as exc:
        # Unexpected non-sigstore exception. Wrap with a structured
        # reason rather than letting the call site see a raw error.
        raise BundleSignatureInvalid(
            f"unexpected sigstore verification error: {exc}",
            details={
                "reason": "verification_failed",
                "exception_type": exc.__class__.__name__,
                "cause": str(exc),
            },
        ) from exc

    # Success: extract structured metadata for evidence binding
    # (CLAUDE.md keystone invariant #2 + VAL-V2M09-022).
    log_index: int | None = None
    try:
        log_entry = bundle.log_entry
        log_index = int(getattr(log_entry, "log_index", 0)) or None
    except Exception:
        log_index = None

    return {
        "trust_anchor": trust_root_label,
        "oidc_issuer": expected_oidc_issuer,
        "identity": expected_identity,
        "log_index": log_index,
        "verified": True,
    }


# -----------------------------------------------------------------------------
# End-to-end install pipeline
# -----------------------------------------------------------------------------


@dataclass(frozen=True)
class InstallResult:
    """Result of a successful ``rly sidecar install`` invocation."""

    sidecar_version: str
    install_path: Path
    bundle_url: str
    bundle_digest: str
    host_os: str
    host_arch: str
    trust_root: str
    bytes_written: int


def install_bundle(
    *,
    home: Path | None = None,
    manifest_path: Path | None = None,
    host_os: str | None = None,
    host_arch: str | None = None,
    fetch_bytes: Any = None,
    fetch_text: Any = None,
    forbidden_url: str | None = None,
) -> InstallResult:
    """Run the full install pipeline.

    Args:
        home: Override ``RELAY_HOME``. Defaults to :func:`relay_home`.
        manifest_path: Override the pinned manifest path (test seam).
        host_os, host_arch: Override host detection (test seam).
        fetch_bytes: Override the bundle fetcher (test seam).
        fetch_text: Override the sigstore-bundle fetcher (test seam).
        forbidden_url: When non-None this signals the user passed a
            ``--url`` flag; the pipeline refuses with VAL-W5-015's
            ``RELAY-CLI-USAGE-014``.

    Returns:
        InstallResult with the install path and bundle binding evidence.

    Raises:
        BundleUsageError: VAL-W5-015 user passed a forbidden flag.
        BundleManifestMalformed: pinned manifest is unusable.
        BundleArchUnsupported: host (os, arch) not in matrix.
        BundleUnavailable: network failure or non-200 HTTP.
        BundleDigestMismatch: VAL-W5-017 SHA-256 mismatch.
        BundleSignatureInvalid: VAL-W5-016 Sigstore failure.
    """
    if forbidden_url is not None:
        raise BundleUsageError(
            "rly sidecar install does not accept a --url flag; the bundle URL "
            "is pinned in packages/cli/src/sidecar_install/bundle_manifest.json",
            details={"forbidden_url": forbidden_url, "reason": "url_flag_forbidden"},
        )

    base_home = home if home is not None else relay_home()
    bin_dir = base_home / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)

    manifest = load_bundle_manifest(manifest_path)
    h_os = host_os if host_os is not None else detect_host_os()
    h_arch = host_arch if host_arch is not None else detect_host_arch()
    if (h_os, h_arch) not in SUPPORTED_OS_ARCH:
        raise BundleArchUnsupported(
            f"host ({h_os}, {h_arch}) is not in the v0.1 supported sidecar matrix",
            details={
                "host_os": h_os,
                "host_arch": h_arch,
                "supported": list(SUPPORTED_OS_ARCH),
            },
        )

    entry = manifest.find(h_os, h_arch)

    fetcher_bytes = fetch_bytes if fetch_bytes is not None else default_fetch_bytes
    fetcher_text = fetch_text if fetch_text is not None else default_fetch_text

    # Step 1: download bundle bytes.
    bundle_bytes = fetcher_bytes(entry.url)
    # Step 2: digest verify (VAL-W5-017) BEFORE signature.
    try:
        observed_digest = verify_digest(
            bundle_bytes, entry.expected_digest, url=entry.url
        )
    except BundleDigestMismatch:
        # VAL-W5-017: delete the downloaded artifact on mismatch.
        # Bytes are in memory; nothing on disk to delete -- the assertion
        # is satisfied by NEVER having moved the bytes to install_path.
        raise

    # Step 3: download cosign-bundle JSON.
    sigstore_text = fetcher_text(entry.sigstore_url)
    # Step 4: signature verify (VAL-W5-016) BEFORE moving to install path.
    # M09 / VAL-V2M09-006: pass the artifact bytes so the cryptographic
    # signature can be verified against them (the bundle's signature
    # binds to the artifact digest, not just the bundle itself).
    try:
        verify_sigstore(
            sigstore_text,
            expected_trust_root=manifest.trust_root,
            expected_oidc_issuer=manifest.expected_oidc_issuer,
            expected_identity=manifest.expected_identity,
            artifact_bytes=bundle_bytes,
        )
    except BundleSignatureInvalid:
        # VAL-W5-016: bundle MUST NOT be moved into its install path until
        # verification succeeds. Since we have not yet written anywhere
        # this is satisfied; surface the failure verbatim.
        raise

    # Step 5: atomic install (VAL-W5-018). MUST go through the four-atomic
    # primitive; direct ``open(install_path, 'wb')`` is banned.
    install_path = bin_dir / f"relay-sidecar-{manifest.sidecar_version}"
    local_atomic_file_write(install_path, bundle_bytes, mode=0o700)
    return InstallResult(
        sidecar_version=manifest.sidecar_version,
        install_path=install_path,
        bundle_url=entry.url,
        bundle_digest=observed_digest,
        host_os=h_os,
        host_arch=h_arch,
        trust_root=manifest.trust_root,
        bytes_written=len(bundle_bytes),
    )


__all__ = [
    "BundleArchUnsupported",
    "BundleDigestMismatch",
    "BundleEntry",
    "BundleInstallError",
    "BundleManifest",
    "BundleManifestMalformed",
    "BundleSignatureInvalid",
    "BundleUnavailable",
    "BundleUsageError",
    "DEFAULT_HTTP_TIMEOUT_S",
    "DEFAULT_TRUST_ROOT",
    "ENV_BUNDLE_MANIFEST_PATH",
    "InstallResult",
    "MANIFEST_SCHEMA_VERSION",
    "RELAY_CLI_SIDECAR_ARCH_UNSUPPORTED",
    "RELAY_CLI_SIDECAR_BUNDLE_UNAVAILABLE",
    "RELAY_CLI_SIDECAR_DIGEST_MISMATCH",
    "RELAY_CLI_SIDECAR_MANIFEST_MALFORMED",
    "RELAY_CLI_SIDECAR_SIGNATURE_INVALID",
    "RELAY_CLI_USAGE_014",
    "SUPPORTED_OS_ARCH",
    "default_fetch_bytes",
    "default_fetch_text",
    "default_manifest_path",
    "detect_host_arch",
    "detect_host_os",
    "install_bundle",
    "load_bundle_manifest",
    "verify_digest",
    "verify_sigstore",
]


# Suppress unused-import for contextlib (kept for future error-cleanup hooks).
_ = contextlib
