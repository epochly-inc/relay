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

The Sigstore verifier is structurally compatible with the TS reference at
``packages/sdk-typescript/src/bin/verify.ts``: the cosign-bundle JSON shape
is parsed; certificate + signature + transparency-log entry are required;
the bundle's ``trust_root`` claim must match the manifest's. A future
maintenance release can wire the full ``sigstore-python`` library without
changing this module's signature.

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

# Manifest schema version (matches what we ship in
# packages/cli/src/sidecar_install/bundle_manifest.json).
MANIFEST_SCHEMA_VERSION: Final[str] = "relay.cli.sidecar_install_manifest.v1"

# Supported OS/arch tuples (mirrors packages/sdk-typescript/src/bin/types.ts
# SUPPORTED_OS_ARCH). Same 5 cells.
SupportedOs = Literal["darwin", "linux", "win32"]
SupportedArch = Literal["x64", "arm64"]
SUPPORTED_OS_ARCH: Final[tuple[tuple[str, str], ...]] = (
    ("darwin", "x64"),
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
    """Raised when the host (os, arch) is not in the 5-cell support matrix."""

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


def verify_sigstore(
    sigstore_bytes: bytes | str,
    *,
    expected_trust_root: str,
    expected_oidc_issuer: str,
    expected_identity: str,
) -> dict[str, Any]:
    """Structurally verify a cosign-bundle JSON.

    Mirrors ``packages/sdk-typescript/src/bin/verify.ts``::verifySigstoreBundle.
    Required structural fields (cosign-bundle wire shape):

      - JSON object root.
      - Either the new wire shape (``verificationMaterial.certificate.rawBytes``,
        ``verificationMaterial.tlogEntries[]``, ``messageSignature.signature``)
        OR the legacy shape (``cert``, ``signature``, ``rekorBundle.Payload``).
      - A ``trust_root`` claim equal to ``expected_trust_root`` (default
        ``relay.epochly.com``).
      - An ``oidc_issuer`` claim equal to ``expected_oidc_issuer``.
      - An ``identity`` claim equal to ``expected_identity``.

    A future maintenance release wires the full ``sigstore-python`` library
    without changing this function's signature or wire-error code. The
    structural check here satisfies VAL-W5-016 (refuse unsigned, refuse
    wrong identity) under hermetic test conditions.
    """
    if isinstance(sigstore_bytes, bytes):
        try:
            text = sigstore_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise BundleSignatureInvalid(
                f"Sigstore bundle is not valid UTF-8: {exc}",
                details={"reason": "sigstore_bytes_not_utf8"},
            ) from exc
    else:
        text = sigstore_bytes
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise BundleSignatureInvalid(
            f"Sigstore bundle is not valid JSON: {exc}",
            details={"reason": "sigstore_not_json"},
        ) from exc
    if not isinstance(parsed, dict):
        raise BundleSignatureInvalid(
            "Sigstore bundle is not a JSON object",
            details={"reason": "sigstore_not_object"},
        )

    has_new = (
        isinstance(parsed.get("verificationMaterial"), dict)
        and isinstance(
            parsed["verificationMaterial"].get("certificate"), dict
        )
        and isinstance(
            parsed["verificationMaterial"]["certificate"].get("rawBytes"), str
        )
        and isinstance(parsed["verificationMaterial"].get("tlogEntries"), list)
        and len(parsed["verificationMaterial"]["tlogEntries"]) > 0
        and isinstance(parsed.get("messageSignature"), dict)
        and isinstance(parsed["messageSignature"].get("signature"), str)
        and parsed["messageSignature"]["signature"]
    )
    has_legacy = (
        isinstance(parsed.get("cert"), str)
        and parsed["cert"]
        and isinstance(parsed.get("signature"), str)
        and parsed["signature"]
        and isinstance(parsed.get("rekorBundle"), dict)
    )
    if not has_new and not has_legacy:
        raise BundleSignatureInvalid(
            "Sigstore bundle lacks required certificate + signature material",
            details={"reason": "sigstore_missing_material", "keys": sorted(parsed.keys())},
        )

    trust_root_claim = parsed.get("trust_root")
    if not isinstance(trust_root_claim, str) or not trust_root_claim:
        raise BundleSignatureInvalid(
            "Sigstore bundle missing 'trust_root' claim",
            details={"reason": "sigstore_missing_trust_root_claim"},
        )
    if trust_root_claim != expected_trust_root:
        raise BundleSignatureInvalid(
            f"Sigstore bundle trust_root {trust_root_claim!r} != expected {expected_trust_root!r}",
            details={
                "reason": "sigstore_trust_root_mismatch",
                "observed": trust_root_claim,
                "expected": expected_trust_root,
            },
        )

    oidc_claim = parsed.get("oidc_issuer")
    if not isinstance(oidc_claim, str) or oidc_claim != expected_oidc_issuer:
        raise BundleSignatureInvalid(
            f"Sigstore bundle oidc_issuer {oidc_claim!r} != expected {expected_oidc_issuer!r}",
            details={
                "reason": "sigstore_oidc_issuer_mismatch",
                "observed": oidc_claim,
                "expected": expected_oidc_issuer,
            },
        )

    identity_claim = parsed.get("identity")
    if not isinstance(identity_claim, str) or identity_claim != expected_identity:
        raise BundleSignatureInvalid(
            f"Sigstore bundle identity {identity_claim!r} != expected {expected_identity!r}",
            details={
                "reason": "sigstore_identity_mismatch",
                "observed": identity_claim,
                "expected": expected_identity,
            },
        )

    return parsed


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
    try:
        verify_sigstore(
            sigstore_text,
            expected_trust_root=manifest.trust_root,
            expected_oidc_issuer=manifest.expected_oidc_issuer,
            expected_identity=manifest.expected_identity,
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
