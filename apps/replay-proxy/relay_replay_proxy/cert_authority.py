"""Per-session CA cert + key generation for the W7.1 replay harness.

VAL-W7-003: each ``rly replay run`` invocation MUST generate a fresh
per-session CA cert (RSA-2048 or ECDSA-P256) under
``~/.relay/cassettes/<session>/ca.pem``. Distinct subject keys, distinct
serial numbers, distinct file digests across sessions.

VAL-W7-004: the CA cert and any derived keying material MUST be removed
on graceful session exit.

VAL-W7-005: the CA cert MUST NEVER be written outside
``~/.relay/cassettes/<session>/``. The harness MUST NOT install the CA
into the OS trust store; injection is via ``SSL_CERT_FILE`` only.

This module owns generation + on-disk layout. The harness module owns
the cleanup lifecycle (atexit + signal handlers).

Per CLAUDE.md keystone invariant #8 (atomic persistence) the cert and
key files are written through ``local_atomic_file_write`` so a partial
write (process kill mid-flush) cannot leave a half-written PEM that the
proxy might silently accept.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Final

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from relay_sidecar.primitives import local_atomic_file_write

# Subject CN MUST contain the substring asserted by VAL-W7-005 so the
# repo grep + filesystem-audit test can identify a Relay-issued CA in any
# stray PEM under /tmp or system trust stores. Do NOT change this string
# without updating the audit test.
SUBJECT_CN_PREFIX: Final[str] = "Relay Replay Session"

# File names (per VAL-W7-003 the cert lives at <session_dir>/ca.pem).
CA_CERT_FILENAME: Final[str] = "ca.pem"
CA_KEY_FILENAME: Final[str] = "ca-key.pem"

# Default validity window: short by design. v0.1 sessions complete in
# minutes; a 24h window is comfortable headroom without producing a
# long-lived cert that could be accidentally trusted.
DEFAULT_VALIDITY_HOURS: Final[int] = 24

# POSIX file mode for the private key. 0o600 = owner read/write only.
# On Windows local_atomic_file_write applies an equivalent ACL via
# pywin32 (see apps/local-sidecar/relay_sidecar/primitives/
# local_atomic_file_write.py::_apply_windows_acl).
KEY_FILE_MODE: Final[int] = 0o600
CERT_FILE_MODE: Final[int] = 0o644


@dataclass(frozen=True)
class GeneratedCA:
    """Materialized CA: paths + identifying fields.

    The harness records ``serial_number`` and ``subject_key_id`` so a
    session's CA can be cross-referenced against the cassette session
    manifest. The fields are also what VAL-W7-003 asserts differ across
    sessions (distinct serials, distinct subject keys).
    """

    cert_path: Path
    key_path: Path
    serial_number: int
    subject_key_id_hex: str
    subject_cn: str
    not_before: datetime
    not_after: datetime


def _validate_session_dir(session_dir: Path) -> None:
    """Reject session_dir paths that would write outside cassettes/<id>/.

    Per VAL-W7-005 the CA MUST NEVER land outside the per-session dir.
    The harness validates this before calling ``generate_ca`` (it
    constructs session_dir as ``relay_home / "cassettes" / session_id``)
    but we re-check here because the public function is callable
    directly from tests.
    """
    if not session_dir.is_absolute():
        raise ValueError(
            f"session_dir must be absolute; got {session_dir!s}"
        )
    # Resolve symlinks so a session_dir of "<cassettes>/<id>/../../../tmp"
    # is rejected at construction time. We accept the rare race where a
    # symlink is swapped after this check; the harness's atexit cleanup
    # walks the actual session_dir path it was given.
    resolved = session_dir.resolve(strict=False)
    parts = resolved.parts
    if "cassettes" not in parts:
        raise ValueError(
            f"session_dir must contain a 'cassettes' path component; "
            f"got {resolved!s}"
        )


def generate_ca(
    *,
    session_id: str,
    session_dir: Path,
    validity_hours: int = DEFAULT_VALIDITY_HOURS,
    not_before: datetime | None = None,
) -> GeneratedCA:
    """Generate and persist a fresh per-session CA cert + private key.

    Returns the materialized :class:`GeneratedCA`. The cert is written to
    ``session_dir / "ca.pem"`` (mode 0o644) and the key to
    ``session_dir / "ca-key.pem"`` (mode 0o600). Both go through the
    ``local_atomic_file_write`` primitive (write-tmp + fsync + rename).

    Uses ECDSA-P256 (per VAL-W7-003 either RSA-2048 or ECDSA-P256 is
    acceptable; we pick P256 for speed and smaller PEM size).

    The serial number is a fresh 159-bit random integer (RFC 5280
    recommends >= 64 bits of entropy; we use 159 to match the
    ``x509.random_serial_number`` upper bound). The subject key
    identifier is computed from the public key bytes per RFC 5280 4.2.1.2.
    """
    _validate_session_dir(session_dir)
    session_dir.mkdir(parents=True, exist_ok=True)

    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    # Subject CN encodes the session_id so a stray CA in a system trust
    # store can be traced to the issuing run.
    subject_cn = f"{SUBJECT_CN_PREFIX} {session_id}"
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, subject_cn),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Epochly Relay"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "replay-proxy"),
        ]
    )
    serial = x509.random_serial_number()
    not_before_resolved = not_before or datetime.now(tz=UTC)
    not_after = not_before_resolved + timedelta(hours=validity_hours)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)  # self-signed (this IS the trust anchor for the session)
        .public_key(public_key)
        .serial_number(serial)
        .not_valid_before(not_before_resolved)
        .not_valid_after(not_after)
        # Mark as a CA so mitmproxy can issue per-host leaf certs from it.
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False,
        )
    )

    certificate = builder.sign(private_key=private_key, algorithm=hashes.SHA256())

    # Recover the SubjectKeyIdentifier extension we just added so we can
    # report it to the harness without re-deriving from the public key.
    ski_ext = certificate.extensions.get_extension_for_class(
        x509.SubjectKeyIdentifier
    )
    subject_key_id_hex = ski_ext.value.digest.hex()

    cert_pem = certificate.public_bytes(serialization.Encoding.PEM)
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    cert_path = session_dir / CA_CERT_FILENAME
    key_path = session_dir / CA_KEY_FILENAME
    local_atomic_file_write(cert_path, cert_pem, mode=CERT_FILE_MODE)
    local_atomic_file_write(key_path, key_pem, mode=KEY_FILE_MODE)

    return GeneratedCA(
        cert_path=cert_path,
        key_path=key_path,
        serial_number=serial,
        subject_key_id_hex=subject_key_id_hex,
        subject_cn=subject_cn,
        not_before=not_before_resolved,
        not_after=not_after,
    )


def remove_ca(ca: GeneratedCA) -> list[str]:
    """Best-effort delete of the per-session CA cert + key.

    Returns the list of paths actually removed. Missing files are not an
    error (idempotent cleanup); permission errors are swallowed and
    reported via the returned list (omitted paths). The caller (harness
    teardown / atexit) logs the result.

    Per VAL-W7-004 the deletion happens on graceful session exit; the
    harness's atexit and signal handlers both call this.
    """
    removed: list[str] = []
    for path in (ca.key_path, ca.cert_path):
        try:
            if path.exists():
                os.unlink(path)
                removed.append(str(path))
        except OSError:
            # Best-effort: a concurrent unlink or permission denial does
            # not abort cleanup. The atexit handler should not raise.
            continue
    return removed


__all__ = [
    "CA_CERT_FILENAME",
    "CA_KEY_FILENAME",
    "CERT_FILE_MODE",
    "DEFAULT_VALIDITY_HOURS",
    "GeneratedCA",
    "KEY_FILE_MODE",
    "SUBJECT_CN_PREFIX",
    "generate_ca",
    "remove_ca",
]
