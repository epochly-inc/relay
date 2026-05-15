"""W10.4 TSA cert chain shipping + no-private-key guard tests.

Covers:
  * VAL-W10-040 (no private-key material in verifier package)
  * VAL-W10-042 (TSA cert chain shipped at canonical path with required
                  properties)

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import datetime as _dt
import re
from pathlib import Path

import pytest
from relay_verifier import (
    MIN_RSA_BITS,
    TSA_CHAIN_DIRNAME,
    TSA_CHAIN_FILENAME,
    inspect_tsa_chain,
    load_bundled_tsa_chain,
    load_tsa_chain_pem_bytes,
)

VERIFIER_PKG_ROOT = (
    Path(__file__).resolve().parents[3] / "packages" / "verifier"
)

CANONICAL_CHAIN_PATH = (
    VERIFIER_PKG_ROOT / "trust" / "tsa-chain.pem"
)

PACKAGED_CHAIN_PATH = (
    VERIFIER_PKG_ROOT / "src" / "relay_verifier" / TSA_CHAIN_DIRNAME / TSA_CHAIN_FILENAME
)


# ---------------------------------------------------------------------------
# VAL-W10-040: no private-key material in verifier package
# ---------------------------------------------------------------------------


_PRIVATE_KEY_HEADER_TOKENS = (
    "BEGIN PRIVATE KEY",
    "BEGIN RSA PRIVATE KEY",
    "BEGIN EC PRIVATE KEY",
    "BEGIN DSA PRIVATE KEY",
    "BEGIN OPENSSH PRIVATE KEY",
    "BEGIN ED25519 PRIVATE KEY",
    "BEGIN ENCRYPTED PRIVATE KEY",
    "PRIVATE KEY-----",
)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-040")
def test_no_private_key_pem_tokens_in_verifier_package() -> None:
    """A repo grep over packages/verifier/ MUST return zero hits for
    private-key PEM headers across non-test source files."""
    excluded_suffixes = (".pyc", ".so", ".dylib")
    excluded_dirs = {"__pycache__", "tests", ".pytest_cache"}

    offending_files: list[tuple[Path, str]] = []
    for path in VERIFIER_PKG_ROOT.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix in excluded_suffixes:
            continue
        # Skip test trees -- VAL-W10-040 explicitly scopes to non-test
        # paths, since tests legitimately produce keypairs in-memory.
        if any(part in excluded_dirs for part in path.parts):
            continue
        try:
            raw = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for tok in _PRIVATE_KEY_HEADER_TOKENS:
            if tok in raw:
                # Allow the literal token to appear in this very test
                # file (it lists the tokens we're scanning for).
                if path == Path(__file__):
                    continue
                offending_files.append((path, tok))
    assert offending_files == [], (
        "VAL-W10-040 violation: private-key PEM headers found in "
        f"non-test files: {offending_files}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-040")
def test_no_private_key_file_extensions_in_verifier_package() -> None:
    """No `.p8`, `.p12`, `.pfx` files anywhere in the verifier package."""
    forbidden_suffixes = {".p8", ".p12", ".pfx", ".key"}
    offending: list[Path] = []
    for path in VERIFIER_PKG_ROOT.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() in forbidden_suffixes:
            offending.append(path)
    assert offending == [], (
        f"VAL-W10-040 violation: forbidden key files present: {offending}"
    )


# ---------------------------------------------------------------------------
# VAL-W10-042: TSA cert chain shipping
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-042")
def test_canonical_tsa_chain_path_exists_with_pem_content() -> None:
    """`packages/verifier/trust/tsa-chain.pem` MUST exist and contain
    at least one BEGIN CERTIFICATE block."""
    assert CANONICAL_CHAIN_PATH.is_file(), (
        f"VAL-W10-042: canonical path {CANONICAL_CHAIN_PATH} missing"
    )
    raw = CANONICAL_CHAIN_PATH.read_text(encoding="utf-8")
    cert_count = len(re.findall(r"-----BEGIN CERTIFICATE-----", raw))
    assert cert_count >= 1, (
        f"chain at {CANONICAL_CHAIN_PATH} contains 0 certificates"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-042")
def test_packaged_tsa_chain_path_exists_and_mirrors_canonical() -> None:
    """The wheel-bundled chain at relay_verifier/tsa_chain/tsa-chain.pem
    MUST exist and contain byte-equal certificate content with the
    canonical path."""
    assert PACKAGED_CHAIN_PATH.is_file(), (
        f"VAL-W10-042: packaged path {PACKAGED_CHAIN_PATH} missing"
    )
    canonical_certs = re.findall(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
        CANONICAL_CHAIN_PATH.read_text(encoding="utf-8"),
        re.DOTALL,
    )
    packaged_certs = re.findall(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
        PACKAGED_CHAIN_PATH.read_text(encoding="utf-8"),
        re.DOTALL,
    )
    assert canonical_certs == packaged_certs, (
        "canonical and packaged chain certificate blocks differ"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-042")
def test_tsa_chain_inspect_reports_chain_ok_for_shipped_chain() -> None:
    """The shipped chain MUST: parse as PEM, contain >= 1 cert, every
    notAfter in future, every key meets minimum strength, and link as
    a chain (root self-signed)."""
    path, raw = load_bundled_tsa_chain()
    check = inspect_tsa_chain(raw, chain_path=str(path))
    assert check.chain_ok, (
        f"VAL-W10-042 chain check failed: {check.reason}"
    )
    assert check.cert_count >= 1
    # Every cert's notAfter in the future.
    now = _dt.datetime.now(tz=_dt.UTC)
    for summary in check.certs:
        not_after = _dt.datetime.fromisoformat(
            summary.not_after[:-1] + "+00:00"
        )
        assert not_after > now, (
            f"cert {summary.subject!r} not_after {summary.not_after} "
            f"is not in the future"
        )
    # Every key meets minimum strength.
    for summary in check.certs:
        if summary.key_alg == "RSA":
            assert summary.key_strength_bits >= MIN_RSA_BITS
        elif summary.key_alg == "Ed25519":
            # Ed25519 has fixed 256-bit security; the classifier reports 256.
            assert summary.key_strength_bits == 256
        elif summary.key_alg.startswith("ECDSA-"):
            assert summary.key_strength_bits >= 256
        else:
            pytest.fail(
                f"unsupported key alg in shipped chain: {summary.key_alg!r}"
            )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-042")
def test_tsa_chain_inspect_rejects_tampered_pem() -> None:
    """A tampered PEM (no BEGIN CERTIFICATE) MUST produce chain_ok=False."""
    check = inspect_tsa_chain(
        b"not a pem at all just garbage bytes",
        chain_path="/tmp/garbage.pem",
    )
    assert check.chain_ok is False
    assert check.cert_count == 0


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-042")
def test_tsa_chain_pem_contains_only_certificate_blocks_not_private_keys() -> None:
    """The shipped chain PEM MUST NOT contain any private-key block."""
    raw = CANONICAL_CHAIN_PATH.read_text(encoding="utf-8")
    for tok in _PRIVATE_KEY_HEADER_TOKENS:
        assert tok not in raw, (
            f"shipped TSA chain contains forbidden token {tok!r}"
        )
    # And does contain BEGIN CERTIFICATE.
    assert "-----BEGIN CERTIFICATE-----" in raw


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-042")
def test_load_tsa_chain_pem_bytes_returns_x509_certificates() -> None:
    """The helper :func:`load_tsa_chain_pem_bytes` MUST return a list
    of parsed x509 certificates from a valid chain PEM."""
    raw = CANONICAL_CHAIN_PATH.read_bytes()
    certs = load_tsa_chain_pem_bytes(raw)
    assert len(certs) >= 1
