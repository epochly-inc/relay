"""ACEF integrity checker — hash, Merkle tree, and signature verification.

Phase 2 of the 4-phase validation pipeline.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

from acef.errors import ValidationDiagnostic
from acef.integrity import (
    verify_content_hashes,
    verify_merkle_root,
)


def check_integrity(bundle_dir: Path) -> list[ValidationDiagnostic]:
    """Run all integrity checks on a bundle directory.

    Steps per spec Section 3.1.3:
    a. Verify content hashes
    b. Verify Merkle root
    c. Verify signatures (if present)

    Returns:
        List of diagnostics.
    """
    diagnostics: list[ValidationDiagnostic] = []

    # Check content-hashes.json exists
    content_hashes_path = bundle_dir / "hashes" / "content-hashes.json"
    if not content_hashes_path.exists():
        diagnostics.append(
            ValidationDiagnostic(
                "ACEF-014",
                "content-hashes.json not found in hashes/",
                path="/hashes/content-hashes.json",
            )
        )
        return diagnostics

    # Load expected hashes
    try:
        expected_hashes = json.loads(content_hashes_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        diagnostics.append(
            ValidationDiagnostic(
                "ACEF-014",
                f"Invalid JSON in content-hashes.json: {e}",
                path="/hashes/content-hashes.json",
            )
        )
        return diagnostics

    # Verify content hashes
    hash_errors = verify_content_hashes(bundle_dir, expected_hashes)
    for error_msg in hash_errors:
        if "mismatch" in error_msg.lower():
            diagnostics.append(
                ValidationDiagnostic("ACEF-010", error_msg)
            )
        else:
            diagnostics.append(
                ValidationDiagnostic("ACEF-014", error_msg)
            )

    # Check Merkle tree
    merkle_path = bundle_dir / "hashes" / "merkle-tree.json"
    if merkle_path.exists():
        try:
            merkle_data = json.loads(merkle_path.read_text(encoding="utf-8"))
            expected_root = merkle_data.get("root", "")
            if not verify_merkle_root(expected_hashes, expected_root):
                diagnostics.append(
                    ValidationDiagnostic(
                        "ACEF-011",
                        "Merkle root mismatch",
                        path="/hashes/merkle-tree.json",
                    )
                )
        except json.JSONDecodeError as e:
            diagnostics.append(
                ValidationDiagnostic(
                    "ACEF-011",
                    f"Invalid JSON in merkle-tree.json: {e}",
                    path="/hashes/merkle-tree.json",
                )
            )

    # Check signatures
    sig_diagnostics = _check_signatures(bundle_dir, content_hashes_path.read_bytes())
    diagnostics.extend(sig_diagnostics)

    return diagnostics


def _check_signatures(bundle_dir: Path, content_hashes_bytes: bytes) -> list[ValidationDiagnostic]:
    """Verify all JWS signatures in signatures/."""
    diagnostics: list[ValidationDiagnostic] = []
    sig_dir = bundle_dir / "signatures"

    if not sig_dir.exists():
        return diagnostics  # Unsigned bundles are valid

    for sig_file in sorted(sig_dir.glob("*.jws")):
        jws_str = sig_file.read_text(encoding="utf-8").strip()
        if not jws_str:
            continue

        # Parse JWS header to check algorithm
        parts = jws_str.split(".")
        if len(parts) != 3:
            diagnostics.append(
                ValidationDiagnostic(
                    "ACEF-012",
                    f"Invalid JWS format in {sig_file.name}",
                    path=f"/signatures/{sig_file.name}",
                )
            )
            continue

        try:
            header_bytes = base64.urlsafe_b64decode(parts[0] + "==")
            header = json.loads(header_bytes)
        except Exception as e:
            diagnostics.append(
                ValidationDiagnostic(
                    "ACEF-012",
                    f"Invalid JWS header in {sig_file.name}: {e}",
                    path=f"/signatures/{sig_file.name}",
                )
            )
            continue

        alg = header.get("alg", "")
        if alg not in ("RS256", "ES256"):
            diagnostics.append(
                ValidationDiagnostic(
                    "ACEF-013",
                    f"Unsupported JWS algorithm in {sig_file.name}: {alg!r}",
                    path=f"/signatures/{sig_file.name}",
                )
            )

        # Note: actual signature verification requires the public key,
        # which is provided by x5c or external trust store.
        # We validate format here; full verification is done with keys.

    return diagnostics


def get_signature_info(bundle_dir: Path) -> tuple[int, list[str]]:
    """Get signature count and algorithms from a bundle.

    Returns:
        Tuple of (signature_count, list_of_algorithms).
    """
    sig_dir = bundle_dir / "signatures"
    if not sig_dir.exists():
        return 0, []

    count = 0
    algorithms: list[str] = []

    for sig_file in sorted(sig_dir.glob("*.jws")):
        jws_str = sig_file.read_text(encoding="utf-8").strip()
        if not jws_str:
            continue

        parts = jws_str.split(".")
        if len(parts) != 3:
            continue

        try:
            header_bytes = base64.urlsafe_b64decode(parts[0] + "==")
            header = json.loads(header_bytes)
            algorithms.append(header.get("alg", ""))
            count += 1
        except Exception:
            continue

    return count, algorithms
