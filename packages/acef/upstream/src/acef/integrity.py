"""ACEF integrity module — RFC 8785 canonicalization, SHA-256 hashing, Merkle tree.

Implements the integrity model from spec Section 3.1.3:
- RFC 8785 (JCS) canonicalization for all JSON in hash domain
- SHA-256 content hashing
- content-hashes.json generation
- Merkle tree construction with odd-leaf promotion
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import rfc8785


# Chunk size for streaming binary file hashing (64 KB)
_HASH_CHUNK_SIZE = 65536


def canonicalize(data: Any) -> bytes:
    """Canonicalize a Python object to RFC 8785 (JCS) bytes.

    Args:
        data: Any JSON-serializable Python object.

    Returns:
        RFC 8785 canonicalized bytes.
    """
    return rfc8785.dumps(data)


def canonicalize_json_str(json_str: str) -> bytes:
    """Parse a JSON string and re-canonicalize via RFC 8785.

    Args:
        json_str: A JSON string.

    Returns:
        RFC 8785 canonicalized bytes.
    """
    data = json.loads(json_str)
    return canonicalize(data)


def sha256_hex(data: bytes) -> str:
    """Compute SHA-256 hash of bytes, return lowercase hex.

    Args:
        data: Raw bytes to hash.

    Returns:
        Lowercase hex-encoded SHA-256 digest.
    """
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    """Compute SHA-256 hash of a file.

    For .json files, the content is parsed and re-canonicalized via RFC 8785
    before hashing. For .jsonl files, each line is independently canonicalized.
    For all other files, raw bytes are hashed using chunked streaming to
    avoid loading the entire file into memory.

    Args:
        path: Path to the file.

    Returns:
        Lowercase hex-encoded SHA-256 digest.
    """
    if path.suffix == ".json":
        content = path.read_text(encoding="utf-8")
        canonical = canonicalize_json_str(content)
        return sha256_hex(canonical)
    elif path.suffix == ".jsonl":
        return sha256_jsonl_file(path)
    else:
        # M-SCOUT-3: Stream binary files in chunks to avoid loading
        # potentially large artifacts entirely into memory.
        return _sha256_file_streaming(path)


def _sha256_file_streaming(path: Path) -> str:
    """Compute SHA-256 hash of a file using chunked streaming.

    Reads the file in 64 KB chunks and updates the hasher incrementally,
    avoiding loading the entire file into memory.

    Args:
        path: Path to the file.

    Returns:
        Lowercase hex-encoded SHA-256 digest.
    """
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(_HASH_CHUNK_SIZE)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def sha256_jsonl_file(path: Path) -> str:
    """Compute SHA-256 of a JSONL file with per-line canonicalization.

    Each line is parsed, canonicalized via RFC 8785, and followed by \\n.
    The hash is over the concatenation of all canonicalized lines.

    Args:
        path: Path to the JSONL file.

    Returns:
        Lowercase hex-encoded SHA-256 digest.
    """
    hasher = hashlib.sha256()
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            data = json.loads(line)
            canonical = canonicalize(data)
            hasher.update(canonical)
            hasher.update(b"\n")
    return hasher.hexdigest()


def compute_content_hashes(bundle_dir: Path) -> dict[str, str]:
    """Compute content-hashes.json for all files in the hash domain.

    Hash domain includes:
    - acef-manifest.json
    - Everything in records/
    - Everything in artifacts/

    Args:
        bundle_dir: Path to the bundle root directory.

    Returns:
        Dict mapping relative paths (sorted) to hex SHA-256 hashes.
    """
    hashes: dict[str, str] = {}

    manifest_path = bundle_dir / "acef-manifest.json"
    if manifest_path.exists():
        hashes["acef-manifest.json"] = sha256_file(manifest_path)

    records_dir = bundle_dir / "records"
    if records_dir.exists():
        for file_path in sorted(records_dir.rglob("*")):
            if file_path.is_file():
                rel = file_path.relative_to(bundle_dir).as_posix()
                hashes[rel] = sha256_file(file_path)

    artifacts_dir = bundle_dir / "artifacts"
    if artifacts_dir.exists():
        for file_path in sorted(artifacts_dir.rglob("*")):
            if file_path.is_file():
                rel = file_path.relative_to(bundle_dir).as_posix()
                hashes[rel] = sha256_file(file_path)

    return dict(sorted(hashes.items()))


def build_merkle_tree(content_hashes: dict[str, str]) -> dict[str, Any]:
    """Build a Merkle tree from content-hashes.json entries.

    Per spec Section 3.1.3:
    - Leaf nodes: SHA-256(path || 0x00 || hash) where both are UTF-8 bytes
    - Inner nodes: SHA-256(left_hash || right_hash) using raw 32-byte digests
    - Odd leaf: promoted unchanged (NOT duplicated)
    - Root: single remaining hash

    Args:
        content_hashes: Dict mapping paths to hex SHA-256 hashes.

    Returns:
        Dict with 'leaves' and 'root' keys matching spec JSON shape.
    """
    if not content_hashes:
        empty_root = sha256_hex(b"")
        return {"leaves": [], "root": empty_root}

    sorted_entries = sorted(content_hashes.items())
    leaves: list[dict[str, str]] = []
    current_level: list[bytes] = []

    for path, hash_hex in sorted_entries:
        leaves.append({"path": path, "hash": hash_hex})
        path_bytes = path.encode("utf-8")
        hash_bytes = hash_hex.encode("utf-8")
        leaf_hash = hashlib.sha256(path_bytes + b"\x00" + hash_bytes).digest()
        current_level.append(leaf_hash)

    while len(current_level) > 1:
        next_level: list[bytes] = []
        i = 0
        while i < len(current_level):
            if i + 1 < len(current_level):
                combined = current_level[i] + current_level[i + 1]
                next_level.append(hashlib.sha256(combined).digest())
                i += 2
            else:
                # Odd leaf: promoted unchanged
                next_level.append(current_level[i])
                i += 1
        current_level = next_level

    root_hex = current_level[0].hex()
    return {"leaves": leaves, "root": root_hex}


def verify_content_hashes(bundle_dir: Path, expected_hashes: dict[str, str]) -> list[str]:
    """Verify file hashes against expected content-hashes.json.

    Args:
        bundle_dir: Path to the bundle root directory.
        expected_hashes: The content-hashes.json entries.

    Returns:
        List of error messages. Empty list means all OK.
    """
    errors: list[str] = []
    actual_hashes = compute_content_hashes(bundle_dir)

    # Check for files in expected but not on disk
    for path in expected_hashes:
        if path not in actual_hashes:
            errors.append(f"File listed in content-hashes.json but not found: {path}")

    # Check for files on disk but not in expected
    for path in actual_hashes:
        if path not in expected_hashes:
            errors.append(f"File in hash domain but not listed in content-hashes.json: {path}")

    # Check hash values
    for path in expected_hashes:
        if path in actual_hashes:
            if actual_hashes[path] != expected_hashes[path]:
                errors.append(f"Hash mismatch for {path}: expected {expected_hashes[path]}, got {actual_hashes[path]}")

    return errors


def verify_merkle_root(content_hashes: dict[str, str], expected_root: str) -> bool:
    """Verify the Merkle root against content-hashes.json.

    Args:
        content_hashes: The content-hashes.json entries.
        expected_root: The expected Merkle root hash.

    Returns:
        True if the Merkle root matches.
    """
    tree = build_merkle_tree(content_hashes)
    return tree["root"] == expected_root


def compute_bundle_digest(content_hashes: dict[str, str]) -> str:
    """Compute the canonical bundle identity.

    Per spec: SHA-256 hash of the RFC 8785-canonicalized content-hashes.json.

    Args:
        content_hashes: The content-hashes.json entries.

    Returns:
        Hex-encoded SHA-256 digest prefixed with 'sha256:'.
    """
    canonical = canonicalize(content_hashes)
    digest = sha256_hex(canonical)
    return f"sha256:{digest}"
