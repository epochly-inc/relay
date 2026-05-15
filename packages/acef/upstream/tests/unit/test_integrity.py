"""Tests for acef.integrity — canonicalization, hashing, Merkle tree, verification."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from acef.integrity import (
    build_merkle_tree,
    canonicalize,
    canonicalize_json_str,
    compute_bundle_digest,
    compute_content_hashes,
    sha256_file,
    sha256_hex,
    sha256_jsonl_file,
    verify_content_hashes,
    verify_merkle_root,
)


class TestCanonicalize:
    """Test RFC 8785 canonicalization."""

    def test_deterministic_key_order(self):
        data = {"z": 1, "a": 2, "m": 3}
        result = canonicalize(data)
        parsed = json.loads(result)
        assert list(parsed.keys()) == ["a", "m", "z"]

    def test_nested_objects_sorted(self):
        data = {"b": {"z": 1, "a": 2}, "a": 1}
        result = canonicalize(data)
        parsed = json.loads(result)
        assert list(parsed.keys()) == ["a", "b"]
        assert list(parsed["b"].keys()) == ["a", "z"]

    def test_same_input_same_output(self):
        data = {"key": "value", "num": 42}
        assert canonicalize(data) == canonicalize(data)

    def test_returns_bytes(self):
        result = canonicalize({"key": "value"})
        assert isinstance(result, bytes)

    def test_no_whitespace(self):
        result = canonicalize({"a": 1, "b": [1, 2, 3]})
        text = result.decode("utf-8")
        assert " " not in text
        assert "\n" not in text

    def test_canonicalize_json_str(self):
        json_str = '{"b": 1, "a": 2}'
        result = canonicalize_json_str(json_str)
        expected = canonicalize({"a": 2, "b": 1})
        assert result == expected


class TestSHA256:
    """Test SHA-256 hashing functions."""

    def test_sha256_hex_known_value(self):
        result = sha256_hex(b"hello")
        expected = hashlib.sha256(b"hello").hexdigest()
        assert result == expected
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)

    def test_sha256_hex_empty(self):
        result = sha256_hex(b"")
        expected = hashlib.sha256(b"").hexdigest()
        assert result == expected

    def test_sha256_file_json(self, tmp_dir: Path):
        data = {"b": 1, "a": 2}
        path = tmp_dir / "test.json"
        path.write_text(json.dumps(data), encoding="utf-8")

        result = sha256_file(path)
        # JSON files are canonicalized before hashing
        canonical = canonicalize(data)
        expected = sha256_hex(canonical)
        assert result == expected

    def test_sha256_file_jsonl(self, tmp_dir: Path):
        path = tmp_dir / "test.jsonl"
        lines = [
            json.dumps({"b": 1, "a": 2}),
            json.dumps({"z": 3}),
        ]
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        result = sha256_file(path)
        # Each line independently canonicalized
        expected_result = sha256_jsonl_file(path)
        assert result == expected_result

    def test_sha256_file_binary(self, tmp_dir: Path):
        path = tmp_dir / "test.bin"
        content = b"\x00\x01\x02\x03"
        path.write_bytes(content)

        result = sha256_file(path)
        expected = sha256_hex(content)
        assert result == expected


class TestSHA256JSONL:
    """Test JSONL-specific hashing."""

    def test_per_line_canonicalization(self, tmp_dir: Path):
        path = tmp_dir / "test.jsonl"
        path.write_text('{"b":1,"a":2}\n{"z":3}\n', encoding="utf-8")

        result = sha256_jsonl_file(path)

        # Manually compute expected
        hasher = hashlib.sha256()
        hasher.update(canonicalize({"b": 1, "a": 2}))
        hasher.update(b"\n")
        hasher.update(canonicalize({"z": 3}))
        hasher.update(b"\n")
        expected = hasher.hexdigest()
        assert result == expected

    def test_skips_empty_lines(self, tmp_dir: Path):
        path = tmp_dir / "test.jsonl"
        path.write_text('{"a":1}\n\n{"b":2}\n', encoding="utf-8")

        result = sha256_jsonl_file(path)

        hasher = hashlib.sha256()
        hasher.update(canonicalize({"a": 1}))
        hasher.update(b"\n")
        hasher.update(canonicalize({"b": 2}))
        hasher.update(b"\n")
        assert result == hasher.hexdigest()


class TestComputeContentHashes:
    """Test content-hashes.json computation."""

    def test_empty_bundle(self, tmp_dir: Path):
        hashes = compute_content_hashes(tmp_dir)
        assert hashes == {}

    def test_with_manifest_only(self, tmp_dir: Path):
        manifest = {"metadata": {"package_id": "test"}}
        (tmp_dir / "acef-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

        hashes = compute_content_hashes(tmp_dir)
        assert "acef-manifest.json" in hashes
        assert len(hashes) == 1

    def test_with_records(self, tmp_dir: Path):
        manifest = {"metadata": {}}
        (tmp_dir / "acef-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        records_dir = tmp_dir / "records"
        records_dir.mkdir()
        (records_dir / "risk_register.jsonl").write_text(
            '{"record_type":"risk_register"}\n', encoding="utf-8"
        )

        hashes = compute_content_hashes(tmp_dir)
        assert "acef-manifest.json" in hashes
        assert "records/risk_register.jsonl" in hashes
        assert len(hashes) == 2

    def test_sorted_keys(self, tmp_dir: Path):
        (tmp_dir / "acef-manifest.json").write_text("{}", encoding="utf-8")
        records_dir = tmp_dir / "records"
        records_dir.mkdir()
        (records_dir / "z_type.jsonl").write_text("{}\n", encoding="utf-8")
        (records_dir / "a_type.jsonl").write_text("{}\n", encoding="utf-8")

        hashes = compute_content_hashes(tmp_dir)
        keys = list(hashes.keys())
        assert keys == sorted(keys)

    def test_includes_artifacts(self, tmp_dir: Path):
        (tmp_dir / "acef-manifest.json").write_text("{}", encoding="utf-8")
        artifacts_dir = tmp_dir / "artifacts"
        artifacts_dir.mkdir()
        (artifacts_dir / "report.pdf").write_bytes(b"PDF content")

        hashes = compute_content_hashes(tmp_dir)
        assert "artifacts/report.pdf" in hashes


class TestBuildMerkleTree:
    """Test Merkle tree construction."""

    def test_empty_hashes(self):
        tree = build_merkle_tree({})
        assert tree["leaves"] == []
        assert tree["root"] == sha256_hex(b"")

    def test_single_entry(self):
        hashes = {"file.json": "abcd1234" * 8}
        tree = build_merkle_tree(hashes)
        assert len(tree["leaves"]) == 1
        assert tree["leaves"][0]["path"] == "file.json"
        # Root should be the single leaf hash
        leaf_hash = hashlib.sha256(
            b"file.json" + b"\x00" + ("abcd1234" * 8).encode("utf-8")
        ).hexdigest()
        assert tree["root"] == leaf_hash

    def test_two_entries(self):
        hashes = {"a.json": "a" * 64, "b.json": "b" * 64}
        tree = build_merkle_tree(hashes)
        assert len(tree["leaves"]) == 2
        # Two leaves combined
        left = hashlib.sha256(b"a.json\x00" + ("a" * 64).encode("utf-8")).digest()
        right = hashlib.sha256(b"b.json\x00" + ("b" * 64).encode("utf-8")).digest()
        expected_root = hashlib.sha256(left + right).hexdigest()
        assert tree["root"] == expected_root

    def test_three_entries_odd_promotion(self):
        hashes = {"a.json": "a" * 64, "b.json": "b" * 64, "c.json": "c" * 64}
        tree = build_merkle_tree(hashes)
        assert len(tree["leaves"]) == 3
        # Odd leaf (c) promoted unchanged
        left = hashlib.sha256(b"a.json\x00" + ("a" * 64).encode("utf-8")).digest()
        middle = hashlib.sha256(b"b.json\x00" + ("b" * 64).encode("utf-8")).digest()
        right = hashlib.sha256(b"c.json\x00" + ("c" * 64).encode("utf-8")).digest()
        combined_ab = hashlib.sha256(left + middle).digest()
        # c promoted, then combined with ab
        expected_root = hashlib.sha256(combined_ab + right).hexdigest()
        assert tree["root"] == expected_root

    def test_four_entries_even(self):
        hashes = {
            "a.json": "a" * 64, "b.json": "b" * 64,
            "c.json": "c" * 64, "d.json": "d" * 64,
        }
        tree = build_merkle_tree(hashes)
        assert len(tree["leaves"]) == 4
        assert len(tree["root"]) == 64  # hex SHA-256

    def test_deterministic(self):
        hashes = {"x.json": "x" * 64, "y.json": "y" * 64}
        tree1 = build_merkle_tree(hashes)
        tree2 = build_merkle_tree(hashes)
        assert tree1["root"] == tree2["root"]

    def test_sorted_input(self):
        # Even if input is unsorted, leaves should be sorted
        hashes = {"z.json": "z" * 64, "a.json": "a" * 64}
        tree = build_merkle_tree(hashes)
        assert tree["leaves"][0]["path"] == "a.json"
        assert tree["leaves"][1]["path"] == "z.json"


class TestVerifyContentHashes:
    """Test content hash verification."""

    def test_success(self, tmp_dir: Path):
        (tmp_dir / "acef-manifest.json").write_text("{}", encoding="utf-8")
        hashes = compute_content_hashes(tmp_dir)
        errors = verify_content_hashes(tmp_dir, hashes)
        assert errors == []

    def test_missing_file(self, tmp_dir: Path):
        expected = {"acef-manifest.json": "a" * 64}
        errors = verify_content_hashes(tmp_dir, expected)
        assert len(errors) > 0
        assert any("not found" in e for e in errors)

    def test_hash_mismatch(self, tmp_dir: Path):
        (tmp_dir / "acef-manifest.json").write_text("{}", encoding="utf-8")
        expected = {"acef-manifest.json": "wrong_hash" * 4 + "00000000"}
        errors = verify_content_hashes(tmp_dir, expected)
        assert len(errors) > 0
        assert any("mismatch" in e.lower() for e in errors)

    def test_extra_file_on_disk(self, tmp_dir: Path):
        (tmp_dir / "acef-manifest.json").write_text("{}", encoding="utf-8")
        records_dir = tmp_dir / "records"
        records_dir.mkdir()
        (records_dir / "extra.jsonl").write_text("{}\n", encoding="utf-8")

        expected = {"acef-manifest.json": compute_content_hashes(tmp_dir)["acef-manifest.json"]}
        errors = verify_content_hashes(tmp_dir, expected)
        assert len(errors) > 0
        assert any("not listed" in e for e in errors)


class TestVerifyMerkleRoot:
    """Test Merkle root verification."""

    def test_success(self):
        hashes = {"a.json": "a" * 64}
        tree = build_merkle_tree(hashes)
        assert verify_merkle_root(hashes, tree["root"])

    def test_failure_wrong_root(self):
        hashes = {"a.json": "a" * 64}
        assert not verify_merkle_root(hashes, "wrong" * 16)


class TestComputeBundleDigest:
    """Test bundle digest computation."""

    def test_produces_sha256_prefix(self):
        hashes = {"file.json": "a" * 64}
        digest = compute_bundle_digest(hashes)
        assert digest.startswith("sha256:")

    def test_digest_uses_canonical_hashes(self):
        hashes = {"b.json": "b" * 64, "a.json": "a" * 64}
        digest = compute_bundle_digest(hashes)
        canonical = canonicalize(hashes)
        expected = f"sha256:{sha256_hex(canonical)}"
        assert digest == expected

    def test_deterministic(self):
        hashes = {"x.json": "x" * 64}
        assert compute_bundle_digest(hashes) == compute_bundle_digest(hashes)
