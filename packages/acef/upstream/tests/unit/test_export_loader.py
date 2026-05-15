"""Tests for acef.export and acef.loader — export, load, round-trip, security."""

from __future__ import annotations

import json
import os
import tarfile
from pathlib import Path

import pytest

from acef.errors import ACEFFormatError
from acef.export import export_archive, export_directory
from acef.integrity import canonicalize, compute_content_hashes, sha256_file
from acef.loader import load
from acef.package import Package


class TestExportDirectory:
    """Test directory bundle export."""

    def test_creates_expected_structure(self, minimal_package: Package, tmp_dir: Path):
        bundle_dir = tmp_dir / "bundle.acef"
        export_directory(minimal_package, str(bundle_dir))

        assert (bundle_dir / "acef-manifest.json").exists()
        assert (bundle_dir / "records").is_dir()
        assert (bundle_dir / "artifacts").is_dir()
        assert (bundle_dir / "hashes").is_dir()
        assert (bundle_dir / "hashes" / "content-hashes.json").exists()
        assert (bundle_dir / "hashes" / "merkle-tree.json").exists()
        assert (bundle_dir / "signatures").is_dir()

    def test_manifest_is_canonicalized(self, minimal_package: Package, tmp_dir: Path):
        bundle_dir = tmp_dir / "bundle.acef"
        export_directory(minimal_package, str(bundle_dir))

        manifest_bytes = (bundle_dir / "acef-manifest.json").read_bytes()
        manifest_data = json.loads(manifest_bytes)
        re_canonical = canonicalize(manifest_data)
        assert manifest_bytes == re_canonical

    def test_jsonl_files_canonicalized(self, minimal_package: Package, tmp_dir: Path):
        bundle_dir = tmp_dir / "bundle.acef"
        export_directory(minimal_package, str(bundle_dir))

        jsonl_path = bundle_dir / "records" / "risk_register.jsonl"
        assert jsonl_path.exists()

        with open(jsonl_path, "rb") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                data = json.loads(line)
                re_canonical = canonicalize(data)
                assert line == re_canonical

    def test_records_sorted_by_timestamp_then_id(self, tmp_dir: Path):
        pkg = Package()
        # Add records with different timestamps
        r1 = pkg.record("risk_register", payload={"n": 1}, timestamp="2025-01-02T00:00:00Z")
        r2 = pkg.record("risk_register", payload={"n": 2}, timestamp="2025-01-01T00:00:00Z")
        r3 = pkg.record("risk_register", payload={"n": 3}, timestamp="2025-01-01T00:00:00Z")

        bundle_dir = tmp_dir / "bundle.acef"
        export_directory(pkg, str(bundle_dir))

        jsonl_path = bundle_dir / "records" / "risk_register.jsonl"
        records = []
        with open(jsonl_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    records.append(json.loads(line))

        # First two should be timestamp 2025-01-01, sorted by record_id
        assert records[0]["timestamp"] == "2025-01-01T00:00:00Z"
        assert records[1]["timestamp"] == "2025-01-01T00:00:00Z"
        assert records[0]["record_id"] <= records[1]["record_id"]
        assert records[2]["timestamp"] == "2025-01-02T00:00:00Z"

    def test_content_hashes_valid(self, minimal_package: Package, tmp_dir: Path):
        bundle_dir = tmp_dir / "bundle.acef"
        export_directory(minimal_package, str(bundle_dir))

        stored_hashes = json.loads(
            (bundle_dir / "hashes" / "content-hashes.json").read_text(encoding="utf-8")
        )
        computed_hashes = compute_content_hashes(bundle_dir)
        assert stored_hashes == computed_hashes


class TestExportWithAttachments:
    """Test export with attachment files."""

    def test_attachment_written(self, tmp_dir: Path):
        pkg = Package()
        pkg.add_attachment("report.pdf", b"PDF content here")
        pkg.record(
            "evaluation_report",
            payload={"result": "pass"},
            attachments=[{"path": "artifacts/report.pdf", "media_type": "application/pdf"}],
        )

        bundle_dir = tmp_dir / "bundle.acef"
        export_directory(pkg, str(bundle_dir))

        assert (bundle_dir / "artifacts" / "report.pdf").exists()
        assert (bundle_dir / "artifacts" / "report.pdf").read_bytes() == b"PDF content here"


class TestRoundTrip:
    """Test export -> load -> re-export produces identical results."""

    def test_directory_round_trip(self, full_package: Package, tmp_dir: Path):
        # Export
        bundle1 = tmp_dir / "bundle1.acef"
        export_directory(full_package, str(bundle1))

        # Load
        loaded = load(str(bundle1))

        # Re-export
        bundle2 = tmp_dir / "bundle2.acef"
        export_directory(loaded, str(bundle2))

        # Compare content hashes
        hashes1 = compute_content_hashes(bundle1)
        hashes2 = compute_content_hashes(bundle2)
        assert hashes1 == hashes2

    def test_archive_round_trip(self, minimal_package: Package, tmp_dir: Path):
        # Export as archive
        archive1 = tmp_dir / "bundle.acef.tar.gz"
        export_archive(minimal_package, str(archive1))
        assert archive1.exists()

        # Load from archive
        loaded = load(str(archive1))

        # Verify loaded package has expected data
        assert len(loaded.subjects) == 1
        assert loaded.subjects[0].name == "Test System"
        assert len(loaded.records) == 1
        assert loaded.records[0].record_type == "risk_register"


class TestArchiveExport:
    """Test deterministic tar.gz archive export."""

    def test_archive_created(self, minimal_package: Package, tmp_dir: Path):
        archive = tmp_dir / "bundle.acef.tar.gz"
        export_archive(minimal_package, str(archive))
        assert archive.exists()
        assert archive.stat().st_size > 0

    def test_archive_deterministic(self, minimal_package: Package, tmp_dir: Path):
        """Archives from the same package produce consistent internal content.

        Note: The archive name is derived from output path, so two exports to
        different paths may differ in directory name. We verify content hashes match
        by extracting and comparing the content-hashes.json from each.
        """
        archive1 = tmp_dir / "same_name.acef.tar.gz"
        archive2 = tmp_dir / "same_name2.acef.tar.gz"
        export_archive(minimal_package, str(archive1))
        export_archive(minimal_package, str(archive2))

        # Both archives should load to identical packages
        from acef.loader import load
        pkg1 = load(str(archive1))
        pkg2 = load(str(archive2))
        assert len(pkg1.records) == len(pkg2.records)

        # Re-export from both loaded packages should produce identical hashes
        dir1 = tmp_dir / "det1.acef"
        dir2 = tmp_dir / "det2.acef"
        pkg1.export(str(dir1))
        pkg2.export(str(dir2))
        import json
        h1 = json.loads((dir1 / "hashes" / "content-hashes.json").read_text())
        h2 = json.loads((dir2 / "hashes" / "content-hashes.json").read_text())
        assert h1 == h2

    def test_archive_contains_expected_files(self, minimal_package: Package, tmp_dir: Path):
        archive = tmp_dir / "bundle.acef.tar.gz"
        export_archive(minimal_package, str(archive))

        with tarfile.open(str(archive), "r:gz") as tar:
            names = tar.getnames()
            # Should have acef-manifest.json, records, hashes, etc.
            manifest_entries = [n for n in names if "acef-manifest.json" in n]
            assert len(manifest_entries) == 1


class TestLoaderSecurity:
    """Test loader security: path traversal, symlinks, tar bomb limits."""

    def test_path_traversal_rejected(self, tmp_dir: Path):
        bundle_dir = tmp_dir / "bundle.acef"
        bundle_dir.mkdir(parents=True)
        manifest = {
            "metadata": {"package_id": "test", "producer": {"name": "t", "version": "1"}},
            "record_files": [{"path": "../../../etc/passwd", "record_type": "risk_register", "count": 0}],
        }
        (bundle_dir / "acef-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

        with pytest.raises(ACEFFormatError, match="Path traversal"):
            load(str(bundle_dir))

    def test_symlink_rejected_in_archive(self, tmp_dir: Path):
        # Create a tar with a symlink
        archive = tmp_dir / "bad.acef.tar.gz"
        with tarfile.open(str(archive), "w:gz") as tar:
            bundle_name = "bad.acef"
            # Add root dir
            dir_info = tarfile.TarInfo(name=f"{bundle_name}/")
            dir_info.type = tarfile.DIRTYPE
            tar.addfile(dir_info)
            # Add symlink
            link_info = tarfile.TarInfo(name=f"{bundle_name}/evil_link")
            link_info.type = tarfile.SYMTYPE
            link_info.linkname = "/etc/passwd"
            tar.addfile(link_info)

        with pytest.raises(ACEFFormatError, match="[Ss]ymlink"):
            load(str(archive))

    def test_missing_manifest_rejected(self, tmp_dir: Path):
        bundle_dir = tmp_dir / "empty.acef"
        bundle_dir.mkdir(parents=True)

        with pytest.raises(ACEFFormatError, match="No acef-manifest.json"):
            load(str(bundle_dir))

    def test_invalid_path_rejected(self, tmp_dir: Path):
        fake = tmp_dir / "nonexistent.txt"
        with pytest.raises(ACEFFormatError):
            load(str(fake))


class TestShardBoundary:
    """Test shard boundary computation."""

    def test_single_shard_small_set(self):
        pkg = Package()
        for i in range(10):
            pkg.record("risk_register", payload={"n": i})
        manifest = pkg.build_manifest()
        rr_files = [rf for rf in manifest.record_files if rf.record_type == "risk_register"]
        assert len(rr_files) == 1
        assert rr_files[0].count == 10
        assert rr_files[0].path == "records/risk_register.jsonl"
