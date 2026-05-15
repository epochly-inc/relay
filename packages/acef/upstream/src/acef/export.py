"""ACEF export module — directory layout, JSONL writing, sharding, deterministic tar.gz.

Implements bundle serialization per spec Section 3.1.1:
- Directory bundle layout
- JSONL record files with RFC 8785 canonicalization
- Deterministic sharding (100k records or 256 MB)
- Deterministic tar.gz archives
"""

from __future__ import annotations

import gzip
import json
import os
import shutil
import tarfile
import tempfile
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any

from acef.errors import ACEFExportError
from acef.integrity import build_merkle_tree, canonicalize, compute_content_hashes
from acef.records_util import canonicalize_record, compute_shard_boundaries, sort_records

if TYPE_CHECKING:
    from acef.package import Package


def _write_jsonl(records: list[Any], path: Path) -> None:
    """Write records to a JSONL file with RFC 8785 canonicalization.

    Each line is independently canonicalized, followed by \\n.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        for rec in records:
            data = rec.to_jsonl_dict()
            canonical = canonicalize_record(data)
            f.write(canonical)
            f.write(b"\n")


def _validate_export_attachment_path(att_path: str) -> None:
    """Validate an attachment path before writing during export.

    Defense-in-depth check to prevent path traversal even if
    add_attachment() validation was bypassed.

    Raises:
        ACEFExportError: If the path is unsafe.
    """
    if "\\" in att_path:
        raise ACEFExportError(
            f"Backslash separators not allowed in attachment path during export: {att_path!r}",
        )
    if att_path.startswith("/"):
        raise ACEFExportError(
            f"Absolute attachment path not allowed during export: {att_path!r}",
        )
    segments = att_path.split("/")
    for segment in segments:
        if segment in (".", ".."):
            raise ACEFExportError(
                f"Traversal/dot segment in attachment path during export: {att_path!r}",
            )
    if not att_path.startswith("artifacts/"):
        raise ACEFExportError(
            f"Attachment path must be under artifacts/: {att_path!r}",
        )


def export_directory(package: Package, output_path: str) -> Path:
    """Export a package as a directory bundle.

    Args:
        package: The Package to export.
        output_path: Path to the output directory.

    Returns:
        Path to the created directory.

    Raises:
        ACEFExportError: If export fails.
    """
    bundle_dir = Path(output_path)

    try:
        bundle_dir.mkdir(parents=True, exist_ok=True)

        # Clear ALL managed subdirectories to prevent stale files (M-IMPL-1, M3)
        for subdir_name in ("records", "artifacts", "hashes", "signatures"):
            subdir = bundle_dir / subdir_name
            if subdir.exists():
                shutil.rmtree(subdir)

        # Create subdirectories
        (bundle_dir / "records").mkdir(exist_ok=True)
        (bundle_dir / "artifacts").mkdir(exist_ok=True)
        (bundle_dir / "hashes").mkdir(exist_ok=True)
        (bundle_dir / "signatures").mkdir(exist_ok=True)

        # Write attachment files with path validation (C-IMPL-1)
        for att_path, content in package.attachments.items():
            _validate_export_attachment_path(att_path)
            full_path = bundle_dir / att_path
            full_path.parent.mkdir(parents=True, exist_ok=True)
            full_path.write_bytes(content)

        # Write record files
        records_by_type: dict[str, list[Any]] = {}
        for rec in package.records:
            records_by_type.setdefault(rec.record_type, []).append(rec)

        for record_type, recs in sorted(records_by_type.items()):
            sorted_recs = sort_records(recs)
            shards = compute_shard_boundaries(sorted_recs)

            if len(shards) == 1:
                path = bundle_dir / "records" / f"{record_type}.jsonl"
                _write_jsonl(shards[0], path)
            else:
                shard_dir = bundle_dir / "records" / record_type
                shard_dir.mkdir(parents=True, exist_ok=True)
                for i, shard in enumerate(shards):
                    shard_num = str(i + 1).zfill(4)
                    path = shard_dir / f"{record_type}.{shard_num}.jsonl"
                    _write_jsonl(shard, path)

        # Write manifest
        manifest = package.build_manifest()
        manifest_data = manifest.to_dict()
        manifest_bytes = canonicalize(manifest_data)
        (bundle_dir / "acef-manifest.json").write_bytes(manifest_bytes)

        # Compute and write content hashes
        content_hashes = compute_content_hashes(bundle_dir)
        hashes_bytes = canonicalize(content_hashes)
        (bundle_dir / "hashes" / "content-hashes.json").write_bytes(hashes_bytes)

        # Compute and write Merkle tree
        merkle_tree = build_merkle_tree(content_hashes)
        merkle_bytes = canonicalize(merkle_tree)
        (bundle_dir / "hashes" / "merkle-tree.json").write_bytes(merkle_bytes)

        # Sign if requested (M-R2-4: use public properties instead of privates)
        if package.is_signed and package.signing_key:
            from acef.signing import sign_bundle

            sign_bundle(bundle_dir, package.signing_key)

    except OSError as e:
        raise ACEFExportError(f"Failed to export bundle: {e}") from e

    return bundle_dir


def export_archive(package: Package, output_path: str) -> Path:
    """Export a package as a .acef.tar.gz archive.

    Per spec: deterministic archive with gzip level 6, mtime=0, OS=0xFF,
    owner 0/0, permissions 0644/0755, lexicographic file order.

    Args:
        package: The Package to export.
        output_path: Path to the output archive.

    Returns:
        Path to the created archive.

    Raises:
        ACEFExportError: If archive creation fails.
    """
    try:
        # First export as directory to a temp location
        with tempfile.TemporaryDirectory() as tmpdir:
            bundle_name = Path(output_path).name.replace(".tar.gz", "").replace(".acef", "") + ".acef"
            bundle_dir = Path(tmpdir) / bundle_name
            export_directory(package, str(bundle_dir))

            # Get the manifest timestamp for deterministic mtime
            manifest_path = bundle_dir / "acef-manifest.json"
            manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
            timestamp_str = manifest_data.get("metadata", {}).get("timestamp", "")
            try:
                mtime = int(datetime.fromisoformat(timestamp_str.replace("Z", "+00:00")).timestamp())
            except (ValueError, AttributeError):
                mtime = 0

            # Collect all files in lexicographic order using forward slashes
            # (per spec: all paths MUST use forward slashes)
            all_files: list[str] = []
            for root, dirs, files in os.walk(str(bundle_dir)):
                dirs.sort()  # Ensure deterministic walk order
                for f in sorted(files):
                    # Use PurePosixPath to ensure forward slashes on all platforms
                    rel = PurePosixPath(Path(root).relative_to(bundle_dir)) / f
                    all_files.append(str(rel))
            all_files.sort()

            # Collect all directories
            all_dirs: list[str] = []
            for root, dirs, files in os.walk(str(bundle_dir)):
                dirs.sort()
                for d in sorted(dirs):
                    rel = PurePosixPath(Path(os.path.join(root, d)).relative_to(bundle_dir))
                    all_dirs.append(str(rel))
            all_dirs.sort()

            # Create deterministic tar.gz
            output = Path(output_path)
            output.parent.mkdir(parents=True, exist_ok=True)

            # Write tar to a temp file first, then gzip with deterministic settings (M-SCOUT-2)
            tar_tmp_path = Path(tmpdir) / "_archive.tar"
            with tarfile.open(str(tar_tmp_path), mode="w") as tar:
                # Add root directory
                root_info = tarfile.TarInfo(name=bundle_name + "/")
                root_info.type = tarfile.DIRTYPE
                root_info.mode = 0o755
                root_info.mtime = mtime
                root_info.uid = 0
                root_info.gid = 0
                root_info.uname = ""
                root_info.gname = ""
                tar.addfile(root_info)

                # Add directories
                for d in all_dirs:
                    dir_info = tarfile.TarInfo(name=f"{bundle_name}/{d}/")
                    dir_info.type = tarfile.DIRTYPE
                    dir_info.mode = 0o755
                    dir_info.mtime = mtime
                    dir_info.uid = 0
                    dir_info.gid = 0
                    dir_info.uname = ""
                    dir_info.gname = ""
                    tar.addfile(dir_info)

                # Add files — stream from disk instead of reading into memory (m9)
                for f in all_files:
                    full_path = bundle_dir / f
                    file_size = full_path.stat().st_size

                    file_info = tarfile.TarInfo(name=f"{bundle_name}/{f}")
                    file_info.size = file_size
                    file_info.mode = 0o644
                    file_info.mtime = mtime
                    file_info.uid = 0
                    file_info.gid = 0
                    file_info.uname = ""
                    file_info.gname = ""
                    with open(str(full_path), "rb") as file_obj:
                        tar.addfile(file_info, file_obj)

            # Stream-gzip the tar file to output with deterministic settings
            _stream_gzip(tar_tmp_path, output, mtime=0, level=6)

            # Patch the OS byte in the gzip header to 0xFF (unknown) per spec.
            # Gzip header format: bytes[0:2]=magic, [2]=method, [3]=flags,
            # [4:8]=mtime, [8]=xfl, [9]=OS. Python sets OS to platform default.
            with open(str(output), "r+b") as f:
                f.seek(9)
                f.write(b"\xff")

            return output

    except ACEFExportError:
        raise
    except OSError as e:
        raise ACEFExportError(f"Failed to create archive: {e}") from e


def _stream_gzip(input_path: Path, output_path: Path, *, mtime: int, level: int) -> None:
    """Stream-gzip a file to output without buffering the entire contents.

    Reads the input file in chunks and writes compressed data incrementally.

    Args:
        input_path: Path to the uncompressed file to read.
        output_path: Path to write the gzipped output.
        mtime: Gzip mtime value for determinism.
        level: Gzip compression level.
    """
    chunk_size = 65536
    with open(str(output_path), "wb") as out_f:
        with gzip.GzipFile(
            filename="",
            mode="wb",
            compresslevel=level,
            fileobj=out_f,
            mtime=mtime,
        ) as gz:
            with open(str(input_path), "rb") as in_f:
                while True:
                    chunk = in_f.read(chunk_size)
                    if not chunk:
                        break
                    gz.write(chunk)
