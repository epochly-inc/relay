"""ACEF loader module — bundle deserialization and round-trip.

Loads ACEF Evidence Bundles from directories or .acef.tar.gz archives.
Implements security mitigations: path traversal rejection, tar bomb guards.
"""

from __future__ import annotations

import gzip
import json
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Any

from acef.errors import ACEFFormatError
from acef.models.entities import Actor, Component, Dataset, EntitiesBlock, Relationship
from acef.models.manifest import AuditTrailEntry, ProfileEntry
from acef.models.metadata import PackageMetadata, ProducerInfo, RetentionPolicy, Versioning
from acef.models.records import (
    RecordEnvelope,
    dict_to_record_envelope,
)
from acef.models.subjects import LifecycleEntry, Subject
from acef.package import Package

# Tar bomb limits
_MAX_EXTRACTED_SIZE = 10 * 1024 * 1024 * 1024  # 10 GB
_MAX_FILE_COUNT = 100_000
_MAX_SINGLE_FILE_SIZE = 1 * 1024 * 1024 * 1024  # 1 GB

# Artifact size guards
_MAX_ARTIFACT_FILE_SIZE = _MAX_SINGLE_FILE_SIZE  # 1 GB per file
_MAX_TOTAL_ARTIFACT_SIZE = _MAX_EXTRACTED_SIZE  # 10 GB cumulative (m8 Scout R2)


def _validate_path(path: str) -> None:
    """Validate a path per spec Section 3.1.1 path normalization rules.

    Rejects:
    - Paths containing '..' segments (traversal)
    - Paths containing '.' segments (current-dir, spec-forbidden)
    - Absolute paths (starting with '/')
    - Backslash separators (must use forward slash)

    Raises:
        ACEFFormatError: If path violates normalization rules.
    """
    # Check for backslash separators
    if "\\" in path:
        raise ACEFFormatError(
            f"Path contains backslash separators (must use forward slash): {path!r}",
            code="ACEF-052",
        )

    # Check for absolute paths
    if path.startswith("/"):
        raise ACEFFormatError(
            f"Absolute path not allowed (must be relative to bundle root): {path!r}",
            code="ACEF-052",
        )

    # Check for . and .. segments per spec: "not contain . or .. segments"
    segments = path.split("/")
    for segment in segments:
        if segment == "..":
            raise ACEFFormatError(
                f"Path traversal detected (.. segment): {path!r}",
                code="ACEF-052",
            )
        if segment == ".":
            raise ACEFFormatError(
                f"Current-directory segment (.) not allowed in paths: {path!r}",
                code="ACEF-052",
            )


def _validate_tar_safety(tar: tarfile.TarFile) -> None:
    """Validate tar archive for bomb protection.

    Checks:
    - No symlinks or hard links
    - Total extracted size < 10 GB
    - File count < 100,000
    - No single file > 1 GB
    - No path traversal

    Raises:
        ACEFFormatError: If any safety check fails.
    """
    total_size = 0
    file_count = 0

    for member in tar.getmembers():
        # Reject symlinks and hard links
        if member.issym() or member.islnk():
            raise ACEFFormatError(
                f"Symlinks/hardlinks not allowed in ACEF archives: {member.name}",
                code="ACEF-052",
            )

        # Path traversal check — strip the leading bundle name for archive members
        # Archive paths are like "bundle.acef/records/..." so validate the full path
        if member.name.startswith("/") or ".." in member.name.split("/"):
            raise ACEFFormatError(
                f"Absolute or traversal path in archive: {member.name}",
                code="ACEF-052",
            )

        if member.isfile():
            file_count += 1
            total_size += member.size

            if member.size > _MAX_SINGLE_FILE_SIZE:
                raise ACEFFormatError(
                    f"File exceeds 1 GB limit: {member.name} ({member.size} bytes)",
                    code="ACEF-050",
                )

    if file_count > _MAX_FILE_COUNT:
        raise ACEFFormatError(
            f"Archive contains too many files: {file_count} (limit: {_MAX_FILE_COUNT})",
            code="ACEF-050",
        )

    if total_size > _MAX_EXTRACTED_SIZE:
        raise ACEFFormatError(
            f"Archive total size exceeds 10 GB limit: {total_size} bytes",
            code="ACEF-050",
        )


def _parse_jsonl(path: Path) -> list[dict[str, Any]]:
    """Parse a JSONL file into a list of record dicts.

    Args:
        path: Path to the JSONL file.

    Returns:
        List of parsed JSON objects.

    Raises:
        ACEFFormatError: If a line is not valid JSON.
    """
    records: list[dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as e:
                raise ACEFFormatError(
                    f"Malformed JSONL at {path}:{line_num}: {e}",
                    code="ACEF-050",
                ) from e
    return records


def load(path: str) -> Package:
    """Load an ACEF Evidence Bundle from a directory or archive.

    Args:
        path: Path to a bundle directory or .acef.tar.gz archive.

    Returns:
        A Package reconstructed from the bundle.

    Raises:
        ACEFFormatError: If the bundle is malformed.
        ACEFSchemaError: If the manifest is invalid.
    """
    bundle_path = Path(path)

    if bundle_path.suffix == ".gz" or str(bundle_path).endswith(".tar.gz"):
        return _load_archive(bundle_path)
    elif bundle_path.is_dir():
        return _load_directory(bundle_path)
    else:
        raise ACEFFormatError(f"Not a directory or .tar.gz archive: {path}")


def _load_archive(archive_path: Path) -> Package:
    """Load from a .acef.tar.gz archive.

    Raises:
        ACEFFormatError: If the archive is malformed, corrupt, or not a valid
            gzip/tar archive (ACEF-050).
    """
    if not archive_path.exists():
        raise ACEFFormatError(f"Archive not found: {archive_path}", code="ACEF-050")

    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            with tarfile.open(str(archive_path), "r:gz") as tar:
                _validate_tar_safety(tar)
                # C-SCOUT-1: filter="data" only available in Python 3.12+
                if sys.version_info >= (3, 12):
                    tar.extractall(tmpdir, filter="data")
                else:
                    tar.extractall(tmpdir)

            # Find the bundle root (first directory)
            extracted = list(Path(tmpdir).iterdir())
            if len(extracted) == 1 and extracted[0].is_dir():
                bundle_dir = extracted[0]
            else:
                bundle_dir = Path(tmpdir)

            return _load_directory(bundle_dir)

    except ACEFFormatError:
        raise
    except (tarfile.TarError, gzip.BadGzipFile, OSError) as e:
        raise ACEFFormatError(
            f"Malformed or corrupt archive: {archive_path}: {e}",
            code="ACEF-050",
        ) from e


def _load_directory(bundle_dir: Path) -> Package:
    """Load from a directory bundle."""
    manifest_path = bundle_dir / "acef-manifest.json"
    if not manifest_path.exists():
        raise ACEFFormatError(
            f"No acef-manifest.json found in {bundle_dir}",
            code="ACEF-002",
        )

    try:
        manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise ACEFFormatError(f"Invalid JSON in manifest: {e}", code="ACEF-050") from e

    # Parse manifest
    metadata_raw = manifest_data.get("metadata", {})
    producer_raw = metadata_raw.get("producer", {})
    producer = ProducerInfo(**producer_raw)

    retention_raw = metadata_raw.get("retention_policy")
    retention = RetentionPolicy(**retention_raw) if retention_raw else None

    # Build metadata
    metadata = PackageMetadata(
        producer=producer,
        retention_policy=retention,
        prior_package_ref=metadata_raw.get("prior_package_ref"),
    )
    metadata.package_id = metadata_raw.get("package_id", metadata.package_id)
    metadata.timestamp = metadata_raw.get("timestamp", metadata.timestamp)

    # Set versioning
    versioning_raw = manifest_data.get("versioning", {})
    versioning = Versioning(**versioning_raw)

    # Parse subjects
    subjects: list[Subject] = []
    for sub_data in manifest_data.get("subjects", []):
        timeline = [LifecycleEntry(**e) for e in sub_data.get("lifecycle_timeline", [])]
        subject = Subject(
            subject_id=sub_data.get("subject_id", ""),
            subject_type=sub_data.get("subject_type", "ai_system"),
            name=sub_data.get("name", ""),
            version=sub_data.get("version", "1.0.0"),
            provider=sub_data.get("provider", ""),
            risk_classification=sub_data.get("risk_classification", "minimal-risk"),
            modalities=sub_data.get("modalities", []),
            lifecycle_phase=sub_data.get("lifecycle_phase", "development"),
            lifecycle_timeline=timeline,
        )
        subjects.append(subject)

    # Parse entities
    entities_raw = manifest_data.get("entities", {})
    entities = EntitiesBlock()

    for comp_data in entities_raw.get("components", []):
        comp = Component(
            component_id=comp_data.get("component_id", ""),
            name=comp_data.get("name", ""),
            type=comp_data.get("type", "model"),
            version=comp_data.get("version", "1.0.0"),
            subject_refs=comp_data.get("subject_refs", []),
            provider=comp_data.get("provider", ""),
        )
        entities.components.append(comp)

    for ds_data in entities_raw.get("datasets", []):
        ds = Dataset(
            dataset_id=ds_data.get("dataset_id", ""),
            name=ds_data.get("name", ""),
            version=ds_data.get("version", "1.0.0"),
            source_type=ds_data.get("source_type", "licensed"),
            modality=ds_data.get("modality", "text"),
            size=ds_data.get("size", {"records": 0, "size_gb": 0.0}),
            subject_refs=ds_data.get("subject_refs", []),
        )
        entities.datasets.append(ds)

    for act_data in entities_raw.get("actors", []):
        actor = Actor(
            actor_id=act_data.get("actor_id", ""),
            role=act_data.get("role", "provider"),
            name=act_data.get("name", ""),
            organization=act_data.get("organization", ""),
        )
        entities.actors.append(actor)

    for rel_data in entities_raw.get("relationships", []):
        rel = Relationship(
            source_ref=rel_data.get("source_ref", ""),
            target_ref=rel_data.get("target_ref", ""),
            relationship_type=rel_data.get("relationship_type", "calls"),
            description=rel_data.get("description", ""),
        )
        entities.relationships.append(rel)

    # Parse profiles
    profiles: list[ProfileEntry] = []
    for prof_data in manifest_data.get("profiles", []):
        profiles.append(ProfileEntry(**prof_data))

    # Parse audit trail
    audit_trail: list[AuditTrailEntry] = []
    for at_data in manifest_data.get("audit_trail", []):
        audit_trail.append(AuditTrailEntry(**at_data))

    # Load records from JSONL files
    records: list[RecordEnvelope] = []
    for rf_entry in manifest_data.get("record_files", []):
        rf_path_str = rf_entry.get("path")
        if not rf_path_str:
            raise ACEFFormatError(
                "record_files entry missing 'path' field",
                code="ACEF-050",
            )
        _validate_path(rf_path_str)
        rf_path = bundle_dir / rf_path_str
        # M-IMPL-2: Raise error when manifest-listed record files are missing
        if not rf_path.exists():
            raise ACEFFormatError(
                f"Record file listed in manifest but not found on disk: {rf_entry['path']}",
                code="ACEF-022",
            )
        records_data = _parse_jsonl(rf_path)
        for rec_data in records_data:
            records.append(dict_to_record_envelope(rec_data))

    # Load attachments with size guards (M-SCOUT-5, m8 Scout R2)
    attachments: dict[str, bytes] = {}
    artifacts_dir = bundle_dir / "artifacts"
    if artifacts_dir.exists():
        cumulative_artifact_size = 0
        for file_path in artifacts_dir.rglob("*"):
            if file_path.is_file():
                file_size = file_path.stat().st_size
                if file_size > _MAX_ARTIFACT_FILE_SIZE:
                    raise ACEFFormatError(
                        f"Artifact file exceeds 1 GB limit: "
                        f"{file_path.relative_to(bundle_dir).as_posix()} "
                        f"({file_size} bytes)",
                        code="ACEF-050",
                    )
                cumulative_artifact_size += file_size
                if cumulative_artifact_size > _MAX_TOTAL_ARTIFACT_SIZE:
                    raise ACEFFormatError(
                        f"Cumulative artifact size exceeds 10 GB limit: "
                        f"{cumulative_artifact_size} bytes",
                        code="ACEF-050",
                    )
                rel = file_path.relative_to(bundle_dir).as_posix()
                attachments[rel] = file_path.read_bytes()

    # Construct Package via the public classmethod (M-ARCH-1)
    return Package._init_from_parts(
        metadata=metadata,
        versioning=versioning,
        subjects=subjects,
        entities=entities,
        profiles=profiles,
        records=records,
        audit_trail=audit_trail,
        attachments=attachments,
    )
