"""ACEF merge module — multi-source evidence merging with conflict detection.

Merges evidence from multiple ACEF packages into a single package.
Detects and reports conflicts per ACEF-060.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from acef.errors import ACEFMergeError, ValidationDiagnostic
from acef.models.entities import EntitiesBlock
from acef.models.enums import AuditEventType
from acef.models.manifest import AuditTrailEntry, ProfileEntry
from acef.models.metadata import PackageMetadata, ProducerInfo, Versioning
from acef.models.records import RecordEnvelope
from acef.models.subjects import Subject
from acef.package import Package


class MergeResult:
    """Result of a package merge operation."""

    def __init__(self, package: Package, conflicts: list[ValidationDiagnostic]) -> None:
        self.package = package
        self.conflicts = conflicts

    @property
    def has_conflicts(self) -> bool:
        return len(self.conflicts) > 0


def _timestamp_is_newer_or_equal(new_ts: str, old_ts: str) -> bool:
    """Compare two ISO 8601 timestamps, returning True if new >= old.

    Uses proper datetime parsing. Raises ACEFMergeError if either timestamp
    fails to parse, rather than falling back to lexicographic comparison
    which would produce nonsense results for malformed timestamps.

    Args:
        new_ts: The candidate newer timestamp.
        old_ts: The candidate older timestamp.

    Returns:
        True if new_ts is newer than or equal to old_ts.

    Raises:
        ACEFMergeError: If either timestamp cannot be parsed as ISO 8601.
    """
    try:
        new_dt = datetime.fromisoformat(new_ts.replace("Z", "+00:00"))
        old_dt = datetime.fromisoformat(old_ts.replace("Z", "+00:00"))
        return new_dt >= old_dt
    except (ValueError, AttributeError):
        raise ACEFMergeError(
            f"Cannot compare timestamps for keep_latest: {new_ts!r} vs {old_ts!r}",
            code="ACEF-060",
        )


def merge_packages(
    packages: list[Package],
    *,
    producer: dict[str, str] | None = None,
    conflict_strategy: str = "keep_latest",
) -> MergeResult:
    """Merge multiple ACEF packages into one.

    Accumulates all data in local collections, then constructs the merged
    package via Package._init_from_parts() to avoid reaching into private
    attributes (M-R2-2).

    Args:
        packages: List of packages to merge.
        producer: Producer info for the merged package.
        conflict_strategy: How to handle conflicts:
            - 'keep_latest': Keep the record with the latest timestamp
            - 'keep_all': Keep all records (may have duplicates)
            - 'fail': Raise on any conflict

    Returns:
        A MergeResult with the merged package and any conflicts.

    Raises:
        ACEFMergeError: If no packages are provided, or if conflict_strategy
            is 'fail' and a conflict is detected, or if an unknown strategy
            is used.
    """
    if not packages:
        raise ACEFMergeError("No packages to merge", code="ACEF-060")

    # Validate conflict strategy
    valid_strategies = {"keep_latest", "keep_all", "fail"}
    if conflict_strategy not in valid_strategies:
        raise ACEFMergeError(
            f"Unknown conflict_strategy: {conflict_strategy!r}. "
            f"Must be one of: {', '.join(sorted(valid_strategies))}",
            code="ACEF-060",
        )

    if producer is None:
        producer = {"name": "acef-merger", "version": "0.1.0"}

    conflicts: list[ValidationDiagnostic] = []

    # Pre-build a lookup for package timestamps (N-R2-3: avoid O(n) scan per duplicate)
    pkg_timestamps: dict[str, str] = {
        pkg.metadata.package_id: pkg.metadata.timestamp for pkg in packages
    }

    # Accumulate all data in local collections
    merged_subjects: list[Subject] = []
    merged_entities = EntitiesBlock()
    merged_profiles: list[ProfileEntry] = []
    merged_records: list[RecordEnvelope] = []
    merged_attachments: dict[str, bytes] = {}

    # Track what we've seen for conflict detection
    seen_subjects: dict[str, tuple[str, Any]] = {}  # name+type -> (pkg_id, subject)
    seen_entities: dict[str, str] = {}  # entity_id -> pkg_id
    # For records: track record_id -> (pkg_id, record) so we can compare timestamps
    seen_records: dict[str, tuple[str, RecordEnvelope]] = {}

    for pkg in packages:
        pkg_id = pkg.metadata.package_id

        # Merge subjects (using public .subjects property)
        for subject in pkg.subjects:
            key = f"{subject.name}:{subject.subject_type.value}"
            if key in seen_subjects:
                conflicts.append(
                    ValidationDiagnostic(
                        "ACEF-060",
                        f"Duplicate subject {key!r} from packages "
                        f"{seen_subjects[key][0]} and {pkg_id}",
                    )
                )
                if conflict_strategy == "fail":
                    raise ACEFMergeError(f"Conflict: duplicate subject {key!r}", code="ACEF-060")
                elif conflict_strategy == "keep_latest":
                    old_pkg_id = seen_subjects[key][0]
                    old_pkg_ts = pkg_timestamps.get(old_pkg_id, "")
                    new_pkg_ts = pkg.metadata.timestamp
                    if _timestamp_is_newer_or_equal(new_pkg_ts, old_pkg_ts):
                        # New package is same age or newer — replace
                        merged_subjects = [
                            s for s in merged_subjects
                            if not (s.name == subject.name
                                    and s.subject_type == subject.subject_type)
                        ]
                        seen_subjects[key] = (pkg_id, subject)
                        merged_subjects.append(subject.model_copy(deep=True))
                    # else: old is newer, keep it (already in merged_subjects)
                elif conflict_strategy == "keep_all":
                    merged_subjects.append(subject.model_copy(deep=True))
            else:
                seen_subjects[key] = (pkg_id, subject)
                merged_subjects.append(subject.model_copy(deep=True))

        # Merge entities (using public .entities property)
        for comp in pkg.entities.components:
            if comp.component_id not in seen_entities:
                seen_entities[comp.component_id] = pkg_id
                merged_entities.components.append(comp.model_copy(deep=True))

        for ds in pkg.entities.datasets:
            if ds.dataset_id not in seen_entities:
                seen_entities[ds.dataset_id] = pkg_id
                merged_entities.datasets.append(ds.model_copy(deep=True))

        for actor in pkg.entities.actors:
            if actor.actor_id not in seen_entities:
                seen_entities[actor.actor_id] = pkg_id
                merged_entities.actors.append(actor.model_copy(deep=True))

        for rel in pkg.entities.relationships:
            merged_entities.relationships.append(rel.model_copy(deep=True))

        # Merge profiles (using public .profiles property, deduplicate by profile_id)
        existing_profile_ids = {p.profile_id for p in merged_profiles}
        for profile in pkg.profiles:
            if profile.profile_id not in existing_profile_ids:
                merged_profiles.append(profile.model_copy(deep=True))
                existing_profile_ids.add(profile.profile_id)

        # Merge records (using public .records property)
        for record in pkg.records:
            if record.record_id in seen_records:
                conflicts.append(
                    ValidationDiagnostic(
                        "ACEF-060",
                        f"Duplicate record_id: {record.record_id!r}",
                    )
                )
                if conflict_strategy == "fail":
                    raise ACEFMergeError(
                        f"Conflict: duplicate record {record.record_id!r}",
                        code="ACEF-060",
                    )
                elif conflict_strategy == "keep_latest":
                    old_pkg_id, old_record = seen_records[record.record_id]
                    if _timestamp_is_newer_or_equal(record.timestamp, old_record.timestamp):
                        # New record is same age or newer — replace
                        merged_records = [
                            r for r in merged_records
                            if r.record_id != record.record_id
                        ]
                        seen_records[record.record_id] = (pkg_id, record)
                        merged_records.append(record.model_copy(deep=True))
                    # else: old record is newer, keep it
                elif conflict_strategy == "keep_all":
                    merged_records.append(record.model_copy(deep=True))
            else:
                seen_records[record.record_id] = (pkg_id, record)
                merged_records.append(record.model_copy(deep=True))

        # Merge attachments (using public .attachments property)
        for att_path, content in pkg.attachments.items():
            if att_path not in merged_attachments:
                merged_attachments[att_path] = content

    # Build the merge audit trail entry
    # Use first package's metadata as base for the merged metadata
    merged_metadata = PackageMetadata(
        producer=ProducerInfo(**producer),
    )

    merge_audit_trail = [
        AuditTrailEntry(
            event_type=AuditEventType.CREATED,
            timestamp=merged_metadata.timestamp,
            description="Initial package creation",
        ),
        AuditTrailEntry(
            event_type=AuditEventType.UPDATED,
            timestamp=merged_metadata.timestamp,
            description=f"Merged from {len(packages)} packages",
        ),
    ]

    # Construct merged package via _init_from_parts (M-R2-2)
    merged = Package._init_from_parts(
        metadata=merged_metadata,
        versioning=Versioning(),
        subjects=merged_subjects,
        entities=merged_entities,
        profiles=merged_profiles,
        records=merged_records,
        audit_trail=merge_audit_trail,
        attachments=merged_attachments,
    )

    return MergeResult(merged, conflicts)
