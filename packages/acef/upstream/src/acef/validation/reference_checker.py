"""ACEF reference checker — dangling refs, duplicates, file existence.

Phase 3 of the 4-phase validation pipeline.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from acef.errors import ValidationDiagnostic


def check_references(
    manifest_data: dict[str, Any],
    records: list[dict[str, Any]],
    bundle_dir: Path | None = None,
) -> list[ValidationDiagnostic]:
    """Check referential integrity of a bundle.

    Checks:
    - Dangling entity_refs (ACEF-020)
    - Duplicate URNs (ACEF-021)
    - Missing record files (ACEF-022)
    - Missing attachment files (ACEF-023)
    - Record count mismatches (ACEF-025)
    - Duplicate record IDs (ACEF-026)

    Returns:
        List of diagnostics.
    """
    diagnostics: list[ValidationDiagnostic] = []

    # Collect all defined URNs
    defined_urns: set[str] = set()
    urn_sources: dict[str, str] = {}  # urn -> first source path

    # Package ID
    pkg_id = manifest_data.get("metadata", {}).get("package_id", "")
    if pkg_id:
        _add_urn(defined_urns, urn_sources, pkg_id, "/metadata/package_id", diagnostics)

    # Subject URNs
    for i, sub in enumerate(manifest_data.get("subjects", [])):
        sub_id = sub.get("subject_id", "")
        if sub_id:
            _add_urn(defined_urns, urn_sources, sub_id, f"/subjects/{i}/subject_id", diagnostics)

    # Entity URNs
    entities = manifest_data.get("entities", {})
    for i, comp in enumerate(entities.get("components", [])):
        comp_id = comp.get("component_id", "")
        if comp_id:
            _add_urn(defined_urns, urn_sources, comp_id, f"/entities/components/{i}", diagnostics)

    for i, ds in enumerate(entities.get("datasets", [])):
        ds_id = ds.get("dataset_id", "")
        if ds_id:
            _add_urn(defined_urns, urn_sources, ds_id, f"/entities/datasets/{i}", diagnostics)

    for i, actor in enumerate(entities.get("actors", [])):
        act_id = actor.get("actor_id", "")
        if act_id:
            _add_urn(defined_urns, urn_sources, act_id, f"/entities/actors/{i}", diagnostics)

    # Check relationship refs
    for i, rel in enumerate(entities.get("relationships", [])):
        for ref_field in ("source_ref", "target_ref"):
            ref = rel.get(ref_field, "")
            if ref and ref not in defined_urns:
                diagnostics.append(
                    ValidationDiagnostic(
                        "ACEF-020",
                        f"Dangling {ref_field} in relationship {i}: {ref!r}",
                        path=f"/entities/relationships/{i}/{ref_field}",
                    )
                )

    # Pre-load content-hashes.json once for ACEF-027 advisory hash checks,
    # rather than re-reading from disk on every record iteration.
    content_hashes: dict[str, str] = {}
    if bundle_dir:
        ch_path = bundle_dir / "hashes" / "content-hashes.json"
        if ch_path.exists():
            try:
                content_hashes = json.loads(ch_path.read_text(encoding="utf-8"))
            except Exception:
                pass

    # Check record entity refs
    record_ids: set[str] = set()
    for i, rec in enumerate(records):
        rec_id = rec.get("record_id", "")
        if rec_id:
            if rec_id in record_ids:
                diagnostics.append(
                    ValidationDiagnostic(
                        "ACEF-026",
                        f"Duplicate record_id: {rec_id!r}",
                        path=f"/records/{i}/record_id",
                    )
                )
            record_ids.add(rec_id)

        entity_refs = rec.get("entity_refs", {})
        for ref_type in ("subject_refs", "component_refs", "dataset_refs", "actor_refs"):
            for ref in entity_refs.get(ref_type, []):
                if ref and ref not in defined_urns:
                    diagnostics.append(
                        ValidationDiagnostic(
                            "ACEF-020",
                            f"Dangling {ref_type} in record {i}: {ref!r}",
                            path=f"/records/{i}/entity_refs/{ref_type}",
                        )
                    )

        # Check attachment paths and advisory hash (ACEF-027)
        if bundle_dir:
            for j, att in enumerate(rec.get("attachments", [])):
                att_path = att.get("path", "")
                if att_path:
                    full_path = bundle_dir / att_path
                    if not full_path.exists():
                        diagnostics.append(
                            ValidationDiagnostic(
                                "ACEF-023",
                                f"Attachment file not found: {att_path!r}",
                                path=f"/records/{i}/attachments/{j}/path",
                            )
                        )
                    # ACEF-027: Advisory hash mismatch check
                    att_hash = att.get("hash", "")
                    if att_hash and att_path in content_hashes:
                        if att_hash != content_hashes[att_path]:
                            diagnostics.append(
                                ValidationDiagnostic(
                                    "ACEF-027",
                                    f"Attachment hash field does not match content-hashes.json "
                                    f"for {att_path!r}",
                                    path=f"/records/{i}/attachments/{j}/hash",
                                )
                            )

    # Check record_files entries
    if bundle_dir:
        for i, rf in enumerate(manifest_data.get("record_files", [])):
            rf_path = rf.get("path", "")
            if rf_path:
                full_path = bundle_dir / rf_path
                if not full_path.exists():
                    diagnostics.append(
                        ValidationDiagnostic(
                            "ACEF-022",
                            f"Record file not found: {rf_path!r}",
                            path=f"/record_files/{i}/path",
                        )
                    )

    # Check record counts
    _check_record_counts(manifest_data, records, diagnostics)

    # Check subject_refs on components and datasets
    for i, comp in enumerate(entities.get("components", [])):
        for ref in comp.get("subject_refs", []):
            if ref and ref not in defined_urns:
                diagnostics.append(
                    ValidationDiagnostic(
                        "ACEF-020",
                        f"Dangling subject_ref in component {i}: {ref!r}",
                        path=f"/entities/components/{i}/subject_refs",
                    )
                )

    for i, ds in enumerate(entities.get("datasets", [])):
        for ref in ds.get("subject_refs", []):
            if ref and ref not in defined_urns:
                diagnostics.append(
                    ValidationDiagnostic(
                        "ACEF-020",
                        f"Dangling subject_ref in dataset {i}: {ref!r}",
                        path=f"/entities/datasets/{i}/subject_refs",
                    )
                )

    return diagnostics


def _add_urn(
    defined: set[str],
    sources: dict[str, str],
    urn: str,
    path: str,
    diagnostics: list[ValidationDiagnostic],
) -> None:
    """Add a URN to the defined set, checking for duplicates."""
    if urn in defined:
        diagnostics.append(
            ValidationDiagnostic(
                "ACEF-021",
                f"Duplicate URN: {urn!r} (first defined at {sources.get(urn, 'unknown')})",
                path=path,
            )
        )
    defined.add(urn)
    if urn not in sources:
        sources[urn] = path


def _check_record_counts(
    manifest_data: dict[str, Any],
    records: list[dict[str, Any]],
    diagnostics: list[ValidationDiagnostic],
) -> None:
    """Check that record_files counts match actual record counts."""
    # Count records by type
    actual_counts: dict[str, int] = {}
    for rec in records:
        rt = rec.get("record_type", "")
        actual_counts[rt] = actual_counts.get(rt, 0) + 1

    # Sum expected counts from record_files
    expected_counts: dict[str, int] = {}
    for rf in manifest_data.get("record_files", []):
        rt = rf.get("record_type", "")
        expected_counts[rt] = expected_counts.get(rt, 0) + rf.get("count", 0)

    for rt, expected in expected_counts.items():
        actual = actual_counts.get(rt, 0)
        if actual != expected:
            diagnostics.append(
                ValidationDiagnostic(
                    "ACEF-025",
                    f"Record count mismatch for {rt}: manifest says {expected}, found {actual}",
                )
            )
