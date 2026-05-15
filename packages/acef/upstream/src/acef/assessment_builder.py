"""ACEF Assessment Builder — Assessment Bundle creation, signing, and export.

Renamed from assessment.py per eng review to prevent import confusion
with models/assessment.py.
"""

from __future__ import annotations

from pathlib import Path

from acef.integrity import canonicalize
from acef.models.assessment import AssessmentBundle
from acef.package import Package
from acef.validation.engine import validate_bundle


def validate(
    package_or_path: Package | str | Path,
    *,
    profiles: list[str] | None = None,
    evaluation_instant: str | None = None,
) -> AssessmentBundle:
    """Validate a package or bundle and produce an Assessment Bundle.

    This is the top-level validation API.

    Args:
        package_or_path: A Package object or path to a bundle directory/archive.
        profiles: List of profile IDs to evaluate.
        evaluation_instant: Override evaluation timestamp (ISO 8601).

    Returns:
        An AssessmentBundle with all results.
    """
    import tempfile

    if isinstance(package_or_path, Package):
        # Export to temp dir, then validate
        with tempfile.TemporaryDirectory() as tmpdir:
            bundle_dir = Path(tmpdir) / "bundle.acef"
            package_or_path.export(str(bundle_dir))
            return validate_bundle(
                bundle_dir,
                profiles=profiles,
                evaluation_instant=evaluation_instant,
            )
    else:
        path = Path(package_or_path)
        if path.suffix == ".gz" or str(path).endswith(".tar.gz"):
            # Extract archive first
            from acef.loader import load

            pkg = load(str(path))
            with tempfile.TemporaryDirectory() as tmpdir:
                bundle_dir = Path(tmpdir) / "bundle.acef"
                pkg.export(str(bundle_dir))
                return validate_bundle(
                    bundle_dir,
                    profiles=profiles,
                    evaluation_instant=evaluation_instant,
                )
        else:
            return validate_bundle(
                path,
                profiles=profiles,
                evaluation_instant=evaluation_instant,
            )


def export_assessment(
    assessment: AssessmentBundle,
    output_path: str,
    *,
    key_path: str | None = None,
) -> Path:
    """Export an Assessment Bundle to a JSON file.

    Args:
        assessment: The AssessmentBundle to export.
        output_path: Path to the output .acef-assessment.json file.
        key_path: Optional path to private key for signing.

    Returns:
        Path to the created file.
    """
    data = assessment.to_dict()

    if key_path:
        from acef.signing import sign_assessment

        data = sign_assessment(data, key_path)

    canonical = canonicalize(data)
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(canonical)

    return output
