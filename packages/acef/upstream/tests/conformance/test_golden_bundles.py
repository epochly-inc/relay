"""Conformance test: Golden bundle validation.

Section 6.5/6.6: Validates all published golden bundles in
tests/conformance/golden-bundles/ by loading each one and running
the full validation pipeline. Verifies that:
1. Each golden bundle loads without errors
2. Validation produces an assessment bundle
3. Provision summaries are present and match fixtures
4. Profiles are evaluated and match fixtures
5. Every provision_outcome matches between fixture and runtime
6. Passed/failed/skipped counts match between fixture and runtime
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from acef.loader import load
from acef.validation.engine import validate_bundle

# Location of golden bundles relative to this file
GOLDEN_BUNDLES_DIR = Path(__file__).parent / "golden-bundles"

# All 6 golden bundle directories
GOLDEN_BUNDLE_NAMES = [
    "china-cac-labeling",
    "eu-high-risk-core",
    "gpai-provider-annex-xi-xii",
    "multi-subject-composed",
    "synthetic-content-marking",
    "us-federal-governance",
]


def _get_golden_bundle_profiles(bundle_name: str) -> list[str]:
    """Read the profile IDs declared in a golden bundle's manifest."""
    manifest_path = GOLDEN_BUNDLES_DIR / bundle_name / "acef-manifest.json"
    manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
    return [p["profile_id"] for p in manifest_data.get("profiles", [])]


def _load_fixture(bundle_name: str) -> dict[str, Any]:
    """Load the published assessment fixture for a golden bundle."""
    fixture_path = GOLDEN_BUNDLES_DIR / f"{bundle_name}.acef-assessment.json"
    return json.loads(fixture_path.read_text(encoding="utf-8"))


class TestGoldenBundleLoading:
    """Each golden bundle loads without errors."""

    @pytest.mark.parametrize("bundle_name", GOLDEN_BUNDLE_NAMES)
    def test_golden_bundle_loads_successfully(self, bundle_name: str) -> None:
        """Load each golden bundle via acef.loader.load and verify basic structure."""
        bundle_dir = GOLDEN_BUNDLES_DIR / bundle_name
        assert bundle_dir.exists(), f"Golden bundle directory not found: {bundle_name}"

        pkg = load(str(bundle_dir))

        # Verify it loaded a valid Package
        assert pkg is not None
        assert pkg.metadata is not None
        assert pkg.metadata.package_id.startswith("urn:acef:pkg:")
        assert len(pkg.subjects) > 0, f"Golden bundle {bundle_name} should have at least one subject"
        assert len(pkg.records) > 0, f"Golden bundle {bundle_name} should have at least one record"


class TestGoldenBundleValidation:
    """Each golden bundle produces a valid assessment with provision summaries."""

    @pytest.mark.parametrize("bundle_name", GOLDEN_BUNDLE_NAMES)
    def test_golden_bundle_validates(self, bundle_name: str) -> None:
        """Run validate_bundle on each golden bundle and check assessment correctness."""
        bundle_dir = GOLDEN_BUNDLES_DIR / bundle_name
        assert bundle_dir.exists()

        profiles = _get_golden_bundle_profiles(bundle_name)
        assert len(profiles) > 0, f"Golden bundle {bundle_name} should declare at least one profile"

        # Use the fixture's evaluation_instant for consistency
        fixture = _load_fixture(bundle_name)
        evaluation_instant = fixture["evaluation_instant"]

        assessment = validate_bundle(
            bundle_dir,
            profiles=profiles,
            evaluation_instant=evaluation_instant,
        )

        # Assessment must be produced
        assert assessment is not None

        # Provision summaries must be present (this proves the validation pipeline ran
        # through all 4 phases and produced meaningful results)
        assert len(assessment.provision_summary) > 0, (
            f"Golden bundle {bundle_name} should produce provision summaries"
        )

        # Profiles must be evaluated
        assert len(assessment.profiles_evaluated) > 0, (
            f"Golden bundle {bundle_name} should have evaluated profiles"
        )

        # Results must be produced (individual rule evaluations)
        assert len(assessment.results) > 0, (
            f"Golden bundle {bundle_name} should have rule evaluation results"
        )


class TestGoldenBundleAssessmentFixtures:
    """Compare runtime assessment against published assessment fixtures.

    Per spec Section 6.5/6.6, the runtime assessment must produce the same
    provision outcomes and rule result counts as the published fixtures.
    Uses the fixture's evaluation_instant to ensure deterministic comparison.
    """

    @pytest.mark.parametrize("bundle_name", GOLDEN_BUNDLE_NAMES)
    def test_assessment_fixture_exists(self, bundle_name: str) -> None:
        """Each golden bundle has a corresponding .acef-assessment.json fixture."""
        fixture_path = GOLDEN_BUNDLES_DIR / f"{bundle_name}.acef-assessment.json"
        assert fixture_path.exists(), (
            f"Missing assessment fixture for golden bundle {bundle_name}"
        )

    @pytest.mark.parametrize("bundle_name", GOLDEN_BUNDLE_NAMES)
    def test_fixture_has_provision_summaries(self, bundle_name: str) -> None:
        """Each assessment fixture contains provision summaries."""
        fixture = _load_fixture(bundle_name)

        assert "provision_summary" in fixture, (
            f"Assessment fixture for {bundle_name} missing provision_summary"
        )
        assert len(fixture["provision_summary"]) > 0, (
            f"Assessment fixture for {bundle_name} has empty provision_summary"
        )

    @pytest.mark.parametrize("bundle_name", GOLDEN_BUNDLE_NAMES)
    def test_runtime_produces_same_profiles_as_fixture(self, bundle_name: str) -> None:
        """Runtime assessment evaluates the same profiles as the published fixture."""
        bundle_dir = GOLDEN_BUNDLES_DIR / bundle_name
        fixture = _load_fixture(bundle_name)
        fixture_profiles = set(fixture.get("profiles_evaluated", []))
        evaluation_instant = fixture["evaluation_instant"]

        profiles = _get_golden_bundle_profiles(bundle_name)
        assessment = validate_bundle(
            bundle_dir,
            profiles=profiles,
            evaluation_instant=evaluation_instant,
        )

        runtime_profiles = set(assessment.profiles_evaluated)
        assert runtime_profiles == fixture_profiles, (
            f"Profile mismatch for {bundle_name}: "
            f"runtime={runtime_profiles} fixture={fixture_profiles}"
        )

    @pytest.mark.parametrize("bundle_name", GOLDEN_BUNDLE_NAMES)
    def test_runtime_provision_count_matches_fixture(self, bundle_name: str) -> None:
        """Runtime assessment produces the same number of provision summaries as fixture."""
        bundle_dir = GOLDEN_BUNDLES_DIR / bundle_name
        fixture = _load_fixture(bundle_name)
        fixture_count = len(fixture.get("provision_summary", []))
        evaluation_instant = fixture["evaluation_instant"]

        profiles = _get_golden_bundle_profiles(bundle_name)
        assessment = validate_bundle(
            bundle_dir,
            profiles=profiles,
            evaluation_instant=evaluation_instant,
        )

        runtime_count = len(assessment.provision_summary)
        assert runtime_count == fixture_count, (
            f"Provision summary count mismatch for {bundle_name}: "
            f"runtime={runtime_count} fixture={fixture_count}"
        )

    @pytest.mark.parametrize("bundle_name", GOLDEN_BUNDLE_NAMES)
    def test_provision_outcomes_match_fixture(self, bundle_name: str) -> None:
        """Every provision_summary entry's provision_outcome matches between fixture and runtime.

        This is the key Section 6.5/6.6 conformance check: given the same evidence
        bundle and evaluation_instant, the validator must produce identical provision
        outcomes as the published fixture.
        """
        bundle_dir = GOLDEN_BUNDLES_DIR / bundle_name
        fixture = _load_fixture(bundle_name)
        evaluation_instant = fixture["evaluation_instant"]

        profiles = _get_golden_bundle_profiles(bundle_name)
        assessment = validate_bundle(
            bundle_dir,
            profiles=profiles,
            evaluation_instant=evaluation_instant,
        )

        # Build lookup from fixture: (profile_id, provision_id) -> provision_outcome
        fixture_outcomes: dict[tuple[str, str], str] = {}
        for ps in fixture.get("provision_summary", []):
            key = (ps["profile_id"], ps["provision_id"])
            fixture_outcomes[key] = ps["provision_outcome"]

        # Build lookup from runtime
        runtime_outcomes: dict[tuple[str, str], str] = {}
        for ps in assessment.provision_summary:
            key = (ps.profile_id, ps.provision_id)
            runtime_outcomes[key] = ps.provision_outcome.value

        # Every fixture provision must exist in runtime with the same outcome
        for key, expected_outcome in fixture_outcomes.items():
            assert key in runtime_outcomes, (
                f"[{bundle_name}] Fixture provision {key} not found in runtime assessment"
            )
            actual_outcome = runtime_outcomes[key]
            assert actual_outcome == expected_outcome, (
                f"[{bundle_name}] Provision {key}: "
                f"expected outcome={expected_outcome!r}, got={actual_outcome!r}"
            )

        # Every runtime provision must exist in fixture (no spurious provisions)
        for key in runtime_outcomes:
            assert key in fixture_outcomes, (
                f"[{bundle_name}] Runtime provision {key} not found in fixture"
            )

    @pytest.mark.parametrize("bundle_name", GOLDEN_BUNDLE_NAMES)
    def test_rule_result_counts_match_fixture(self, bundle_name: str) -> None:
        """The count of passed/failed/skipped rule results matches between fixture and runtime.

        Verifies that the validation engine produces the same number of individual
        rule results in each outcome category as the published fixture.
        """
        bundle_dir = GOLDEN_BUNDLES_DIR / bundle_name
        fixture = _load_fixture(bundle_name)
        evaluation_instant = fixture["evaluation_instant"]

        profiles = _get_golden_bundle_profiles(bundle_name)
        assessment = validate_bundle(
            bundle_dir,
            profiles=profiles,
            evaluation_instant=evaluation_instant,
        )

        # Count fixture results by outcome
        fixture_results = fixture.get("results", [])
        fixture_counts: dict[str, int] = {}
        for r in fixture_results:
            outcome = r.get("outcome", "unknown")
            fixture_counts[outcome] = fixture_counts.get(outcome, 0) + 1

        # Count runtime results by outcome
        runtime_counts: dict[str, int] = {}
        for r in assessment.results:
            outcome = r.outcome.value
            runtime_counts[outcome] = runtime_counts.get(outcome, 0) + 1

        # Total result count must match
        assert len(assessment.results) == len(fixture_results), (
            f"[{bundle_name}] Total rule result count mismatch: "
            f"runtime={len(assessment.results)} fixture={len(fixture_results)}"
        )

        # Per-outcome counts must match
        all_outcomes = set(fixture_counts.keys()) | set(runtime_counts.keys())
        for outcome in sorted(all_outcomes):
            fixture_n = fixture_counts.get(outcome, 0)
            runtime_n = runtime_counts.get(outcome, 0)
            assert runtime_n == fixture_n, (
                f"[{bundle_name}] Rule result count for outcome={outcome!r}: "
                f"runtime={runtime_n} fixture={fixture_n}"
            )
