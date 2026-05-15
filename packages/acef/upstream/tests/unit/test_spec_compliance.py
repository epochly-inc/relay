"""Tests for spec compliance fixes — assessment versioning, evaluation_scope,
gzip OS byte, modalities scope, ACEF-027, chain(), sign()/verify()."""

from __future__ import annotations

import gzip
import json
import tempfile
from pathlib import Path

import pytest

import acef
from acef.models.assessment import AssessmentBundle, AssessmentVersioning
from acef.package import Package


class TestAssessmentVersioning:
    """CG-1: Assessment Bundle must use assessment_version, not profiles_version."""

    def test_assessment_bundle_has_assessment_version(self) -> None:
        assessment = AssessmentBundle()
        data = assessment.to_dict()
        assert "assessment_version" in data["versioning"]
        assert "profiles_version" not in data["versioning"]

    def test_assessment_versioning_model(self) -> None:
        v = AssessmentVersioning()
        assert v.core_version == "1.0.0"
        assert v.assessment_version == "1.0.0"

    def test_validate_produces_assessment_version(self, minimal_package: Package) -> None:
        assessment = acef.validate(minimal_package)
        data = assessment.to_dict()
        assert "assessment_version" in data["versioning"]
        assert data["versioning"]["assessment_version"] == "1.0.0"


class TestEvaluationScopePackage:
    """CG-2: evaluation_scope='package' should evaluate provision once, not per-subject."""

    def test_package_scope_evaluated_once(self, tmp_dir: Path) -> None:
        """A package-scoped provision produces one summary entry, not one per subject."""
        from acef.templates.models import EvaluationRule, Provision, Template
        from acef.templates.registry import _get_template_dir

        # Create a temporary template with a package-scoped provision
        template_data = {
            "template_id": "test-pkg-scope",
            "template_name": "Test Package Scope",
            "version": "1.0.0",
            "jurisdiction": "TEST",
            "instrument_type": "standard",
            "legal_force": "voluntary",
            "instrument_status": "final",
            "applicable_system_types": [],
            "provisions": [
                {
                    "provision_id": "pkg-gov",
                    "provision_name": "Package Governance",
                    "evaluation_scope": "package",
                    "required_evidence_types": ["governance_policy"],
                    "evaluation": [
                        {
                            "rule_id": "pkg-gov-exists",
                            "rule": "has_record_type",
                            "params": {"type": "governance_policy", "min_count": 1},
                            "severity": "fail",
                            "message": "Governance policy required"
                        }
                    ]
                }
            ]
        }

        # Write temp template
        template_dir = _get_template_dir()
        template_file = template_dir / "test-pkg-scope.json"
        template_file.write_text(json.dumps(template_data))

        try:
            # Create package with 2 subjects + governance_policy record
            pkg = Package(producer={"name": "test", "version": "1.0"})
            s1 = pkg.add_subject("ai_system", name="System A")
            s2 = pkg.add_subject("ai_model", name="Model B")
            pkg.add_profile("test-pkg-scope")
            pkg.record("governance_policy", payload={"policy_type": "ai_governance"})

            assessment = acef.validate(pkg, profiles=["test-pkg-scope"])

            # Package-scoped provision should produce exactly 1 summary, not 2
            pkg_summaries = [
                ps for ps in assessment.provision_summary
                if ps.provision_id == "pkg-gov"
            ]
            assert len(pkg_summaries) == 1
            # Should have empty subject_scope (package-level)
            assert pkg_summaries[0].subject_scope == []
        finally:
            template_file.unlink(missing_ok=True)
            # Clear template cache
            from acef.templates.registry import load_template
            load_template.cache_clear()


class TestGzipOSByte:
    """CG-4: gzip header OS byte must be 0xFF."""

    def test_archive_os_byte_is_0xff(self, minimal_package: Package, tmp_dir: Path) -> None:
        archive_path = tmp_dir / "test.acef.tar.gz"
        minimal_package.export(str(archive_path))

        with open(archive_path, "rb") as f:
            header = f.read(10)
            # Gzip header: bytes[0:2]=magic, [9]=OS
            assert header[0:2] == b"\x1f\x8b"  # gzip magic
            assert header[9] == 0xFF  # OS byte must be 0xFF per spec


class TestNoWallClockFallback:
    """MG-5: evidence_freshness must not use wall-clock time."""

    def test_no_evaluation_instant_returns_pass(self) -> None:
        from acef.models.records import RecordEnvelope
        from acef.validation.operators import op_evidence_freshness

        records = [RecordEnvelope(record_type="risk_register", payload={})]
        # No evaluation_instant provided — should NOT use wall-clock
        passed, _ = op_evidence_freshness(
            {"max_days": 365},
            records,
            evaluation_instant="",
            package_timestamp="",
        )
        # Returns True (pass) when no reference date available, rather than
        # falling back to wall-clock time
        assert passed


class TestModalitiesScopeFilter:
    """MG-4: modalities scope filter must be checked."""

    def test_modalities_filter_excludes_non_matching(self) -> None:
        from acef.models.records import RecordEnvelope
        from acef.validation.rule_engine import _matches_scope

        record = RecordEnvelope(record_type="risk_register", payload={})
        scope = {"modalities": ["image", "video"]}

        # Text-only subject should not match image/video scope
        assert not _matches_scope(record, scope, subject_modalities=["text"])

    def test_modalities_filter_includes_matching(self) -> None:
        from acef.models.records import RecordEnvelope
        from acef.validation.rule_engine import _matches_scope

        record = RecordEnvelope(record_type="risk_register", payload={})
        scope = {"modalities": ["text", "image"]}

        assert _matches_scope(record, scope, subject_modalities=["text"])

    def test_no_modalities_scope_matches_all(self) -> None:
        from acef.models.enums import ObligationRole
        from acef.models.records import RecordEnvelope
        from acef.validation.rule_engine import _matches_scope

        record = RecordEnvelope(
            record_type="risk_register", payload={},
            obligation_role=ObligationRole.PROVIDER,
        )
        scope = {"obligation_roles": ["provider"]}

        # No modalities in scope — should match regardless of subject modalities
        assert _matches_scope(record, scope, subject_modalities=["text"])


class TestChainFunction:
    """MG-14: acef.chain() convenience function."""

    def test_chain_creates_package_with_prior_ref(self, minimal_package: Package, tmp_dir: Path) -> None:
        bundle_dir = tmp_dir / "prior.acef"
        minimal_package.export(str(bundle_dir))

        new_pkg = acef.chain(
            str(bundle_dir),
            producer={"name": "test", "version": "2.0"},
        )
        assert new_pkg.metadata.prior_package_ref is not None
        assert new_pkg.metadata.prior_package_ref.startswith("sha256:")


class TestTopLevelSignVerify:
    """MG-13: acef.sign and acef.verify exist."""

    def test_sign_is_callable(self) -> None:
        assert callable(acef.sign)

    def test_verify_is_callable(self) -> None:
        assert callable(acef.verify)

    def test_sign_is_sign_bundle(self) -> None:
        from acef.signing import sign_bundle
        assert acef.sign is sign_bundle

    def test_verify_is_verify_detached_jws(self) -> None:
        from acef.signing import verify_detached_jws
        assert acef.verify is verify_detached_jws


class TestACEF032Emission:
    """ACEF-032: Provision not yet effective produces info diagnostic."""

    def test_future_provision_emits_acef032(self, tmp_dir: Path) -> None:
        pkg = Package(producer={"name": "test", "version": "1.0"})
        pkg.add_subject("ai_system", name="Test", risk_classification="high-risk")
        pkg.add_profile("eu-ai-act-2024", provisions=["article-9"])

        # Evaluate with a date before the provision effective date
        assessment = acef.validate(
            pkg,
            profiles=["eu-ai-act-2024"],
            evaluation_instant="2024-01-01T00:00:00Z",
        )

        # Should have ACEF-032 info diagnostics
        acef032_errors = [
            e for e in assessment.structural_errors
            if e.get("code") == "ACEF-032"
        ]
        assert len(acef032_errors) > 0
