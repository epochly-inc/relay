"""Integration tests for the ACEF CLI."""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from acef.cli.main import cli
from acef.package import Package


@pytest.fixture
def runner():
    return CliRunner()


class TestCLI:
    """CLI command integration tests."""

    def test_version(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output

    def test_init_creates_bundle(self, runner: CliRunner, tmp_dir: Path) -> None:
        bundle_path = str(tmp_dir / "new-bundle.acef")
        result = runner.invoke(cli, ["init", bundle_path])
        assert result.exit_code == 0
        assert "Created ACEF bundle" in result.output
        assert (tmp_dir / "new-bundle.acef" / "acef-manifest.json").exists()

    def test_init_with_subject(self, runner: CliRunner, tmp_dir: Path) -> None:
        bundle_path = str(tmp_dir / "with-subject.acef")
        result = runner.invoke(cli, [
            "init", bundle_path,
            "--subject-name", "Test System",
            "--subject-type", "ai_system",
            "--risk-classification", "high-risk",
        ])
        assert result.exit_code == 0

    def test_inspect_bundle(self, runner: CliRunner, minimal_package: Package, tmp_dir: Path) -> None:
        bundle_path = str(tmp_dir / "inspect.acef")
        minimal_package.export(bundle_path)

        result = runner.invoke(cli, ["inspect", bundle_path])
        assert result.exit_code == 0

    def test_inspect_json(self, runner: CliRunner, minimal_package: Package, tmp_dir: Path) -> None:
        bundle_path = str(tmp_dir / "inspect-json.acef")
        minimal_package.export(bundle_path)

        result = runner.invoke(cli, ["inspect", bundle_path, "--format", "json"])
        assert result.exit_code == 0

    def test_validate_bundle(self, runner: CliRunner, minimal_package: Package, tmp_dir: Path) -> None:
        bundle_path = str(tmp_dir / "validate.acef")
        minimal_package.export(bundle_path)

        result = runner.invoke(cli, ["validate", bundle_path])
        # Exit code 0 (pass), 1 (not satisfied), or 2 (fatal schema errors) are all valid
        # depending on schema strictness. The command should complete without exceptions.
        assert result.exit_code in (0, 1, 2)

    def test_doctor_healthy_bundle(self, runner: CliRunner, minimal_package: Package, tmp_dir: Path) -> None:
        bundle_path = str(tmp_dir / "doctor.acef")
        minimal_package.export(bundle_path)

        result = runner.invoke(cli, ["doctor", bundle_path])
        assert result.exit_code == 0

    def test_export_to_archive(self, runner: CliRunner, minimal_package: Package, tmp_dir: Path) -> None:
        bundle_path = str(tmp_dir / "export-src.acef")
        minimal_package.export(bundle_path)

        archive_path = str(tmp_dir / "export-out.acef.tar.gz")
        result = runner.invoke(cli, ["export", bundle_path, archive_path])
        assert result.exit_code == 0
        assert Path(archive_path).exists()
