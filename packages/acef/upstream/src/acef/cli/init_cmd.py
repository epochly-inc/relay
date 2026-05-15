"""ACEF CLI — init command: scaffold an empty bundle."""

from __future__ import annotations


import click

from acef.package import Package


@click.command("init")
@click.argument("path")
@click.option("--producer-name", default="acef-cli", help="Producer tool name")
@click.option("--producer-version", default="0.1.0", help="Producer tool version")
@click.option("--subject-name", default=None, help="Initial subject name")
@click.option("--subject-type", default="ai_system", type=click.Choice(["ai_system", "ai_model"]))
@click.option("--risk-classification", default="minimal-risk",
              type=click.Choice(["high-risk", "gpai", "gpai-systemic", "limited-risk", "minimal-risk"]))
def init_cmd(
    path: str,
    producer_name: str,
    producer_version: str,
    subject_name: str | None,
    subject_type: str,
    risk_classification: str,
) -> None:
    """Initialize a new ACEF Evidence Bundle at PATH.

    Creates a minimal valid bundle directory structure.
    """
    pkg = Package(producer={"name": producer_name, "version": producer_version})

    if subject_name:
        pkg.add_subject(
            subject_type=subject_type,
            name=subject_name,
            risk_classification=risk_classification,
        )

    pkg.export(path)
    click.echo(f"Created ACEF bundle at: {path}")
    click.echo(f"Package ID: {pkg.metadata.package_id}")
