"""ACEF CLI — inspect command: bundle summary."""

from __future__ import annotations

import json
from pathlib import Path

import click

from acef.cli.formatters import print_bundle_info


@click.command("inspect")
@click.argument("path")
@click.option("--format", "fmt", default="pretty", type=click.Choice(["pretty", "json"]))
def inspect_cmd(path: str, fmt: str) -> None:
    """Inspect an ACEF Evidence Bundle at PATH.

    Shows metadata, subjects, entities, records, and profiles.
    """
    bundle_path = Path(path)

    if bundle_path.suffix == ".gz" or str(bundle_path).endswith(".tar.gz"):
        from acef.loader import load

        pkg = load(path)
        manifest_data = pkg.build_manifest().to_dict()
    else:
        manifest_file = bundle_path / "acef-manifest.json"
        if not manifest_file.exists():
            click.echo(f"Error: No acef-manifest.json found in {path}", err=True)
            raise SystemExit(1)
        manifest_data = json.loads(manifest_file.read_text(encoding="utf-8"))

    if fmt == "json":
        click.echo(json.dumps(manifest_data, indent=2))
    else:
        print_bundle_info(manifest_data)
