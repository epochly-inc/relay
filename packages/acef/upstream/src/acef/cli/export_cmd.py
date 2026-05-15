"""ACEF CLI — export command: export directory/archive."""

from __future__ import annotations

import click

from acef.loader import load


@click.command("export")
@click.argument("input_path")
@click.argument("output_path")
@click.option("--format", "fmt", default="directory", type=click.Choice(["directory", "archive"]))
@click.option("--sign", "key_path", default=None, help="Path to PEM private key for signing")
def export_cmd(input_path: str, output_path: str, fmt: str, key_path: str | None) -> None:
    """Export an ACEF bundle from INPUT_PATH to OUTPUT_PATH.

    Can convert between directory and archive formats.
    """
    pkg = load(input_path)

    if key_path:
        pkg.sign(key_path)

    if fmt == "archive" or output_path.endswith(".tar.gz"):
        if not output_path.endswith(".tar.gz"):
            output_path += ".acef.tar.gz"
        pkg.export(output_path)
        click.echo(f"Exported archive: {output_path}")
    else:
        pkg.export(output_path)
        click.echo(f"Exported directory: {output_path}")
