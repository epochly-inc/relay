"""ACEF CLI — main entry point with Click group."""

from __future__ import annotations

import click

from acef._version import __version__


@click.group()
@click.version_option(version=__version__, prog_name="acef")
def cli() -> None:
    """ACEF — AI Compliance Evidence Format CLI.

    Tools for creating, validating, and inspecting ACEF Evidence Bundles.
    """
    pass


# Import and register subcommands
from acef.cli.init_cmd import init_cmd
from acef.cli.validate_cmd import validate_cmd
from acef.cli.export_cmd import export_cmd
from acef.cli.inspect_cmd import inspect_cmd
from acef.cli.record_cmd import record_cmd
from acef.cli.scaffold_cmd import scaffold_cmd
from acef.cli.doctor_cmd import doctor_cmd

cli.add_command(init_cmd, "init")
cli.add_command(validate_cmd, "validate")
cli.add_command(export_cmd, "export")
cli.add_command(inspect_cmd, "inspect")
cli.add_command(record_cmd, "record")
cli.add_command(scaffold_cmd, "scaffold")
cli.add_command(doctor_cmd, "doctor")


if __name__ == "__main__":
    cli()
