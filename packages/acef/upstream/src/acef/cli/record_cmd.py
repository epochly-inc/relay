"""ACEF CLI — record command: add records to a bundle."""

from __future__ import annotations

import json

import click

from acef.loader import load


@click.command("record")
@click.argument("bundle_path")
@click.option("--type", "record_type", required=True, help="Record type")
@click.option("--provision", "-p", multiple=True, help="Provisions addressed")
@click.option("--payload", required=True, help="JSON payload string or @file.json")
@click.option("--role", default="provider", help="Obligation role")
def record_cmd(
    bundle_path: str,
    record_type: str,
    provision: tuple[str, ...],
    payload: str,
    role: str,
) -> None:
    """Add an evidence record to the bundle at BUNDLE_PATH."""
    # Load existing bundle
    pkg = load(bundle_path)

    # Parse payload
    if payload.startswith("@"):
        with open(payload[1:], "r") as f:
            payload_data = json.load(f)
    else:
        payload_data = json.loads(payload)

    # Add record
    record = pkg.record(
        record_type=record_type,
        provisions=list(provision),
        payload=payload_data,
        obligation_role=role,
    )

    # Re-export
    pkg.export(bundle_path)
    click.echo(f"Added {record_type} record: {record.record_id}")
