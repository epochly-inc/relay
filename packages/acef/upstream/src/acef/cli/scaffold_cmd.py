"""ACEF CLI — scaffold command: generate template stubs."""

from __future__ import annotations


import click

from acef.templates.registry import list_templates, load_template


@click.command("scaffold")
@click.argument("profile_id")
@click.option("--output", "-o", default=None, help="Output directory for scaffold")
@click.option("--format", "fmt", default="json", type=click.Choice(["json", "summary"]))
def scaffold_cmd(profile_id: str, output: str | None, fmt: str) -> None:
    """Generate evidence stubs for a regulation profile.

    Shows what records are needed and generates payload templates.
    """
    try:
        template = load_template(profile_id)
    except Exception as e:
        click.echo(f"Error loading template: {e}", err=True)
        available = list_templates()
        if available:
            click.echo(f"Available templates: {', '.join(available)}", err=True)
        raise SystemExit(1)

    click.echo(f"Scaffold for: {template.template_name} ({template.template_id})")
    click.echo(f"Version: {template.version}")
    click.echo(f"Jurisdiction: {template.jurisdiction}")
    click.echo()

    for provision in template.provisions:
        click.echo(f"  {provision.provision_id}: {provision.provision_name}")
        if provision.required_evidence_types:
            for rt in provision.required_evidence_types:
                min_count = provision.minimum_evidence_count.get(rt, 1)
                click.echo(f"    - {rt} (min: {min_count})")
        if provision.evaluation:
            for rule in provision.evaluation:
                click.echo(f"    Rule: {rule.rule_id} [{rule.severity}] {rule.rule}")
        click.echo()
