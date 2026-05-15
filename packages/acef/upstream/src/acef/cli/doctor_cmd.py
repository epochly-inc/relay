"""ACEF CLI — doctor command: diagnose bundle issues."""

from __future__ import annotations

import json
from pathlib import Path

import click
from rich.console import Console

console = Console()


@click.command("doctor")
@click.argument("path")
def doctor_cmd(path: str) -> None:
    """Diagnose issues with an ACEF Evidence Bundle at PATH.

    Checks structure, integrity, references, and common problems.
    """
    bundle_path = Path(path)
    issues: list[tuple[str, str, str]] = []  # (severity, category, message)

    console.print(f"\n[bold]ACEF Doctor: Examining {path}[/bold]\n")

    # Check bundle exists
    if not bundle_path.exists():
        console.print(f"[red]Bundle not found: {path}[/red]")
        raise SystemExit(1)

    if bundle_path.is_file() and (bundle_path.suffix == ".gz" or str(bundle_path).endswith(".tar.gz")):
        console.print("[yellow]Archive bundles — extracting for analysis...[/yellow]")
        from acef.loader import load

        try:
            load(path)
            console.print("[green]Archive loads successfully[/green]")
        except Exception as e:
            console.print(f"[red]Archive load failed: {e}[/red]")
            raise SystemExit(1)
        return

    # Check directory structure
    _check_structure(bundle_path, issues)

    # Check manifest
    _check_manifest(bundle_path, issues)

    # Check integrity
    _check_integrity(bundle_path, issues)

    # Check records
    _check_records(bundle_path, issues)

    # Report
    console.print()
    if not issues:
        console.print("[green bold]No issues found! Bundle looks healthy.[/green bold]")
    else:
        for severity, category, message in issues:
            if severity == "error":
                console.print(f"  [red][{category}][/red] {message}")
            elif severity == "warning":
                console.print(f"  [yellow][{category}][/yellow] {message}")
            else:
                console.print(f"  [dim][{category}][/dim] {message}")

        errors = sum(1 for s, _, _ in issues if s == "error")
        warnings = sum(1 for s, _, _ in issues if s == "warning")
        console.print(f"\n[bold]Summary: {errors} errors, {warnings} warnings[/bold]")


def _check_structure(bundle_path: Path, issues: list[tuple[str, str, str]]) -> None:
    """Check bundle directory structure."""
    console.print("Checking structure...")

    if not (bundle_path / "acef-manifest.json").exists():
        issues.append(("error", "structure", "Missing acef-manifest.json"))
        return

    console.print("  [green]acef-manifest.json found[/green]")

    for dirname in ("records", "artifacts", "hashes", "signatures"):
        if (bundle_path / dirname).exists():
            console.print(f"  [green]{dirname}/ present[/green]")
        elif dirname in ("records",):
            issues.append(("warning", "structure", f"Missing {dirname}/ directory"))
        else:
            console.print(f"  [dim]{dirname}/ not present (optional)[/dim]")


def _check_manifest(bundle_path: Path, issues: list[tuple[str, str, str]]) -> None:
    """Check manifest validity."""
    console.print("\nChecking manifest...")
    manifest_path = bundle_path / "acef-manifest.json"

    if not manifest_path.exists():
        return

    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        console.print("  [green]Valid JSON[/green]")
    except json.JSONDecodeError as e:
        issues.append(("error", "manifest", f"Invalid JSON: {e}"))
        return

    # Check required fields
    metadata = data.get("metadata")
    if not metadata:
        issues.append(("error", "manifest", "Missing metadata block"))
    else:
        if not metadata.get("package_id"):
            issues.append(("error", "manifest", "Missing metadata.package_id"))
        if not metadata.get("timestamp"):
            issues.append(("error", "manifest", "Missing metadata.timestamp"))
        if not metadata.get("producer"):
            issues.append(("error", "manifest", "Missing metadata.producer"))
        console.print(f"  [green]Package ID: {metadata.get('package_id', 'N/A')}[/green]")

    versioning = data.get("versioning")
    if not versioning:
        issues.append(("warning", "manifest", "Missing versioning block"))

    subjects = data.get("subjects", [])
    console.print(f"  Subjects: {len(subjects)}")
    if not subjects:
        issues.append(("warning", "manifest", "No subjects declared"))


def _check_integrity(bundle_path: Path, issues: list[tuple[str, str, str]]) -> None:
    """Check integrity files."""
    console.print("\nChecking integrity...")

    hashes_path = bundle_path / "hashes" / "content-hashes.json"
    if hashes_path.exists():
        try:
            hashes = json.loads(hashes_path.read_text(encoding="utf-8"))
            console.print(f"  [green]content-hashes.json: {len(hashes)} entries[/green]")

            # Spot-check a few hashes
            from acef.integrity import verify_content_hashes

            errors = verify_content_hashes(bundle_path, hashes)
            if errors:
                for err in errors[:5]:
                    issues.append(("error", "integrity", err))
            else:
                console.print("  [green]All hashes verified[/green]")
        except json.JSONDecodeError:
            issues.append(("error", "integrity", "Invalid JSON in content-hashes.json"))
    else:
        issues.append(("warning", "integrity", "No content-hashes.json found"))

    merkle_path = bundle_path / "hashes" / "merkle-tree.json"
    if merkle_path.exists():
        console.print("  [green]merkle-tree.json present[/green]")
    else:
        issues.append(("warning", "integrity", "No merkle-tree.json found"))

    sig_dir = bundle_path / "signatures"
    if sig_dir.exists():
        sigs = list(sig_dir.glob("*.jws"))
        if sigs:
            console.print(f"  [green]{len(sigs)} signature(s) found[/green]")
        else:
            console.print("  [dim]No signatures (unsigned bundle — valid)[/dim]")
    else:
        console.print("  [dim]No signatures directory (unsigned bundle — valid)[/dim]")


def _check_records(bundle_path: Path, issues: list[tuple[str, str, str]]) -> None:
    """Check record files."""
    console.print("\nChecking records...")

    records_dir = bundle_path / "records"
    if not records_dir.exists():
        console.print("  [dim]No records directory[/dim]")
        return

    jsonl_files = list(records_dir.rglob("*.jsonl"))
    console.print(f"  Found {len(jsonl_files)} record file(s)")

    total_records = 0
    for jsonl_file in jsonl_files:
        try:
            count = 0
            with open(jsonl_file, "r", encoding="utf-8") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        json.loads(line)
                        count += 1
                    except json.JSONDecodeError:
                        issues.append(("error", "records", f"Invalid JSON at {jsonl_file.name}:{line_num}"))
            total_records += count
        except Exception as e:
            issues.append(("error", "records", f"Failed to read {jsonl_file.name}: {e}"))

    console.print(f"  Total records: {total_records}")
