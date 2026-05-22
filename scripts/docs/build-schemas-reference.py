#!/usr/bin/env python3
# ruff: noqa: E501
"""Schemas reference generator (VAL-DOCS-M3-004).

Walks ``packages/schemas/catalogs/*.schema.json`` and produces a single
landing page at ``docs/reference/schemas/index.md`` listing every
canonical schema with its schema_version const, one-line description,
required top-level fields, and a cross-link to the corresponding
narrative docs page (when one is known).

The generator is operationally pure: same input -> byte-identical
output across runs. ``--check`` exits 1 on drift without writing.

Exit codes:
  0  -- success / no drift
  1  -- drift detected (``--check`` only)
  64 -- usage error (BSD/sysexits convention; matches CLI surface)

ASCII-only output per CLAUDE.md "ASCII-Safe Source".

Spec citations:
- plan.md "Wave 3 deliverable 29" (schemas reference landing page)
- contract.md VAL-DOCS-M3-004
- spec section A (canonical schemas registry)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[2]
CATALOGS = REPO_ROOT / "packages" / "schemas" / "catalogs"
DEFAULT_OUT = REPO_ROOT / "docs" / "reference" / "schemas" / "index.md"

BANNER = (
    "Generated from packages/schemas/catalogs/*.schema.json. Do not edit by hand."
)

# Cross-link map: schema name (stem without .schema) -> repo-relative narrative doc.
# Links are emitted relative to docs/reference/schemas/index.md.
# A schema absent from this map renders without a cross-link.
CROSS_LINKS: dict[str, str] = {
    "manifest.v1": "../../contracts/manifest-binding.md",
    "evidence_bundle.v1": "../../evidence/bundle-anatomy.md",
    "contract.v1": "../../contracts/writing-assertions.md",
    "redaction_policy.v1": "../../guards/INDEX.md",
    "relay.gate_metric_catalog.v1": "../../contracts/coverage-invariant.md",
}

USAGE_EXIT = 64
DRIFT_EXIT = 1
OK_EXIT = 0


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------


def _schema_files(catalogs_dir: Path) -> list[Path]:
    """Return the sorted list of ``*.schema.json`` files in ``catalogs_dir``."""
    if not catalogs_dir.is_dir():
        sys.stderr.write(f"error: catalogs dir not found: {catalogs_dir}\n")
        raise SystemExit(USAGE_EXIT)
    return sorted(catalogs_dir.glob("*.schema.json"))


def _load_schema(path: Path) -> dict[str, Any]:
    """Load a single schema file as a JSON object. Raises SystemExit(64) on error."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        sys.stderr.write(f"error: failed to load {path}: {exc}\n")
        raise SystemExit(USAGE_EXIT) from exc
    if not isinstance(data, dict):
        sys.stderr.write(f"error: {path}: top-level must be a JSON object\n")
        raise SystemExit(USAGE_EXIT)
    return data


# ---------------------------------------------------------------------------
# Extraction helpers
# ---------------------------------------------------------------------------


def _schema_name(path: Path) -> str:
    """Return the schema slug (filename without ``.schema.json``)."""
    name = path.name
    if name.endswith(".schema.json"):
        return name[: -len(".schema.json")]
    return path.stem


def _schema_version(schema: dict[str, Any]) -> str:
    """Extract the ``schema_version`` const from a schema's properties.

    Falls back to ``(unspecified)`` if absent so the generator never
    silently drops a schema from the index.
    """
    props = schema.get("properties")
    if not isinstance(props, dict):
        return "(unspecified)"
    sv = props.get("schema_version")
    if not isinstance(sv, dict):
        return "(unspecified)"
    const = sv.get("const")
    if isinstance(const, str) and const:
        return const
    # Some schemas may use ``enum`` with a single value or ``type: string``
    # plus a default. Fall back deterministically.
    enum = sv.get("enum")
    if isinstance(enum, list) and len(enum) == 1 and isinstance(enum[0], str):
        return enum[0]
    return "(unspecified)"


def _one_line_description(schema: dict[str, Any]) -> str:
    """Return the first non-empty line of the schema's top-level description."""
    desc = schema.get("description")
    if not isinstance(desc, str):
        return ""
    for line in desc.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return ""


def _required_top_level(schema: dict[str, Any]) -> list[str]:
    """Return required top-level field names, preserving schema order."""
    required = schema.get("required")
    if not isinstance(required, list):
        return []
    props = schema.get("properties")
    known = set(props.keys()) if isinstance(props, dict) else set()
    out: list[str] = []
    for item in required:
        if not isinstance(item, str):
            continue
        # Only include fields that actually appear in ``properties`` so the
        # reference page reflects fields the user can introspect.
        if known and item not in known:
            continue
        out.append(item)
    return out


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def _render_entry(path: Path, schema: dict[str, Any]) -> str:
    """Render one schema's Markdown section."""
    name = _schema_name(path)
    version = _schema_version(schema)
    description = _one_line_description(schema)
    required = _required_top_level(schema)
    link = CROSS_LINKS.get(name)

    lines: list[str] = []
    lines.append(f"## `{name}`")
    lines.append("")
    lines.append(f"- **Source:** `packages/schemas/catalogs/{path.name}`")
    lines.append(f"- **schema_version:** `{version}`")
    if description:
        lines.append(f"- **Description:** {description}")
    if required:
        rendered = ", ".join(f"`{r}`" for r in required)
        lines.append(f"- **Required top-level fields:** {rendered}")
    else:
        lines.append("- **Required top-level fields:** _none declared_")
    if link:
        lines.append(f"- **See also:** [narrative docs]({link})")
    lines.append("")
    return "\n".join(lines)


def render(catalogs_dir: Path = CATALOGS) -> str:
    """Render the full ``docs/reference/schemas/index.md`` body."""
    files = _schema_files(catalogs_dir)

    out: list[str] = []
    out.append("# Schemas reference")
    out.append("")
    out.append(f"> {BANNER}")
    out.append("")
    out.append(
        "Every canonical Relay schema. Each entry shows the source file, the "
        "literal `schema_version` discriminator engines accept, a one-line "
        "description, and the required top-level fields. Cross-links point to "
        "the narrative documentation that explains how each schema is used."
    )
    out.append("")
    out.append(f"Total schemas: **{len(files)}**.")
    out.append("")

    if not files:
        out.append("_No schemas found in `packages/schemas/catalogs/`._")
        out.append("")
    else:
        for path in files:
            schema = _load_schema(path)
            out.append(_render_entry(path, schema))

    out.append("---")
    out.append("")
    out.append("Spec: §A")
    out.append("")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="build-schemas-reference.py",
        description=(
            "Generate docs/reference/schemas/index.md from every "
            "packages/schemas/catalogs/*.schema.json file."
        ),
    )
    p.add_argument(
        "--check",
        action="store_true",
        help="Drift-check mode: exit 1 if on-disk content differs from generated; do not write.",
    )
    p.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUT,
        help=f"Output file (default: {DEFAULT_OUT.relative_to(REPO_ROOT)}).",
    )
    p.add_argument(
        "--catalogs",
        type=Path,
        default=CATALOGS,
        help=f"Catalogs directory (default: {CATALOGS.relative_to(REPO_ROOT)}).",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        if exc.code not in (0, None):
            return USAGE_EXIT
        return int(exc.code or OK_EXIT)

    body = render(args.catalogs)

    if args.check:
        existing = args.out.read_text(encoding="utf-8") if args.out.exists() else ""
        if existing != body:
            sys.stderr.write(f"drift detected in {args.out}\n")
            return DRIFT_EXIT
        return OK_EXIT

    args.out.parent.mkdir(parents=True, exist_ok=True)
    # Idempotent write: only rewrite when content actually differs.
    if args.out.exists() and args.out.read_text(encoding="utf-8") == body:
        return OK_EXIT
    args.out.write_text(body, encoding="utf-8")
    return OK_EXIT


if __name__ == "__main__":
    raise SystemExit(main())
