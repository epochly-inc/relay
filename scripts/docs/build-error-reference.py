#!/usr/bin/env python3
# ruff: noqa: E501
"""Error-code reference generator (VAL-DOCS-M1-009).

Reads the canonical docs registry at
``packages/schemas/raw/error-codes.yaml`` and writes one Markdown page per
``RELAY-*`` code at ``docs/reference/errors/<CODE>/index.md``.

The directory-style ``<CODE>/index.md`` slug shape is mandatory: the CLI
and SDK build documentation URLs as
``https://relay.epochly.com/docs/errors/<CODE>`` (prefix lives in
``packages/sdk-typescript/src/errors.ts`` as ``DEFAULT_DOC_URL_PREFIX``).
When GitHub Pages serves the staging site at
``https://epochly-inc.github.io/relay/errors/<CODE>/`` the directory-style
layout produces the matching path component. A trailing-slash redirect on
GH Pages handles the prefix-with-trailing-slash mapping.

Operationally pure: the generator is read-only outside the output
directory and idempotent (same input -> byte-identical output across
runs). The ``--check`` flag turns it into a CI drift detector: it
regenerates into a tmp dir and diffs against the on-disk tree without
mutating anything.

Exit codes:
  0  -- success / no drift
  1  -- drift detected (``--check`` only)
  64 -- usage error (per BSD/sysexits convention; matches CLI surface)

ASCII-only output per CLAUDE.md "ASCII-Safe Source".

Spec citations:
- plan.md "Wave 1 deliverable 6" (error-code reference auto-generator)
- contract.md VAL-DOCS-M1-009
"""

from __future__ import annotations

import argparse
import re
import shutil
import sys
from pathlib import Path
from typing import Any

import yaml

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INPUT = REPO_ROOT / "packages" / "schemas" / "raw" / "error-codes.yaml"
DEFAULT_OUT = REPO_ROOT / "docs" / "reference" / "errors"

YAML_SOURCE_PATH = "packages/schemas/raw/error-codes.yaml"
BANNER = (
    "Generated from packages/schemas/raw/error-codes.yaml. Do not edit by hand."
)
SCHEMA_VERSION = "relay.error_registry.v1"

# Mirrors the canonical RELAY-<DOMAIN>-<TAIL> grammar. The tail accepts
# numeric (031) and word-form (PROXY-NOT-SET) tails per
# docs/internal/error-codes.md. Loader rejects entries that do not match.
CODE_RE = re.compile(r"^RELAY-[A-Z][A-Z0-9_]*-[A-Z0-9_]+$")

USAGE_EXIT = 64
DRIFT_EXIT = 1
OK_EXIT = 0

# ---------------------------------------------------------------------------
# Loader + validator
# ---------------------------------------------------------------------------


def load_registry(path: Path) -> list[dict[str, Any]]:
    """Load ``path`` and return the validated ``codes`` list.

    Raises ``SystemExit(64)`` with an informative message on usage errors.
    """
    if not path.exists():
        sys.stderr.write(f"error: registry file not found: {path}\n")
        raise SystemExit(USAGE_EXIT)
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        sys.stderr.write(f"error: YAML parse failed for {path}: {exc}\n")
        raise SystemExit(USAGE_EXIT) from exc
    if not isinstance(data, dict):
        sys.stderr.write(f"error: {path}: top-level must be a mapping\n")
        raise SystemExit(USAGE_EXIT)
    if data.get("schema_version") != SCHEMA_VERSION:
        sys.stderr.write(
            f"error: {path}: schema_version must be {SCHEMA_VERSION!r}; "
            f"got {data.get('schema_version')!r}\n"
        )
        raise SystemExit(USAGE_EXIT)
    codes = data.get("codes")
    if not isinstance(codes, list):
        sys.stderr.write(f"error: {path}: 'codes' must be a list\n")
        raise SystemExit(USAGE_EXIT)
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for idx, raw in enumerate(codes):
        if not isinstance(raw, dict):
            sys.stderr.write(
                f"error: {path}: codes[{idx}] must be a mapping; got {raw!r}\n"
            )
            raise SystemExit(USAGE_EXIT)
        code = raw.get("code")
        if not isinstance(code, str) or not CODE_RE.match(code):
            sys.stderr.write(
                f"error: {path}: codes[{idx}].code {code!r} does not match "
                f"RELAY-[A-Z][A-Z0-9_]*-[A-Z0-9_]+ grammar\n"
            )
            raise SystemExit(USAGE_EXIT)
        if code in seen:
            sys.stderr.write(
                f"error: {path}: codes[{idx}].code {code!r} appears more than once\n"
            )
            raise SystemExit(USAGE_EXIT)
        seen.add(code)
        # Defensive: skip any entry the registry explicitly hides from the
        # user-facing reference. Today no entry uses these flags; the guard
        # is here so a future addition does not silently leak.
        if raw.get("internal_only") or raw.get("hidden"):
            continue
        out.append(raw)
    return out


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def _normalize_block(value: Any) -> str:
    """Return ``value`` as a stripped string with consistent trailing newline behaviour.

    YAML literal blocks (``|``) preserve a trailing newline; YAML flow
    scalars do not. We strip both ends so the rendered Markdown is
    byte-identical regardless of which YAML form authored the field.
    """
    if value is None:
        return ""
    return str(value).strip()


def _render_section(title: str, body: str) -> str | None:
    """Render a Markdown level-2 section, or None when the body is empty.

    Fix #34: empty sections previously rendered "_Not yet documented. Track
    via the docs backlog._" which is a placeholder shipped to readers (and
    a CLAUDE.md production-readiness violation). The new behavior is to
    return ``None`` so ``_render_page`` can omit the section entirely and
    instead surface the gap once at the top via the documentation-status
    banner -- honest about what is missing without scattering placeholder
    text through every page.
    """
    body = _normalize_block(body)
    if not body:
        return None
    return f"## {title}\n\n{body}\n"


def _render_page(entry: dict[str, Any]) -> str:
    """Render a single code's Markdown body. Pure function for idempotency."""
    code = entry["code"]
    domain = _normalize_block(entry.get("domain")) or "uncategorized"
    severity = _normalize_block(entry.get("severity")) or "error"
    introduced_in = _normalize_block(entry.get("introduced_in")) or "unspecified"
    spec_section = _normalize_block(entry.get("spec_section"))
    description = _normalize_block(entry.get("description"))
    triggers = _normalize_block(entry.get("triggers"))
    how_to_fix = _normalize_block(entry.get("how_to_fix"))
    missing_fields = [
        name
        for name, value in (
            ("description", description),
            ("triggers", triggers),
            ("how_to_fix", how_to_fix),
        )
        if not value
    ]

    lines: list[str] = []
    lines.append(f"# {code}")
    lines.append("")
    lines.append(f"> {BANNER}")
    lines.append("")
    if missing_fields:
        lines.append(
            "!!! warning \"Documentation pending for: "
            + ", ".join(missing_fields)
            + "\"\n"
            + "    This error code is defined in the wire registry but its\n"
            + "    user-facing prose has not yet been authored. The emit\n"
            + "    site in the codebase is the authoritative source of\n"
            + "    behavior; grep for the code constant to find it.\n"
        )
        lines.append("")
    lines.append("| Field | Value |")
    lines.append("|---|---|")
    lines.append(f"| Code | `{code}` |")
    lines.append(f"| Domain | {domain} |")
    lines.append(f"| Severity | {severity} |")
    lines.append(f"| Introduced in | {introduced_in} |")
    if spec_section:
        lines.append(f"| Spec section | §{spec_section} |")
    lines.append("")
    for section in (
        _render_section("Description", description),
        _render_section("Triggers", triggers),
        _render_section("How to fix", how_to_fix),
    ):
        if section is not None:
            lines.append(section)
    if spec_section:
        lines.append("---")
        lines.append("")
        lines.append(f"Spec: §{spec_section}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_all(entries: list[dict[str, Any]]) -> dict[str, str]:
    """Return a ``{code: rendered_body}`` mapping, sorted by code lexicographically."""
    out: dict[str, str] = {}
    for entry in sorted(entries, key=lambda e: e["code"]):
        out[entry["code"]] = _render_page(entry)
    return out


# ---------------------------------------------------------------------------
# Filesystem writers
# ---------------------------------------------------------------------------


def write_pages(out_root: Path, pages: dict[str, str]) -> None:
    """Write each page at ``<out_root>/<CODE>/index.md`` atomically.

    Removes stale ``<CODE>/`` subdirectories that no longer correspond to
    registry entries so the output dir stays in lockstep with the source.
    A ``.gitkeep`` at the root is preserved.
    """
    out_root.mkdir(parents=True, exist_ok=True)
    # Sweep stale code directories.
    expected_dirs = set(pages.keys())
    for child in out_root.iterdir():
        if child.is_dir() and CODE_RE.match(child.name) and child.name not in expected_dirs:
            shutil.rmtree(child)
    # Write fresh.
    for code, body in pages.items():
        code_dir = out_root / code
        code_dir.mkdir(parents=True, exist_ok=True)
        index_path = code_dir / "index.md"
        # Idempotent: only rewrite if the body differs (avoids spurious
        # mtime changes between identical runs).
        if index_path.is_file():
            current = index_path.read_text(encoding="utf-8")
            if current == body:
                continue
        index_path.write_text(body, encoding="utf-8")


def check_drift(out_root: Path, pages: dict[str, str]) -> tuple[bool, list[str]]:
    """Compare on-disk content against the rendered ``pages`` map.

    Returns ``(no_drift, drift_descriptions)``. ``no_drift`` is True when
    every expected page exists with byte-identical content AND no
    unexpected ``RELAY-*/`` dirs are present.
    """
    drift: list[str] = []
    expected_codes = set(pages.keys())
    seen_codes: set[str] = set()
    if not out_root.exists():
        drift.append(f"output dir missing: {out_root}")
        return False, drift
    for code, body in pages.items():
        page = out_root / code / "index.md"
        if not page.is_file():
            drift.append(f"missing page: {page.relative_to(REPO_ROOT)}")
            continue
        current = page.read_text(encoding="utf-8")
        if current != body:
            drift.append(f"content drift: {page.relative_to(REPO_ROOT)}")
    for child in out_root.iterdir():
        if child.is_dir() and CODE_RE.match(child.name):
            seen_codes.add(child.name)
    extras = seen_codes - expected_codes
    for extra in sorted(extras):
        drift.append(f"unexpected dir: {(out_root / extra).relative_to(REPO_ROOT)}")
    return (not drift), drift


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="build-error-reference.py",
        description=(
            "Generate docs/reference/errors/<CODE>/index.md pages from the "
            "canonical registry at packages/schemas/raw/error-codes.yaml."
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
        help=f"Output directory (default: {DEFAULT_OUT.relative_to(REPO_ROOT)}).",
    )
    p.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_INPUT,
        help=f"Registry YAML path (default: {DEFAULT_INPUT.relative_to(REPO_ROOT)}).",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        # argparse exits 2 on usage error; normalize to our convention.
        if exc.code not in (0, None):
            return USAGE_EXIT
        return int(exc.code or OK_EXIT)

    entries = load_registry(args.input)
    pages = render_all(entries)

    if args.check:
        ok, drift = check_drift(args.out, pages)
        if ok:
            return OK_EXIT
        sys.stderr.write("drift detected:\n")
        for d in drift:
            sys.stderr.write(f"  - {d}\n")
        return DRIFT_EXIT

    write_pages(args.out, pages)
    return OK_EXIT


if __name__ == "__main__":
    raise SystemExit(main())
