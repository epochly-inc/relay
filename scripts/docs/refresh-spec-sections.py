#!/usr/bin/env python3
"""Refresh packages/schemas/raw/spec-sections.txt from the live spec.

Reads the canonical spec at the workspace-parent path
``../planning/epochly-replay-spec.md`` and writes a sorted, deduplicated
list of section IDs (e.g. ``A``, ``A.1``, ``AO.4``) to the vendored
``packages/schemas/raw/spec-sections.txt`` inside the public relay/ repo.

The vendored file is consumed by scripts/docs/audit-codebase-alignment.py
as a fallback when SPEC_PATH is not reachable (e.g. CI on the public
relay/ checkout that does NOT include the private workspace parent's
planning/ tree).

Run this locally after the spec is updated, then commit the refreshed
file. The script is read-only against the spec and only writes to the
vendored output path.

Exit codes:
  0  - PASS (file written or already up-to-date)
  1  - FAIL (spec not reachable -- run locally with the workspace parent)
  64 - usage / runtime error
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SPEC_PATH = REPO_ROOT.parent / "planning" / "epochly-replay-spec.md"
VENDOR_PATH = REPO_ROOT / "packages" / "schemas" / "raw" / "spec-sections.txt"

# Same regex as audit-codebase-alignment.py:_load_spec_sections.
_SECTION_HEADER_RE = re.compile(r"^####? ([A-Z]+(?:\.\d+)?)(?:[\.\s]|$)")

_HEADER = """\
# Vendored list of section IDs from planning/epochly-replay-spec.md.
# Used by scripts/docs/audit-codebase-alignment.py as a fallback when
# the spec file is not reachable (e.g. CI checking only relay/).
# Regenerate via: python scripts/docs/refresh-spec-sections.py
# One section ID per line; blank lines and # comments ignored.

"""


def _extract_sections(spec_text: str) -> list[str]:
    sections: set[str] = set()
    for line in spec_text.splitlines():
        m = _SECTION_HEADER_RE.match(line)
        if m:
            sid = m.group(1)
            sections.add(sid)
            if "." in sid:
                sections.add(sid.split(".", 1)[0])
    # Sort by (alpha-prefix length, lexical) so single-letter sections come
    # before multi-letter ones with the same starting letter (e.g. A, A.1,
    # AO, AO.4).
    return sorted(sections, key=lambda s: (len(s.split(".")[0]), s))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit 1 if VENDOR_PATH would change; do not write.",
    )
    args = parser.parse_args(argv)

    if not SPEC_PATH.is_file():
        print(
            f"FAIL: spec not reachable at {SPEC_PATH}; "
            f"run this script from a workspace checkout that includes planning/",
            file=sys.stderr,
        )
        return 1

    spec_text = SPEC_PATH.read_text(encoding="utf-8", errors="replace")
    sections = _extract_sections(spec_text)
    body = _HEADER + "\n".join(sections) + "\n"

    if args.check:
        existing = VENDOR_PATH.read_text(encoding="utf-8") if VENDOR_PATH.is_file() else ""
        if existing != body:
            print(f"FAIL: {VENDOR_PATH} is out of date relative to {SPEC_PATH}", file=sys.stderr)
            return 1
        print(f"OK: {VENDOR_PATH} matches current spec ({len(sections)} sections)")
        return 0

    VENDOR_PATH.parent.mkdir(parents=True, exist_ok=True)
    VENDOR_PATH.write_text(body)
    print(f"OK: wrote {len(sections)} section IDs to {VENDOR_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
