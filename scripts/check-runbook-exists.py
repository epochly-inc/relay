#!/usr/bin/env python3
"""First-tagged-release gate: assert release runbook exists with required sections.

VAL-W12-047 (PW1-7): Before the first tagged release, the file
``docs/release/runbook.md`` MUST exist AND contain every required
section header. CI invokes this script as a workflow guard step that
runs before the publish step; a missing runbook or a missing required
section exits non-zero with structured JSON on stdout so the workflow
fails fast with a parseable signal.

Required sections (per VAL-W12-039, 041, 042, 043, 047):

  * "Compromised OIDC response"   (VAL-W12-041)
  * "No Destructive Rollback"     (VAL-W12-039)
  * "Sectigo TSA fallback"        (VAL-W12-043)
  * "Trust-anchor governance cross-reference"  (VAL-W12-042)

Section headers are matched case-insensitively at the start of a
markdown header line (any heading level ``#``..``######``).

Exit codes:
  0  : runbook present, all required sections found
  1  : runbook present but missing one or more required sections
  2  : runbook file not found

Wire code on failure: ``RELAY-RELEASE-047``.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Final

REPO_ROOT: Final[Path] = Path(__file__).resolve().parent.parent
DEFAULT_RUNBOOK_PATH: Final[Path] = REPO_ROOT / "docs" / "release" / "runbook.md"

RELAY_RELEASE_047: Final[str] = "RELAY-RELEASE-047"

# Required section headers. Match case-insensitively at the start of any
# markdown heading line. Each entry is the canonical title and a
# fuzzy-match regex (allowing minor case/whitespace drift).
REQUIRED_SECTIONS: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    (
        "Compromised OIDC response",
        re.compile(
            r"^\s*#{1,6}\s+compromised[\s-]+oidc\s+response\b",
            re.IGNORECASE | re.MULTILINE,
        ),
    ),
    (
        "No Destructive Rollback",
        re.compile(
            r"^\s*#{1,6}\s+no[\s-]+destructive[\s-]+rollback\b",
            re.IGNORECASE | re.MULTILINE,
        ),
    ),
    (
        "Sectigo TSA fallback",
        re.compile(
            r"^\s*#{1,6}\s+sectigo[\s-]+tsa[\s-]+fallback\b",
            re.IGNORECASE | re.MULTILINE,
        ),
    ),
    (
        "Trust-anchor governance cross-reference",
        re.compile(
            r"^\s*#{1,6}\s+trust[\s-]+anchor\s+governance(\s+cross[\s-]+reference)?\b",
            re.IGNORECASE | re.MULTILINE,
        ),
    ),
)


def check_runbook(runbook_path: Path) -> dict[str, object]:
    """Verify the runbook exists and contains every required section.

    Returns a structured result dict suitable for JSON serialization:

        {
          "runbook_path": "<str>",
          "exists": <bool>,
          "missing_sections": ["<title>", ...],
          "found_sections":   ["<title>", ...],
          "status":           "pass|fail",
          "error_code":       "RELAY-RELEASE-047" | null,
          "exit_code":        <int>
        }
    """
    if not runbook_path.exists():
        return {
            "runbook_path": str(runbook_path),
            "exists": False,
            "missing_sections": [title for title, _ in REQUIRED_SECTIONS],
            "found_sections": [],
            "status": "fail",
            "error_code": RELAY_RELEASE_047,
            "message": (
                f"first-tagged-release gate FAIL: runbook missing at "
                f"{runbook_path}"
            ),
            "exit_code": 2,
        }
    try:
        text = runbook_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return {
            "runbook_path": str(runbook_path),
            "exists": True,
            "missing_sections": [title for title, _ in REQUIRED_SECTIONS],
            "found_sections": [],
            "status": "fail",
            "error_code": RELAY_RELEASE_047,
            "message": f"runbook unreadable: {exc}",
            "exit_code": 1,
        }

    found: list[str] = []
    missing: list[str] = []
    for title, pattern in REQUIRED_SECTIONS:
        if pattern.search(text):
            found.append(title)
        else:
            missing.append(title)

    if missing:
        return {
            "runbook_path": str(runbook_path),
            "exists": True,
            "missing_sections": missing,
            "found_sections": found,
            "status": "fail",
            "error_code": RELAY_RELEASE_047,
            "message": (
                f"first-tagged-release gate FAIL: runbook at "
                f"{runbook_path} missing required sections: {missing}"
            ),
            "exit_code": 1,
        }

    return {
        "runbook_path": str(runbook_path),
        "exists": True,
        "missing_sections": [],
        "found_sections": found,
        "status": "pass",
        "error_code": None,
        "message": "first-tagged-release gate PASS",
        "exit_code": 0,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "First-tagged-release gate: assert the release runbook "
            "exists with the required sections (VAL-W12-047)."
        )
    )
    parser.add_argument(
        "--runbook",
        type=Path,
        default=DEFAULT_RUNBOOK_PATH,
        help=(
            f"Path to the release runbook (default: "
            f"{DEFAULT_RUNBOOK_PATH.relative_to(REPO_ROOT)})"
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit a structured JSON result on stdout (default: human-readable).",
    )
    args = parser.parse_args(argv)

    result = check_runbook(args.runbook)
    if args.json:
        sys.stdout.write(
            json.dumps(result, separators=(",", ":"), ensure_ascii=True) + "\n"
        )
    else:
        if result["status"] == "pass":
            sys.stdout.write("[OK] " + str(result["message"]) + "\n")
            sys.stdout.write(
                f"[OK] found {len(result['found_sections'])} required sections\n"
            )
        else:
            sys.stderr.write("[FAIL] " + str(result["message"]) + "\n")
            for m in result["missing_sections"]:
                sys.stderr.write(f"[FAIL] missing: {m}\n")
    return int(result["exit_code"])


if __name__ == "__main__":
    sys.exit(main())
