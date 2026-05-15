#!/usr/bin/env python3
"""VAL-W5-009 / VAL-W5-009b banned product copy lint.

CLAUDE.md banned product copy table (banned pattern #9, spec section J.5)
forbids customer-facing surfaces from containing the tokens:

  * compliant
  * certified
  * AI Act-approved (with optional dot/space variants)
  * guaranteed AI Act compliance (with optional dot/space variants)

VAL-W5-009 covers ``packages/cli/src/`` and the CLI's locale + error-
fixture string resources. VAL-W5-009b extends coverage to the full
distribution surface produced by the CLI release pipeline:

  1. ``packages/cli/src/`` (CLI source tree)
  2. ``packages/cli/README.md`` (PyPI long_description)
  3. ``packages/cli/pyproject.toml`` ``description`` field
  4. Root ``package.json`` ``description`` field (npm @epochly/relay)
  5. ``packages/sdk-typescript/package.json`` description (npm parity)
  6. Public docs under ``docs/`` (when present)
  7. ``.github/release-notes/`` templates (when present)
  8. PyInstaller spec ``datas=`` entries (when present in
     ``packages/cli/src/sidecar_install/build/relay-sidecar.spec``)

Per surface the lint runs the regex
``r"compliant|certified|AI[. ]Act[. -]approved|guaranteed[. ]AI[. ]Act"``
case-insensitive and asserts zero matches. The aggregator exits 0 only
when every surface passes.

Per the boundaries document (section 1.1) the script writes to NOTHING -
it is read-only. Its sole side effect is exit code (0 = clean, 1 =
violation found).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

# Repo root -- this script lives at <repo>/scripts/.
REPO_ROOT = Path(__file__).resolve().parent.parent

# Banned-token regex per VAL-W5-009 / VAL-W5-009b. The pattern is
# deliberately loose on the separator characters between "AI", "Act",
# and "approved"/"compliance" so variants like "AI.Act-approved" or
# "AI Act approved" all match. Case-insensitive.
BANNED_REGEX = re.compile(
    r"compliant|certified|AI[. ]Act[. \-]approved|guaranteed[. ]AI[. ]Act",
    re.IGNORECASE,
)

# Surface scopes per VAL-W5-009b. Each entry is a (label, glob_root,
# include_globs, exclude_globs) tuple. include_globs is a list of glob
# patterns relative to glob_root that the lint scans; exclude_globs is
# a list of relative globs to skip. A missing root is treated as a
# zero-match surface (e.g., docs/ may not exist yet in v0.1).
SURFACES: list[dict[str, object]] = [
    {
        "label": "cli-source-tree",
        "root": "packages/cli/src",
        "includes": ["**/*.py", "**/*.json", "**/*.txt"],
        "excludes": ["**/__pycache__/**"],
    },
    {
        "label": "cli-readme",
        "root": "packages/cli",
        "includes": ["README.md"],
        "excludes": [],
    },
    {
        "label": "cli-pyproject",
        "root": "packages/cli",
        "includes": ["pyproject.toml"],
        "excludes": [],
    },
    {
        "label": "root-package-json",
        "root": ".",
        "includes": ["package.json"],
        "excludes": [],
    },
    {
        "label": "sdk-typescript-package-json",
        "root": "packages/sdk-typescript",
        "includes": ["package.json"],
        "excludes": [],
    },
    {
        "label": "schemas-typescript-package-json",
        "root": "packages/schemas/typescript",
        "includes": ["package.json"],
        "excludes": [],
    },
    {
        "label": "public-docs",
        "root": "docs",
        "includes": ["**/*.md"],
        "excludes": [],
    },
    {
        "label": "github-release-notes",
        "root": ".github/release-notes",
        "includes": ["**/*.md", "**/*.txt"],
        "excludes": [],
    },
    {
        "label": "pyinstaller-spec",
        "root": "packages/cli/src/sidecar_install/build",
        "includes": ["**/*.spec"],
        "excludes": [],
    },
]


def _scan_file(path: Path) -> list[str]:
    """Return a list of matched-token strings for `path`.

    Reads the file as UTF-8 with errors='replace' so binary noise does
    not crash the lint. Returns the unique set of matches preserving
    discovery order; the caller decides whether any non-empty result
    constitutes a violation.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    seen: list[str] = []
    for match in BANNED_REGEX.finditer(text):
        token = match.group(0)
        if token not in seen:
            seen.append(token)
    return seen


def _scan_surface(surface: dict[str, object]) -> dict[str, object]:
    """Scan one surface and return a result dict.

    Result schema:
        {
          "label": str,
          "root_exists": bool,
          "files_scanned": int,
          "violations": [{"path": str, "matches": [str, ...]}, ...]
        }
    """
    label = str(surface["label"])
    root_rel = str(surface["root"])
    includes = list(surface["includes"])  # type: ignore[arg-type]
    excludes = list(surface["excludes"])  # type: ignore[arg-type]
    root_path = REPO_ROOT / root_rel
    if not root_path.exists():
        return {
            "label": label,
            "root_exists": False,
            "files_scanned": 0,
            "violations": [],
        }
    excluded_paths: set[Path] = set()
    for pattern in excludes:
        for p in root_path.glob(pattern):
            excluded_paths.add(p.resolve())
    # Files that legitimately enumerate every banned token because their
    # purpose is to detect the tokens elsewhere (the verify-self
    # banned-pattern detector and its closed finding-codes enum / shared
    # util module). The same exemption convention used for this lint
    # script's own self-reference (below).
    self_mention_paths: set[Path] = {
        (
            REPO_ROOT
            / "packages"
            / "cli"
            / "src"
            / "verify_self"
            / "finding_codes.py"
        ).resolve(),
        (
            REPO_ROOT
            / "packages"
            / "cli"
            / "src"
            / "relay_cli"
            / "invariants"
            / "banned_patterns.py"
        ).resolve(),
        (
            REPO_ROOT
            / "packages"
            / "cli"
            / "src"
            / "relay_cli"
            / "invariants"
            / "util.py"
        ).resolve(),
    }
    files_scanned = 0
    violations: list[dict[str, object]] = []
    for pattern in includes:
        for p in sorted(root_path.glob(pattern)):
            if not p.is_file():
                continue
            if p.resolve() in excluded_paths:
                continue
            # Skip files that are themselves the lint script (which
            # legitimately mentions every banned token in its docs).
            if p.resolve() == Path(__file__).resolve():
                continue
            # Skip the verify-self detector / enum / util modules whose
            # purpose IS to enumerate the banned tokens.
            if p.resolve() in self_mention_paths:
                continue
            files_scanned += 1
            matches = _scan_file(p)
            if matches:
                violations.append(
                    {
                        "path": str(p.relative_to(REPO_ROOT)),
                        "matches": matches,
                    }
                )
    return {
        "label": label,
        "root_exists": True,
        "files_scanned": files_scanned,
        "violations": violations,
    }


def main(argv: list[str]) -> int:
    """Entry point. Returns 0 on clean lint, 1 on any violation."""
    json_output = "--json" in argv
    results = [_scan_surface(s) for s in SURFACES]
    total_violations = sum(len(r["violations"]) for r in results)  # type: ignore[arg-type]
    if json_output:
        report = {
            "schema_version": "relay.lint.banned_copy.v1",
            "exit_code": 0 if total_violations == 0 else 1,
            "total_violations": total_violations,
            "surfaces": results,
        }
        print(json.dumps(report, separators=(",", ":"), ensure_ascii=True))
    else:
        for r in results:
            label = r["label"]
            if not r["root_exists"]:
                print(f"[SKIP] {label}: root does not exist")
                continue
            count = len(r["violations"])  # type: ignore[arg-type]
            if count == 0:
                print(
                    "[PASS] {label}: 0 violations across {n} files".format(
                        label=label, n=r["files_scanned"]
                    )
                )
            else:
                print(
                    "[FAIL] {label}: {n} violations across {f} files".format(
                        label=label, n=count, f=r["files_scanned"]
                    )
                )
                for v in r["violations"]:  # type: ignore[union-attr]
                    print(
                        "       {path}: matches={matches}".format(
                            path=v["path"], matches=v["matches"]
                        )
                    )
        if total_violations == 0:
            print("[OK] banned-copy lint: 0 violations across all surfaces")
        else:
            print(
                f"[FAIL] banned-copy lint: {total_violations} total violations"
            )
    return 0 if total_violations == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
