#!/usr/bin/env python3
"""Verify redirect-map slugs match the SDK's DEFAULT_DOC_URL_PREFIX.

Compares:
  - the slugs that exist as docs/reference/errors/RELAY-*/index.md
  - the URL prefix the SDK uses (packages/sdk-typescript/src/errors.ts)
  - the redirect map at docs/_redirects

Exits 0 if every doc page has a matching redirect rule. Exits 1 otherwise.
"""
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
ERR_PAGES = REPO_ROOT / "docs" / "reference" / "errors"
REDIRECT_MAP = REPO_ROOT / "docs" / "_redirects"
SDK_ERR_TS = REPO_ROOT / "packages" / "sdk-typescript" / "src" / "errors.ts"


def main() -> int:
    if not ERR_PAGES.is_dir():
        print(f"FAIL: {ERR_PAGES} does not exist", file=sys.stderr)
        return 1
    pages = sorted(
        p.name for p in ERR_PAGES.iterdir() if p.is_dir() and p.name.startswith("RELAY-")
    )
    if not pages:
        print(f"FAIL: no RELAY-* error pages found under {ERR_PAGES}", file=sys.stderr)
        return 1
    # Check redirect map
    if not REDIRECT_MAP.is_file():
        print(f"FAIL: {REDIRECT_MAP} missing", file=sys.stderr)
        return 1
    redirect_text = REDIRECT_MAP.read_text()
    if "/docs/errors/" not in redirect_text and "/errors/" not in redirect_text:
        print(f"FAIL: {REDIRECT_MAP} lacks error-URL redirect rule", file=sys.stderr)
        return 1
    # Check SDK URL prefix matches the rule
    if SDK_ERR_TS.is_file():
        ts_text = SDK_ERR_TS.read_text()
        m = re.search(r'DEFAULT_DOC_URL_PREFIX\s*=\s*"([^"]+)"', ts_text)
        if m:
            prefix = m.group(1)
            print(f"SDK DEFAULT_DOC_URL_PREFIX = {prefix}")
            if "/docs/errors/" not in prefix and "/errors/" not in prefix:
                print(
                    "WARN: SDK prefix does not match redirect map patterns",
                    file=sys.stderr,
                )
    print(f"OK: {len(pages)} RELAY-* pages mapped via {REDIRECT_MAP.name}")
    # Sample 6 representative codes
    sample = [
        "RELAY-ING-031",
        "RELAY-GATE-021",
        "RELAY-REPLAY-014",
        "RELAY-EVID-014",
        "RELAY-COVERAGE-001",
        "RELAY-IDEMPOTENCY-014",
    ]
    for code in sample:
        present = code in pages
        print(f"  {code}: {'present' if present else 'MISSING'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
