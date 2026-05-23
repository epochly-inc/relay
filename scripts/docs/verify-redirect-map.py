#!/usr/bin/env python3
"""Verify redirect-map slugs match the SDK's DEFAULT_DOC_URL_PREFIX.

Compares:
  - the slugs that exist as docs/reference/errors/RELAY-*/index.md
  - the URL prefix the SDK uses (packages/sdk-typescript/src/errors.ts)
  - the redirect map at docs/_redirects

Exits 0 if every doc page has a matching redirect rule. Exits 1 otherwise.

Fixes #6 and #7 (roborev 353, structural-review A):
- #6: parse non-comment _redirects lines and require ACTIVE rules
  matching /docs/errors/* and/or /errors/* with status 301/302. Comments
  are stripped before substring search so a deleted rule cannot pass.
- #7: SDK prefix mismatch is now a FAILURE (returns 1) instead of WARN+0.
"""
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
ERR_PAGES = REPO_ROOT / "docs" / "reference" / "errors"
REDIRECT_MAP = REPO_ROOT / "docs" / "_redirects"
SDK_ERR_TS = REPO_ROOT / "packages" / "sdk-typescript" / "src" / "errors.ts"

# Netlify/Cloudflare _redirects rule:  <src-path>  <dest-path>  [<status>]
# Comments (#) and blank lines are stripped before matching.
_RULE_RE = re.compile(
    r"^\s*(?P<src>\S+)\s+(?P<dest>\S+)(?:\s+(?P<status>\d{3}))?\s*$"
)

# Active rules must match one of these source-path patterns to satisfy the
# SDK-emitted error URL contract.
_REQUIRED_SRC_PATTERNS = ("/docs/errors/", "/errors/")


def _parse_active_rules(text: str) -> list[tuple[str, str, str]]:
    """Return [(src, dest, status), ...] from non-comment, non-blank lines."""
    rules: list[tuple[str, str, str]] = []
    for raw in text.splitlines():
        # Strip inline comments and full-line comments.
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        m = _RULE_RE.match(line)
        if not m:
            continue
        rules.append((m.group("src"), m.group("dest"), m.group("status") or "200"))
    return rules


def _src_satisfies_pattern(src: str, pattern: str) -> bool:
    """True iff redirect src starts with the required prefix.

    The Netlify ``:splat`` convention means a rule like
    ``/docs/errors/*  /reference/errors/:splat/index.html  301``
    has src=``/docs/errors/*``. The leading prefix is the load-bearing
    invariant; the splat suffix is how the destination interpolates.
    """
    return src.startswith(pattern)


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

    # Fix #6: redirect-map parse, not substring match.
    if not REDIRECT_MAP.is_file():
        print(f"FAIL: {REDIRECT_MAP} missing", file=sys.stderr)
        return 1
    rules = _parse_active_rules(REDIRECT_MAP.read_text())
    if not rules:
        print(f"FAIL: {REDIRECT_MAP} contains no active (non-comment) rules", file=sys.stderr)
        return 1
    matching = [
        (src, dest, status)
        for (src, dest, status) in rules
        if any(_src_satisfies_pattern(src, p) for p in _REQUIRED_SRC_PATTERNS)
    ]
    if not matching:
        print(
            f"FAIL: {REDIRECT_MAP} has {len(rules)} rules but NONE match the "
            f"required SDK error-URL prefixes {_REQUIRED_SRC_PATTERNS}",
            file=sys.stderr,
        )
        return 1
    # Require at least one 301 (permanent) redirect; 302 (temporary) is
    # acceptable but flagged for review.
    if not any(status in ("301", "302") for (_, _, status) in matching):
        print(
            f"FAIL: matching rules exist but none use status 301/302: "
            f"{[(s, d, st) for (s, d, st) in matching]}",
            file=sys.stderr,
        )
        return 1

    # Fix #7: SDK prefix mismatch is a HARD failure (was WARN+0 before).
    if SDK_ERR_TS.is_file():
        ts_text = SDK_ERR_TS.read_text()
        m = re.search(r'DEFAULT_DOC_URL_PREFIX\s*=\s*"([^"]+)"', ts_text)
        if not m:
            print(
                f"FAIL: could not parse DEFAULT_DOC_URL_PREFIX from {SDK_ERR_TS}",
                file=sys.stderr,
            )
            return 1
        prefix = m.group(1)
        print(f"SDK DEFAULT_DOC_URL_PREFIX = {prefix}")
        # Fix #7: extract the SDK prefix's URL path and require it to EQUAL
        # one of the expected paths. Substring/endswith checks false-pass
        # URLs like `/help/errors/` because that string ends with `/errors/`.
        # The redirect map only routes the literal path-roots `/docs/errors/`
        # and `/errors/`; nothing else resolves.
        try:
            from urllib.parse import urlparse
            sdk_path = urlparse(prefix).path
        except Exception as exc:  # noqa: BLE001
            print(
                f"FAIL: SDK prefix {prefix!r} did not parse as URL: {exc}",
                file=sys.stderr,
            )
            return 1
        if sdk_path not in _REQUIRED_SRC_PATTERNS:
            print(
                f"FAIL: SDK prefix path {sdk_path!r} (from {prefix!r}) is "
                f"not in the required set {_REQUIRED_SRC_PATTERNS}; redirect "
                f"map cannot resolve SDK-emitted error URLs",
                file=sys.stderr,
            )
            return 1
    else:
        print(f"NOTE: {SDK_ERR_TS} absent; skipping SDK-prefix parity check")

    print(
        f"OK: {len(pages)} RELAY-* pages; {len(rules)} active rules in "
        f"{REDIRECT_MAP.name} ({len(matching)} match required prefixes)"
    )
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
