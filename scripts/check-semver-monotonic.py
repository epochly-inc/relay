#!/usr/bin/env python3
"""W12.1 SemVer monotonicity gate (VAL-W12-040).

Pre-publish gate invoked from ``.github/workflows/release-pypi.yml``.
Compares the proposed release version against the latest published
version of ``epochly-relay`` on PyPI and refuses to publish unless
the proposed version is strictly greater under SemVer ordering.

Behavior:

  * Reads the proposed version from one of (in order):
      1. ``--version`` CLI argument
      2. environment variable ``RELAY_RELEASE_VERSION``
      3. the ``GITHUB_REF_NAME`` env var with a leading ``v`` stripped
  * Reads the latest published version from PyPI's JSON API
    (``https://pypi.org/pypi/epochly-relay/json``) unless
    ``--latest`` or ``--published`` is provided (allows offline tests
    to inject values).
  * Compares the two via the pure-stdlib SemVer 2.0.0 implementation
    in :func:`parse_semver` / :func:`compare_semver`.
  * Exits 0 when the proposed version is strictly greater AND not
    equal to any prior published version; exits 1 otherwise.

This script intentionally has zero third-party dependencies. SemVer
parsing is implemented inline against the SemVer 2.0.0 specification
so the workspace's plumbing-tier tests can exercise it without
touching ``uv sync`` or the network.

This script is part of feature ``w12.1-release-pypi-trusted-publish``.
The static workflow guard (``scripts/check-pypi-publish-workflow.py``)
only verifies that the workflow YAML references this script's name.
The actual SemVer comparison runs at tag-cut time.

Exit codes (canonical mapping per contract preamble):

    0  proposed version is strictly greater than latest
    1  proposed version is equal-or-less than latest (RELAY-RELEASE-040)
    2  malformed version string
    3  invalid invocation
    4  could not read latest version from PyPI

ASCII-only output per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import sys
import urllib.error
import urllib.request
from collections.abc import Iterable
from dataclasses import dataclass

PYPI_PROJECT = "epochly-relay"
PYPI_JSON_URL = f"https://pypi.org/pypi/{PYPI_PROJECT}/json"

# SemVer 2.0.0 regex (https://semver.org/#is-there-a-suggested-regular-expression-regex-to-check-a-semver-string).
# Captures MAJOR, MINOR, PATCH, optional PRE-RELEASE, optional BUILD.
_SEMVER_RE: re.Pattern[str] = re.compile(
    r"^(?P<major>0|[1-9]\d*)"
    r"\.(?P<minor>0|[1-9]\d*)"
    r"\.(?P<patch>0|[1-9]\d*)"
    r"(?:-(?P<prerelease>"
    r"(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)"
    r"(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?"
    r"(?:\+(?P<build>[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$"
)


@dataclass(frozen=True)
class SemVer:
    """SemVer 2.0.0 version triple plus optional pre-release identifiers.

    Build metadata is parsed but intentionally not retained on this
    object: SemVer 2.0.0 declares build metadata MUST be ignored for
    precedence comparisons.
    """

    major: int
    minor: int
    patch: int
    prerelease: tuple[str, ...]  # empty tuple when absent
    raw: str

    @property
    def is_prerelease(self) -> bool:
        return bool(self.prerelease)


def parse_semver(raw: str) -> SemVer:
    """Parse ``raw`` as SemVer 2.0.0.

    Raises ``ValueError`` on malformed input. The caller converts to
    the appropriate exit code.
    """
    if not isinstance(raw, str):
        raise ValueError(f"version must be a string, got {type(raw).__name__}")
    m = _SEMVER_RE.match(raw)
    if not m:
        raise ValueError(f"'{raw}' is not a valid SemVer 2.0.0 string")
    pre_str = m.group("prerelease")
    prerelease: tuple[str, ...] = tuple(pre_str.split(".")) if pre_str else ()
    return SemVer(
        major=int(m.group("major")),
        minor=int(m.group("minor")),
        patch=int(m.group("patch")),
        prerelease=prerelease,
        raw=raw,
    )


def _prerelease_key(identifiers: tuple[str, ...]) -> tuple:
    """SemVer 2.0.0 precedence ordering for pre-release identifiers.

    Per SemVer 2.0.0 section 11:

      * Identifiers consisting of only digits are compared numerically.
      * Identifiers with letters or hyphens are compared lexically in
        ASCII sort order.
      * Numeric identifiers always have lower precedence than non-
        numeric identifiers.
      * A larger set of pre-release fields has a higher precedence
        than a smaller set, if all of the preceding identifiers are
        equal.

    We encode each identifier as a (sort_class, value) tuple so the
    default Python tuple comparison yields the SemVer-conformant order.
    """
    keyed: list[tuple] = []
    for ident in identifiers:
        if ident.isdigit():
            # Numeric: lower precedence than alphanumeric. Use class 0.
            keyed.append((0, int(ident)))
        else:
            # Alphanumeric: higher precedence. Use class 1 + raw bytes.
            keyed.append((1, ident))
    return tuple(keyed)


def compare_semver(a: SemVer, b: SemVer) -> int:
    """Return -1 if a < b, 0 if equal, 1 if a > b.

    SemVer 2.0.0 precedence: build metadata ignored; pre-release
    versions have lower precedence than the corresponding release.
    """
    if (a.major, a.minor, a.patch) != (b.major, b.minor, b.patch):
        if (a.major, a.minor, a.patch) < (b.major, b.minor, b.patch):
            return -1
        return 1
    # Major/minor/patch equal; pre-release determines precedence.
    if not a.prerelease and not b.prerelease:
        return 0
    if not a.prerelease and b.prerelease:
        # a is a release, b is a pre-release -> a > b.
        return 1
    if a.prerelease and not b.prerelease:
        return -1
    ak = _prerelease_key(a.prerelease)
    bk = _prerelease_key(b.prerelease)
    if ak < bk:
        return -1
    if ak > bk:
        return 1
    return 0


# ---------------------------------------------------------------------------
# CLI plumbing.
# ---------------------------------------------------------------------------


def _resolve_proposed_version(arg_version: str | None) -> str:
    if arg_version:
        return arg_version.lstrip("v")
    env_version = os.environ.get("RELAY_RELEASE_VERSION")
    if env_version:
        return env_version.lstrip("v")
    ref_name = os.environ.get("GITHUB_REF_NAME", "")
    if ref_name:
        return ref_name.lstrip("v")
    print(
        "FAIL: no proposed version supplied "
        "(pass --version, RELAY_RELEASE_VERSION, or GITHUB_REF_NAME)",
        file=sys.stderr,
    )
    raise SystemExit(3)


def _parse_or_die(raw: str) -> SemVer:
    try:
        return parse_semver(raw)
    except ValueError as exc:
        print(
            f"FAIL: {exc}; use 'MAJOR.MINOR.PATCH' (e.g., '0.1.0')",
            file=sys.stderr,
        )
        raise SystemExit(2) from None


def _fetch_published_versions() -> list[str]:
    try:
        with urllib.request.urlopen(PYPI_JSON_URL, timeout=15) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        # ALWAYS close the HTTPError body stream first, regardless of how
        # we handle the status code. Without this, the urllib response
        # body lingers on the HTTPError and is finalized by GC -- which
        # under Python 3.14 raises a ResourceWarning ("Implicitly cleaning
        # up <HTTPError ...>") that pytest's unraisable-exception hook
        # catches and escalates to a hard failure under the repo-wide
        # filterwarnings=error policy. Closing here prevents it on BOTH
        # the 404 success path and the abort-on-other-status path.
        code = exc.code
        fp = getattr(exc, "fp", None)
        if fp is not None:
            with contextlib.suppress(Exception):
                fp.close()
        with contextlib.suppress(Exception):
            exc.close()
        # 404 = the package has never been published. This is the EXPECTED
        # state for the FIRST release (e.g. v0.1.0) and must be treated
        # as "no prior versions", not as an error -- otherwise the first
        # publish is permanently blocked at this gate. Any other HTTP
        # error (5xx, transient network failure) still aborts.
        if code == 404:
            return []
        print(
            f"FAIL: could not query PyPI for {PYPI_PROJECT}: HTTP Error {code}",
            file=sys.stderr,
        )
        raise SystemExit(4) from None
    except Exception as exc:  # noqa: BLE001 - any other failure aborts cleanly
        print(f"FAIL: could not query PyPI for {PYPI_PROJECT}: {exc}", file=sys.stderr)
        raise SystemExit(4) from None
    releases = payload.get("releases", {})
    if not isinstance(releases, dict):
        return []
    return list(releases.keys())


def _latest_strict_semver(published: Iterable[str]) -> SemVer | None:
    parsed: list[SemVer] = []
    for raw in published:
        try:
            parsed.append(parse_semver(raw))
        except ValueError:
            # PyPI accepts PEP 440 versions that are not strict SemVer.
            # Those are invisible to this comparator; non-SemVer prior
            # publishes do not gate strict-SemVer future releases.
            continue
    if not parsed:
        return None
    # Reduce to max via repeated compare_semver.
    latest = parsed[0]
    for candidate in parsed[1:]:
        if compare_semver(candidate, latest) > 0:
            latest = candidate
    return latest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Refuse non-monotonic SemVer release versions."
    )
    parser.add_argument("--version", help="Proposed release version (overrides env).")
    parser.add_argument(
        "--latest",
        help="Latest published version (bypasses PyPI fetch; for tests).",
    )
    parser.add_argument(
        "--published",
        help=(
            "Comma-separated list of already-published versions "
            "(bypasses PyPI fetch; for tests). Takes precedence over --latest."
        ),
    )
    args = parser.parse_args(argv)

    proposed_raw = _resolve_proposed_version(args.version)
    proposed = _parse_or_die(proposed_raw)

    if args.published is not None:
        published_versions = [v.strip() for v in args.published.split(",") if v.strip()]
    elif args.latest is not None:
        published_versions = [args.latest]
    else:
        published_versions = _fetch_published_versions()

    if proposed_raw in published_versions:
        print(
            f"FAIL RELAY-RELEASE-040: version '{proposed_raw}' is already "
            "published; rollback via version increment (see runbook "
            "'No Destructive Rollback')",
            file=sys.stderr,
        )
        return 1

    latest = _latest_strict_semver(published_versions)
    if latest is not None and compare_semver(proposed, latest) <= 0:
        print(
            f"FAIL RELAY-RELEASE-040: proposed version '{proposed_raw}' is "
            f"not strictly greater than latest published version "
            f"'{latest.raw}' (monotonic per SemVer)",
            file=sys.stderr,
        )
        return 1

    latest_repr = latest.raw if latest is not None else "none"
    print(
        f"OK: proposed version '{proposed_raw}' is monotonic per SemVer "
        f"(latest published: {latest_repr})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
