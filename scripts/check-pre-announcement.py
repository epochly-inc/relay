#!/usr/bin/env python3
"""W12.1 Pre-announcement gate (VAL-W12-046).

Pre-publish gate invoked from ``.github/workflows/release-pypi.yml``.
Enforces the spec section Q.2 rule: "major changes pre-announced 7 days
in advance." A tag annotated as ``breaking: true`` MUST NOT publish
unless an announcement file with a matching ``target_version`` exists
in ``docs/release/announcements/`` AND was published at least 7 days
before the proposed release.

A tag is "breaking" when its annotated tag message contains the
literal token ``RELAY-BREAKING-CHANGE`` on its own line. The release
engineer sets this when cutting the tag (see runbook).

Behavior:

  * Reads the proposed tag's name (and message, if available) from
    one of:
      - ``--tag`` + ``--message`` CLI args (preferred for tests)
      - environment variables ``RELAY_RELEASE_TAG`` + ``RELAY_RELEASE_TAG_MESSAGE``
      - ``git tag -l --format='%(contents)' <ref>`` against ``GITHUB_REF_NAME``
  * If the tag is non-breaking, exits 0 (no-op).
  * If the tag is breaking, scans ``docs/release/announcements/`` for
    a matching announcement file:
      - frontmatter ``target_version:`` equals the tag's version
      - frontmatter ``breaking: true``
      - frontmatter ``published_at:`` is RFC 3339 UTC AND is at least
        7 days earlier than ``--now`` (defaults to current UTC time)
  * Exits 0 if a qualifying announcement exists; exits 1 with
    ``RELAY-RELEASE-046`` otherwise.

This script intentionally has zero third-party dependencies; the
frontmatter parser is a tiny stdlib-only implementation.

Exit codes:

    0  no pre-announcement required, OR a qualifying announcement exists
    1  breaking tag without qualifying announcement (RELAY-RELEASE-046)
    2  malformed announcement frontmatter
    3  invalid invocation
"""

from __future__ import annotations

import argparse
import datetime as dt
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

BREAKING_TOKEN = "RELAY-BREAKING-CHANGE"
ANNOUNCEMENTS_RELDIR = "docs/release/announcements"
MIN_LEAD_DAYS = 7

# Required keys in announcement frontmatter.
_REQUIRED_KEYS: tuple[str, ...] = ("target_version", "breaking", "published_at")


@dataclass(frozen=True)
class Announcement:
    path: Path
    target_version: str
    breaking: bool
    published_at: dt.datetime


def _strip_v(raw: str) -> str:
    return raw[1:] if raw.startswith("v") else raw


def _resolve_tag(arg_tag: str | None) -> str:
    if arg_tag:
        return arg_tag
    env_tag = os.environ.get("RELAY_RELEASE_TAG")
    if env_tag:
        return env_tag
    ref_name = os.environ.get("GITHUB_REF_NAME", "")
    if ref_name:
        return ref_name
    print(
        "FAIL: no tag supplied (pass --tag, RELAY_RELEASE_TAG, "
        "or GITHUB_REF_NAME)",
        file=sys.stderr,
    )
    raise SystemExit(3)


def _resolve_message(arg_message: str | None, tag: str) -> str:
    if arg_message is not None:
        return arg_message
    env_msg = os.environ.get("RELAY_RELEASE_TAG_MESSAGE")
    if env_msg is not None:
        return env_msg
    # Fall back to git. ``%(contents)`` includes the annotated tag's
    # body (without the trailing PGP signature) and is empty for
    # lightweight tags.
    try:
        result = subprocess.run(  # noqa: S603 - command literal, args validated
            ["git", "tag", "-l", "--format=%(contents)", tag],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        print(
            f"FAIL: could not read tag '{tag}' message via git: {exc}",
            file=sys.stderr,
        )
        raise SystemExit(3) from None
    if result.returncode != 0:
        return ""
    return result.stdout


def _is_breaking(message: str) -> bool:
    """Return True when the tag message contains the breaking-change token.

    The token must appear on its own line (whitespace-only padding
    allowed) to avoid false positives from prose mentions of the
    token name.
    """
    return any(line.strip() == BREAKING_TOKEN for line in message.splitlines())


def _parse_frontmatter(text: str, path: Path) -> dict[str, str]:
    """Parse the YAML-frontmatter block at the top of ``text``.

    We support only the simple ``key: value`` form (no nested
    structures); announcement frontmatter is intentionally flat.
    Raises ``ValueError`` on malformed input.
    """
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        raise ValueError(
            f"announcement {path} missing leading '---' frontmatter delimiter"
        )
    fm: dict[str, str] = {}
    closed = False
    for line in lines[1:]:
        if line.strip() == "---":
            closed = True
            break
        if not line.strip() or line.strip().startswith("#"):
            continue
        if ":" not in line:
            raise ValueError(
                f"announcement {path} frontmatter line missing ':' -> '{line}'"
            )
        key, _, value = line.partition(":")
        fm[key.strip()] = value.strip()
    if not closed:
        raise ValueError(
            f"announcement {path} frontmatter missing closing '---' delimiter"
        )
    return fm


def _parse_announcement(path: Path) -> Announcement:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"cannot read announcement {path}: {exc}") from None
    fm = _parse_frontmatter(text, path)
    for k in _REQUIRED_KEYS:
        if k not in fm:
            raise ValueError(f"announcement {path} missing required key '{k}'")
    breaking_raw = fm["breaking"].lower()
    if breaking_raw not in ("true", "false"):
        raise ValueError(
            f"announcement {path} frontmatter 'breaking' must be true|false"
        )
    breaking = breaking_raw == "true"
    published_raw = fm["published_at"]
    try:
        # Accept trailing 'Z' as UTC per RFC 3339.
        normalized = published_raw.replace("Z", "+00:00")
        published_at = dt.datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError(
            f"announcement {path} 'published_at' is not RFC 3339: {exc}"
        ) from None
    if published_at.tzinfo is None:
        raise ValueError(
            f"announcement {path} 'published_at' must be timezone-aware (RFC 3339)"
        )
    return Announcement(
        path=path,
        target_version=_strip_v(fm["target_version"]),
        breaking=breaking,
        published_at=published_at.astimezone(dt.UTC),
    )


def _load_announcements(ann_dir: Path) -> list[Announcement]:
    if not ann_dir.is_dir():
        return []
    out: list[Announcement] = []
    for entry in sorted(ann_dir.iterdir()):
        if not entry.is_file():
            continue
        if entry.suffix != ".md":
            continue
        if entry.name == "README.md":
            continue
        out.append(_parse_announcement(entry))
    return out


def _find_qualifying(
    announcements: list[Announcement],
    target_version: str,
    now: dt.datetime,
) -> Announcement | None:
    deadline = now - dt.timedelta(days=MIN_LEAD_DAYS)
    for ann in announcements:
        if ann.target_version != target_version:
            continue
        if not ann.breaking:
            continue
        if ann.published_at > deadline:
            continue
        return ann
    return None


def _parse_now(raw: str | None) -> dt.datetime:
    if not raw:
        return dt.datetime.now(dt.UTC)
    normalized = raw.replace("Z", "+00:00")
    parsed = dt.datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise SystemExit("FAIL: --now must be timezone-aware RFC 3339")
    return parsed.astimezone(dt.UTC)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Refuse breaking releases without 7-day pre-announcement."
    )
    parser.add_argument("--tag", help="Proposed tag name (e.g., v1.0.0).")
    parser.add_argument(
        "--message",
        default=None,
        help=(
            "Annotated tag message; if absent we read it from "
            "RELAY_RELEASE_TAG_MESSAGE or via 'git tag -l --format'."
        ),
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=None,
        help=(
            "Repository root (defaults to cwd). The announcements directory "
            "is searched at <repo-root>/docs/release/announcements/."
        ),
    )
    parser.add_argument(
        "--now",
        default=None,
        help="Override 'now' for tests; RFC 3339 UTC. Defaults to current time.",
    )
    args = parser.parse_args(argv)

    tag = _resolve_tag(args.tag)
    version = _strip_v(tag)
    message = _resolve_message(args.message, tag)
    breaking = _is_breaking(message)

    if not breaking:
        print(
            f"OK: tag '{tag}' is non-breaking; no pre-announcement required"
        )
        return 0

    repo_root = (args.repo_root or Path.cwd()).resolve()
    ann_dir = repo_root / ANNOUNCEMENTS_RELDIR
    try:
        announcements = _load_announcements(ann_dir)
    except ValueError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 2

    try:
        now = _parse_now(args.now)
    except SystemExit:
        return 3

    match = _find_qualifying(announcements, version, now)
    if match is None:
        print(
            f"FAIL RELAY-RELEASE-046: breaking tag '{tag}' has no qualifying "
            f"pre-announcement (need a file in {ANNOUNCEMENTS_RELDIR} with "
            f"target_version: {version}, breaking: true, and published_at "
            f"at least {MIN_LEAD_DAYS} days before now={now.isoformat()})",
            file=sys.stderr,
        )
        return 1

    print(
        f"OK: breaking tag '{tag}' has qualifying announcement at "
        f"{match.path.relative_to(repo_root)} "
        f"(published_at={match.published_at.isoformat()})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
