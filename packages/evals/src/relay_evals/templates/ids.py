"""Deterministic canonical assertion-id derivation for W9.2 templates.

Per VAL-W9-011 every assertion-template return value carries a stable
``assertion_id`` matching::

    ^VAL-[A-Z0-9]+(-[A-Z0-9]+)*-[0-9]{3,}$

The regex anchors the contract assertion-id grammar (spec section D.5
EvalAssertion line 3860; D.6 CoverageOwner line 3879) and is shared with
the gate engine and CLI surfaces. The id is deterministic in two senses:

  1. Calling the same template twice with the same input MUST produce
     the same ``assertion_id``.
  2. Calling the same template with materially different inputs MUST
     produce different ``assertion_id`` values (collision-resistant via
     SHA-256 over the JCS-canonicalized seed).

The numeric tail is derived from the first 12 hex chars of the
SHA-256-over-JCS digest, parsed as an unsigned int, modulo 10**9 (to
keep the printed tail at 9 digits). The slug is uppercased and rinsed
of non-``[A-Z0-9-]`` characters; collisions inside the slug component
are unlikely because the numeric tail carries the bulk of the entropy.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Final

# Re-export the canonical relay sha256 / canonical bytes machinery from
# the contracts package so we never re-implement JCS.
from relay_contracts.canonical import jcs_canonicalize

# Per VAL-W9-011: VAL-<DOMAIN>-<SLUG>-NNN where the body components are
# uppercase alphanumerics separated by single hyphens and the numeric
# tail is at least three digits.
ASSERTION_ID_PATTERN: Final[str] = r"^VAL-[A-Z0-9]+(-[A-Z0-9]+)*-[0-9]{3,}$"
ASSERTION_ID_RE: Final[re.Pattern[str]] = re.compile(ASSERTION_ID_PATTERN)

# Maximum permitted slug component length (ASCII-only). Long inputs
# truncate; the numeric tail then disambiguates.
_MAX_SLUG_LENGTH: Final[int] = 32

# Width of the printed numeric tail. Nine digits gives ~1e9 unique
# tails per (domain, slug) which is more than ample for v0.1 template
# corpus sizes.
_TAIL_WIDTH: Final[int] = 9
_TAIL_MOD: Final[int] = 10 ** _TAIL_WIDTH

# Hex prefix consumed from the SHA-256 digest to derive the tail. 12
# hex chars = 48 bits, comfortably above 30 bits of tail entropy.
_TAIL_HEX_PREFIX: Final[int] = 12

# Slug normaliser: anything not [A-Z0-9-] is replaced by '-' after
# uppercasing. Consecutive hyphens collapse and trailing/leading
# hyphens are stripped so the regex pattern matches.
_SLUG_DISALLOWED_RE: Final[re.Pattern[str]] = re.compile(r"[^A-Z0-9-]+")
_SLUG_HYPHEN_RUN_RE: Final[re.Pattern[str]] = re.compile(r"-{2,}")


def _normalize_slug(raw: str) -> str:
    """Return a canonical slug component matching ``[A-Z0-9]+(-[A-Z0-9]+)*``.

    Empty input falls back to ``UNNAMED`` so the regex still matches
    even on degenerate input. Truncation occurs after normalisation so
    the truncation point lands on a deterministic byte.
    """
    if not isinstance(raw, str):
        raw = str(raw)
    upper = raw.upper()
    cleaned = _SLUG_DISALLOWED_RE.sub("-", upper)
    cleaned = _SLUG_HYPHEN_RUN_RE.sub("-", cleaned).strip("-")
    if not cleaned:
        cleaned = "UNNAMED"
    if len(cleaned) > _MAX_SLUG_LENGTH:
        cleaned = cleaned[:_MAX_SLUG_LENGTH].rstrip("-")
    return cleaned


def _tail_from_seed(seed_bytes: bytes) -> str:
    """Derive the deterministic numeric tail (zero-padded to 9 digits)."""
    digest = hashlib.sha256(seed_bytes).hexdigest()
    n = int(digest[:_TAIL_HEX_PREFIX], 16) % _TAIL_MOD
    return f"{n:0{_TAIL_WIDTH}d}"


def derive_assertion_id(*, domain: str, slug: str, seed: Any) -> str:
    """Return a canonical ``VAL-<DOMAIN>-<SLUG>-NNN`` assertion id.

    The id is fully determined by the three inputs:

      - ``domain`` -- short uppercase token identifying the template
        family (``COVERAGE``, ``TOOLARG``, ``SCHEMAMATCH``).
      - ``slug``   -- short identifier inside the domain (typically the
        bound ``tool_name`` / ``schema_id`` / ``owner_email`` local part).
      - ``seed``   -- any JCS-canonicalisable Python value (dict, list,
        str, int, etc.). The SHA-256 of the JCS bytes drives the
        numeric tail.

    The returned string is guaranteed to match
    :data:`ASSERTION_ID_PATTERN` (asserted before return so a malformed
    derivation surfaces as ``ValueError`` rather than an invalid id
    leaking into ``eval_results``).
    """
    domain_norm = _normalize_slug(domain)
    slug_norm = _normalize_slug(slug)
    seed_bytes = jcs_canonicalize(seed) if not isinstance(seed, bytes | bytearray) else bytes(seed)
    tail = _tail_from_seed(seed_bytes)
    candidate = f"VAL-{domain_norm}-{slug_norm}-{tail}"
    if not ASSERTION_ID_RE.match(candidate):  # pragma: no cover - guarded by normalisation
        raise ValueError(
            f"Derived assertion_id {candidate!r} does not match "
            f"{ASSERTION_ID_PATTERN!r}; this is an internal invariant "
            "violation in derive_assertion_id."
        )
    return candidate


__all__ = [
    "ASSERTION_ID_PATTERN",
    "ASSERTION_ID_RE",
    "derive_assertion_id",
]
