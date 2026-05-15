"""JWKS cache for offline evidence verification (W5.4 VAL-W5-027).

The CLI evidence verifier MUST be able to verify a bundle without making
any outbound network call once the relevant JWKS is cached locally. This
module owns the on-disk cache layout under
``${RELAY_HOME}/jwks-cache/<host>.json`` and the read/write helpers.

Design constraints:

  * Per CLAUDE.md keystone invariant #11 the OSS verifier defaults to
    the spec-pinned trust-anchor URL declared in
    :mod:`relay_cli.commands.evidence` as ``DEFAULT_TRUST_ANCHOR_URL``.
    The cache key is the HOSTNAME of the trust-anchor URL so that BYO
    trust anchors per spec section AO.4 can co-exist with the canonical
    anchor in the same cache directory.
  * Per CLAUDE.md keystone invariant #8 every persistent file write goes
    through :func:`relay_sidecar.primitives.local_atomic_file_write`. No
    direct ``open(..., 'w')`` calls anywhere in this module.
  * Per CLAUDE.md banned pattern #13 changing the default trust-anchor
    URL is a board-level decision; the literal lives in
    :mod:`relay_cli.commands.evidence` (single canonical occurrence)
    and is passed in as a parameter here so the cache module remains
    URL-agnostic.
  * Cache files are written 0o600 (POSIX) / single-ACE-DACL (Windows)
    via the underlying primitive's default mode -- the OSS profile keeps
    the JWKS plaintext but never world-readable.

Cache file format:

    {
      "schema_version": "relay.cli.jwks_cache.v1",
      "trust_anchor_url": "<the URL the JWKS was fetched from>",
      "fetched_at": "RFC3339-Z",
      "jwks": { "keys": [ { ... }, ... ] }
    }

Verification semantics:

  * :func:`load_jwks_from_cache` returns the parsed JWKS object on cache
    hit; returns ``None`` on miss or schema mismatch (caller decides
    whether to fetch). Malformed JSON is treated as miss; the corrupted
    cache file is left in place for operator inspection (offline-only
    verification cannot safely auto-rewrite a cache the CLI did not
    fetch itself).
  * :func:`store_jwks_in_cache` writes the canonical envelope through the
    atomic primitive; the function is total (caller is responsible for
    ensuring `jwks` is a dict shape conforming to RFC 7517 sec 5).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final
from urllib.parse import urlparse

from relay_sidecar.lockfile import relay_home
from relay_sidecar.primitives import local_atomic_file_write

# Cache envelope schema version. Bump this constant if the cache file
# format changes; old caches with a mismatching version are treated as
# misses (callers re-fetch).
JWKS_CACHE_SCHEMA_VERSION: Final[str] = "relay.cli.jwks_cache.v1"

# Subdirectory under RELAY_HOME for cached JWKS documents. The directory
# name is invariant; per-host filenames are derived from the URL hostname.
JWKS_CACHE_DIRNAME: Final[str] = "jwks-cache"

# Allowed characters in a cache filename. The hostname component of a URL
# is restricted to letters/digits/dots/hyphens/colons (port) per RFC 3986
# section 3.2.2 (host) and section 3.2.3 (port). The cache filename
# replaces the colon (port separator) with an underscore so the result
# is filesystem-safe on every supported OS (Windows disallows ``:`` in
# filenames). All other RFC-3986-host characters are alphanumeric or
# the dot/hyphen pair which Windows tolerates.
_HOST_FILENAME_SAFE_RE: Final[re.Pattern[str]] = re.compile(r"[^A-Za-z0-9._-]")


def _now_rfc3339_z() -> str:
    """Return the current UTC time as an RFC 3339 ``Z`` string."""
    return (
        datetime.now(tz=UTC)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _resolve_home(home: Path | str | None) -> Path:
    """Resolve the cache base directory.

    Mirrors the convention used by ``rly sidecar`` and ``rly replay``:
    when ``home`` is empty or None, fall back to
    :func:`relay_sidecar.lockfile.relay_home` (which honors RELAY_HOME).
    Caller-supplied paths are expanduser'd so ``~`` works for tests that
    pass it in.
    """
    if home is None:
        return relay_home()
    if isinstance(home, str):
        if not home:
            return relay_home()
        return Path(home).expanduser()
    return home


def _hostname_for_url(trust_anchor_url: str) -> str:
    """Extract the hostname (and port, if present) for cache keying.

    Returns a single string suitable for embedding in a filename. Includes
    the port when the URL specifies one (``:8443`` -> ``_8443``) so that
    a self-hoster running multiple JWKS endpoints on the same host on
    different ports does not collide.

    Raises:
        ValueError: when the URL has no parseable hostname (e.g., a
        relative path or an opaque URI).
    """
    parsed = urlparse(trust_anchor_url)
    host = (parsed.hostname or "").strip().lower()
    if not host:
        raise ValueError(
            f"trust anchor URL has no hostname: {trust_anchor_url!r}"
        )
    if parsed.port is not None:
        return f"{host}_{parsed.port}"
    return host


def cache_dir(home: Path | str | None = None) -> Path:
    """Return ``${RELAY_HOME}/jwks-cache`` (resolved, not created)."""
    return _resolve_home(home) / JWKS_CACHE_DIRNAME


def cache_path_for_url(
    trust_anchor_url: str,
    *,
    home: Path | str | None = None,
) -> Path:
    """Return the cache filename for ``trust_anchor_url``.

    The filename is the URL hostname (lowercased; port appended with an
    underscore) followed by ``.json``. Any character outside the
    canonical RFC-3986-host charset is replaced with an underscore so
    the path remains valid on every supported OS.
    """
    host = _hostname_for_url(trust_anchor_url)
    safe = _HOST_FILENAME_SAFE_RE.sub("_", host)
    return cache_dir(home) / f"{safe}.json"


def load_jwks_from_cache(
    trust_anchor_url: str,
    *,
    home: Path | str | None = None,
) -> dict[str, Any] | None:
    """Return the cached JWKS for ``trust_anchor_url`` or None on miss.

    Returns:
        The parsed JWKS object (RFC 7517 ``{"keys": [...]}``) on cache
        hit. Returns ``None`` for any of:

          * cache file does not exist
          * cache file is empty
          * cache file is not valid JSON
          * envelope ``schema_version`` does not match
          * envelope ``trust_anchor_url`` does not match the requested URL
          * envelope ``jwks`` field is missing or malformed

    Notes:
        Returning None for malformed cache content is a deliberate
        design choice: an offline verifier cannot safely auto-rewrite a
        corrupted cache it did not fetch itself; the operator must
        re-fetch (online) or repair the file.
    """
    path = cache_path_for_url(trust_anchor_url, home=home)
    if not path.exists():
        return None
    try:
        raw = path.read_bytes()
    except (OSError, PermissionError):
        return None
    if not raw:
        return None
    try:
        envelope = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(envelope, dict):
        return None
    if envelope.get("schema_version") != JWKS_CACHE_SCHEMA_VERSION:
        return None
    if envelope.get("trust_anchor_url") != trust_anchor_url:
        # Cache key collision (e.g., file named for a host that serves
        # multiple URLs). Treat as miss so we never authenticate a
        # bundle against a JWKS the operator did not associate with this
        # exact URL.
        return None
    jwks = envelope.get("jwks")
    if not isinstance(jwks, dict):
        return None
    keys = jwks.get("keys")
    if not isinstance(keys, list):
        return None
    return jwks


def store_jwks_in_cache(
    trust_anchor_url: str,
    jwks: dict[str, Any],
    *,
    home: Path | str | None = None,
) -> Path:
    """Write the JWKS to ``${RELAY_HOME}/jwks-cache/<host>.json`` atomically.

    Args:
        trust_anchor_url: the canonical URL the JWKS was fetched from.
            Stored alongside the JWKS so cache loads can verify the URL
            still matches at read time (rejecting stale caches whose URL
            assignment has changed).
        jwks: the parsed JWKS object (RFC 7517 ``{"keys": [...]}``).
        home: optional base directory override (test seam).

    Returns:
        The absolute path the cache was written to.

    Raises:
        ValueError: when ``trust_anchor_url`` has no hostname (delegated
            from :func:`_hostname_for_url`).
    """
    path = cache_path_for_url(trust_anchor_url, home=home)
    path.parent.mkdir(parents=True, exist_ok=True)
    envelope: dict[str, Any] = {
        "schema_version": JWKS_CACHE_SCHEMA_VERSION,
        "trust_anchor_url": trust_anchor_url,
        "fetched_at": _now_rfc3339_z(),
        "jwks": jwks,
    }
    payload = json.dumps(
        envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8") + b"\n"
    local_atomic_file_write(path, payload, mode=0o600)
    return path


__all__ = [
    "JWKS_CACHE_DIRNAME",
    "JWKS_CACHE_SCHEMA_VERSION",
    "cache_dir",
    "cache_path_for_url",
    "load_jwks_from_cache",
    "store_jwks_in_cache",
]
