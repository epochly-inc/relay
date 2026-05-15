"""Trust-anchor JWKS resolver for the OSS verifier (W10.1).

Owns the bundled-JWKS asset loader, the cached-JWKS reader, and the
top-level :func:`resolve_jwks` orchestration that selects which JWKS
source to use based on operator inputs (offline flag, BYO --trust-anchor
URL, BYO config file, cache state) per VAL-W10-003 through VAL-W10-009.

Source precedence (top of file is authoritative; the implementation
below mirrors this order exactly):

  1. ``offline=True`` -> bundled JWKS only; no cache, no network.
     Source label: :data:`TRUST_ANCHOR_SOURCE_BUNDLED`.
  2. BYO URL via flag (``--trust-anchor <url>``) or config
     (``trust_anchor_url = "..."``) -> use that URL. Sub-precedence:
     flag overrides config; config overrides default. Source label:
     :data:`TRUST_ANCHOR_SOURCE_BYO_FLAG` or
     :data:`TRUST_ANCHOR_SOURCE_BYO_CONFIG`.
  3. Otherwise -> compiled-in default URL from
     :data:`relay_verifier.constants.DEFAULT_JWKS_URL`. Source label
     when fetched online: :data:`TRUST_ANCHOR_SOURCE_LIVE`.
  4. Live fetch fails AND fresh cache exists -> use cache + emit WARN
     to stderr with ``cache_age_seconds`` and
     ``cache_staleness_threshold_seconds`` (VAL-W10-007). Source label:
     :data:`TRUST_ANCHOR_SOURCE_CACHE`.
  5. Live fetch fails AND no fresh cache AND bundled missing -> raise
     :class:`relay_verifier.errors.RelayJWKSUnavailableError`
     (VAL-W10-008). NO silent fallback path.

Per CLAUDE.md keystone invariant #11 the OSS verifier defaults to the
spec-pinned trust anchor (single canonical occurrence lives in
:mod:`relay_verifier.constants`). Per banned pattern #13 changing the
default constant is a board-level decision; the BYO mechanisms here are
the supported escape hatch for forks and self-hosters.

The loader is **import-boundary safe**: it does NOT depend on the CLI
or sidecar. The cache reader implements the same on-disk envelope shape
as ``packages/cli/src/relay_cli/jwks_cache.py`` so the two packages can
share an operator's cache directory without conflict.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import importlib.resources
import json
import os
import re
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final
from urllib.parse import urlparse

from .constants import DEFAULT_JWKS_URL, VERIFIER_PACKAGE_NAME
from .errors import (
    RelayBundledJWKSMissingError,
    RelayConfigInvalidError,
    RelayJWKSUnavailableError,
)

# -----------------------------------------------------------------------------
# Cache envelope constants (must match packages/cli/src/relay_cli/jwks_cache.py
# so an operator's existing cache directory works with either package).
# -----------------------------------------------------------------------------

JWKS_CACHE_SCHEMA_VERSION: Final[str] = "relay.cli.jwks_cache.v1"
"""Envelope schema version. Identical to the CLI's value (see
``packages/cli/src/relay_cli/jwks_cache.py:67``) so the two packages
interoperate on shared cache files."""

JWKS_CACHE_DIRNAME: Final[str] = "jwks-cache"
"""Subdirectory under ``RELAY_HOME`` where cache files live."""

# Staleness budget for the cache fallback path (VAL-W10-007). Caches older
# than this are treated as miss and the loader continues to the bundled
# JWKS rather than authenticate a bundle against a stale key set. The
# value mirrors spec section L.5 (trust bundle drift) -- 7 days is the
# documented operator-facing window for "acceptable" offline drift.
CACHE_STALENESS_THRESHOLD_SECONDS: Final[int] = 7 * 24 * 60 * 60


# -----------------------------------------------------------------------------
# Trust-anchor source labels (VAL-W10-004 / VAL-W10-005)
# -----------------------------------------------------------------------------
#
# The :class:`JWKSLoadResult.source` field carries one of these literal
# strings; downstream code emits it in the verifier output JSON envelope
# as ``trust_anchor_source``.

TRUST_ANCHOR_SOURCE_LIVE: Final[str] = "live_fetch"
TRUST_ANCHOR_SOURCE_CACHE: Final[str] = "cached_jwks"
TRUST_ANCHOR_SOURCE_BUNDLED: Final[str] = "bundled_jwks"
TRUST_ANCHOR_SOURCE_BYO_FLAG: Final[str] = "byo_flag"
TRUST_ANCHOR_SOURCE_BYO_CONFIG: Final[str] = "byo_config"


# -----------------------------------------------------------------------------
# Bundled JWKS asset filename (importlib.resources lookup)
# -----------------------------------------------------------------------------
#
# The wheel ships :data:`BUNDLED_JWKS_ASSET` next to this module; the
# hatch wheel target's ``force-include`` rule in pyproject.toml ensures
# the file lands inside the wheel's ``relay_verifier/`` directory.

BUNDLED_JWKS_ASSET: Final[str] = "bundled_jwks.json"


# Filesystem-safe charset for the per-host cache filename (mirrors
# packages/cli/src/relay_cli/jwks_cache.py:80).
_HOST_FILENAME_SAFE_RE: Final[re.Pattern[str]] = re.compile(r"[^A-Za-z0-9._-]")


# -----------------------------------------------------------------------------
# Result type
# -----------------------------------------------------------------------------


@dataclass(frozen=True)
class JWKSLoadResult:
    """Output of :func:`resolve_jwks`.

    Attributes:
        jwks: the parsed JWKS dict (RFC 7517 ``{"keys": [...]}``).
        source: one of the ``TRUST_ANCHOR_SOURCE_*`` literals describing
            which loader produced ``jwks``.
        trust_anchor_url: the URL the loader was asked about; equal to
            the BYO URL when overridden, otherwise
            :data:`relay_verifier.constants.DEFAULT_JWKS_URL`.
        warnings: list of structured WARN dicts the caller should emit
            on stderr. Each entry has ``schema_version``, ``code``,
            ``level`` ("warn"), and an optional ``message`` plus
            source-specific fields (e.g., ``cache_age_seconds``).
    """

    jwks: dict[str, Any]
    source: str
    trust_anchor_url: str
    warnings: list[dict[str, Any]] = field(default_factory=list)


# Type alias for the network-fetch callable. Defining it as a Callable
# alias rather than a Protocol keeps it test-injectable without a class.
NetworkFetcher = Callable[[str], dict[str, Any]]
"""Signature: ``fetch(url) -> jwks_dict``. Raise any exception to signal
fetch failure (the resolver catches Exception and falls back).

For ``file://`` URLs the fetcher may read the file directly. For
``https://`` URLs the fetcher uses whatever HTTP client the caller
prefers; the verifier package does NOT bundle an HTTP client because
``offline``-mode verification (VAL-W10-004 / VAL-W10-009) MUST NOT
import a transport. The default in :func:`resolve_jwks` is ``None``,
which is equivalent to ``offline=True`` (no live fetch attempted).
"""


# -----------------------------------------------------------------------------
# Bundled JWKS loader
# -----------------------------------------------------------------------------


def load_bundled_jwks() -> dict[str, Any]:
    """Load the JWKS shipped inside the wheel.

    Uses :mod:`importlib.resources` so the lookup works from a zipped
    wheel, an editable install, and a built sdist alike. Does NOT touch
    the network or the JWKS cache directory.

    Returns:
        Parsed JWKS dict on success.

    Raises:
        RelayBundledJWKSMissingError: when the asset is absent, empty,
            unreadable, not valid JSON, or fails the minimal RFC 7517
            shape check (top-level object with a ``keys`` list).
    """
    try:
        resource = importlib.resources.files(VERIFIER_PACKAGE_NAME).joinpath(
            BUNDLED_JWKS_ASSET
        )
        raw = resource.read_bytes()
    except (FileNotFoundError, ModuleNotFoundError, OSError) as exc:
        raise RelayBundledJWKSMissingError(
            f"bundled JWKS asset {BUNDLED_JWKS_ASSET!r} not found in "
            f"package {VERIFIER_PACKAGE_NAME!r}: {exc}",
            details={"asset": BUNDLED_JWKS_ASSET, "package": VERIFIER_PACKAGE_NAME},
        ) from exc
    if not raw:
        raise RelayBundledJWKSMissingError(
            f"bundled JWKS asset {BUNDLED_JWKS_ASSET!r} is empty",
            details={"asset": BUNDLED_JWKS_ASSET},
        )
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise RelayBundledJWKSMissingError(
            f"bundled JWKS asset is not valid UTF-8 JSON: {exc}",
            details={"asset": BUNDLED_JWKS_ASSET},
        ) from exc
    if not isinstance(parsed, dict):
        raise RelayBundledJWKSMissingError(
            "bundled JWKS root must be a JSON object",
            details={"asset": BUNDLED_JWKS_ASSET},
        )
    keys = parsed.get("keys")
    if not isinstance(keys, list):
        raise RelayBundledJWKSMissingError(
            "bundled JWKS missing 'keys' array (RFC 7517 sec 5)",
            details={"asset": BUNDLED_JWKS_ASSET},
        )
    return parsed


# -----------------------------------------------------------------------------
# Cache loader (mirrors packages/cli/src/relay_cli/jwks_cache.py shape)
# -----------------------------------------------------------------------------


def _relay_home_default() -> Path:
    """Return the default ``RELAY_HOME`` for cache lookups.

    Honors the ``RELAY_HOME`` env var (the sidecar/CLI convention). Falls
    back to ``~/.relay``. The verifier package does NOT import
    ``relay_sidecar.lockfile.relay_home`` to keep the import boundary
    clean -- this duplicates the resolution logic minimally instead.
    """
    env = os.environ.get("RELAY_HOME", "").strip()
    if env:
        return Path(env).expanduser()
    return Path("~/.relay").expanduser()


def _hostname_for_url(url: str) -> str:
    """Extract the cache-key hostname (and port, if present) from a URL."""
    parsed = urlparse(url)
    host = (parsed.hostname or "").strip().lower()
    if not host:
        raise ValueError(f"trust anchor URL has no hostname: {url!r}")
    if parsed.port is not None:
        return f"{host}_{parsed.port}"
    return host


def _cache_path_for_url(url: str, *, home: Path | None = None) -> Path:
    """Return the cache filename for ``url`` (see CLI helper for parity)."""
    base = home or _relay_home_default()
    host = _hostname_for_url(url)
    safe = _HOST_FILENAME_SAFE_RE.sub("_", host)
    return base / JWKS_CACHE_DIRNAME / f"{safe}.json"


def load_cached_jwks(
    url: str,
    *,
    home: Path | None = None,
) -> tuple[dict[str, Any], int] | None:
    """Load the cached JWKS envelope for ``url``.

    Returns:
        ``(jwks, cache_age_seconds)`` on cache hit. ``cache_age_seconds``
        is the wall-clock difference between now and the envelope's
        ``fetched_at`` timestamp, computed in UTC. The caller compares
        the age against :data:`CACHE_STALENESS_THRESHOLD_SECONDS` to
        decide whether to use the cache.

        ``None`` for any of: file missing, file empty, file not valid
        JSON, envelope schema mismatch, envelope ``trust_anchor_url``
        mismatch, ``jwks`` field missing/malformed. Mirrors the CLI's
        cache loader exactly so the same on-disk file works with either
        package.
    """
    path = _cache_path_for_url(url, home=home)
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
    if envelope.get("trust_anchor_url") != url:
        return None
    jwks = envelope.get("jwks")
    if not isinstance(jwks, dict):
        return None
    keys = jwks.get("keys")
    if not isinstance(keys, list):
        return None
    fetched_at_s = envelope.get("fetched_at")
    if not isinstance(fetched_at_s, str):
        return None
    try:
        fetched_dt = datetime.fromisoformat(fetched_at_s.replace("Z", "+00:00"))
    except ValueError:
        return None
    if fetched_dt.tzinfo is None:
        fetched_dt = fetched_dt.replace(tzinfo=UTC)
    now = datetime.now(tz=UTC)
    age = int(max(0, (now - fetched_dt).total_seconds()))
    return jwks, age


# -----------------------------------------------------------------------------
# Config-file loader (VAL-W10-006)
# -----------------------------------------------------------------------------


def _load_config_trust_anchor(path: Path) -> str | None:
    """Read ``trust_anchor_url`` from a TOML config file.

    Returns the URL string on success or None when the file does not
    exist. Raises :class:`RelayConfigInvalidError` when the file is
    present but malformed.
    """
    if not path.exists():
        return None
    try:
        # tomllib lands in stdlib at 3.11+; we require 3.12+ so this is
        # always available.
        import tomllib
    except ImportError as exc:  # pragma: no cover - 3.12+ guaranteed
        raise RelayConfigInvalidError(
            "tomllib not available; verifier requires Python 3.11+",
            details={"path": str(path)},
        ) from exc
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise RelayConfigInvalidError(
            f"verifier config file {path!s} is not valid TOML: {exc}",
            details={"path": str(path)},
        ) from exc
    if not isinstance(data, dict):
        raise RelayConfigInvalidError(
            f"verifier config root must be a TOML table: {path!s}",
            details={"path": str(path)},
        )
    if "trust_anchor_url" not in data:
        # Config file present but the key is absent -> caller treats
        # this as "no override" without an error. Operators may use the
        # config file for other settings (forward compatibility).
        return None
    value = data["trust_anchor_url"]
    if not isinstance(value, str) or not value.strip():
        raise RelayConfigInvalidError(
            f"verifier config trust_anchor_url must be a non-empty string: "
            f"{path!s}",
            details={"path": str(path), "value_type": type(value).__name__},
        )
    parsed = urlparse(value)
    if parsed.scheme not in {"https", "http", "file"} or not parsed.scheme:
        raise RelayConfigInvalidError(
            f"verifier config trust_anchor_url must be an http/https/file URL: "
            f"{value!r}",
            details={"path": str(path), "url": value},
        )
    return value


# -----------------------------------------------------------------------------
# Trust-anchor URL precedence (flag > config > default)
# -----------------------------------------------------------------------------


def resolve_trust_anchor_url(
    *,
    flag_url: str | None = None,
    config_path: Path | None = None,
) -> tuple[str, str]:
    """Resolve the effective trust-anchor URL and its source label.

    Precedence (VAL-W10-005, VAL-W10-006):
      1. ``flag_url`` (non-empty) -> source ``byo_flag``.
      2. ``config_path`` exists AND defines ``trust_anchor_url`` ->
         source ``byo_config``.
      3. Otherwise -> default URL from :mod:`relay_verifier.constants`,
         source ``live_fetch`` (the resolver will downgrade to ``cache``
         or ``bundled`` if the live fetch fails or is disabled).

    Args:
        flag_url: value of a ``--trust-anchor`` CLI flag; empty/None
            means no flag was supplied.
        config_path: optional path to a TOML config file
            (``~/.relay/verifier.toml`` by convention). When None the
            config-file source is skipped entirely.

    Returns:
        ``(url, source_label)`` where ``source_label`` is one of the
        ``TRUST_ANCHOR_SOURCE_*`` constants -- specifically
        ``TRUST_ANCHOR_SOURCE_BYO_FLAG``,
        ``TRUST_ANCHOR_SOURCE_BYO_CONFIG``, or
        ``TRUST_ANCHOR_SOURCE_LIVE`` for the default URL.

    Raises:
        RelayConfigInvalidError: when the config file is present but
            malformed.
    """
    if flag_url and flag_url.strip():
        return flag_url.strip(), TRUST_ANCHOR_SOURCE_BYO_FLAG
    if config_path is not None:
        config_url = _load_config_trust_anchor(config_path)
        if config_url is not None:
            return config_url, TRUST_ANCHOR_SOURCE_BYO_CONFIG
    return DEFAULT_JWKS_URL, TRUST_ANCHOR_SOURCE_LIVE


# -----------------------------------------------------------------------------
# Top-level resolver (VAL-W10-003 through VAL-W10-009)
# -----------------------------------------------------------------------------


def _emit_stderr_warning(warn: dict[str, Any]) -> None:
    """Emit a structured stderr WARN line (one JSON object per line)."""
    sys.stderr.write(
        json.dumps(warn, separators=(",", ":"), ensure_ascii=True) + "\n"
    )
    sys.stderr.flush()


def resolve_jwks(
    *,
    flag_url: str | None = None,
    config_path: Path | None = None,
    offline: bool = False,
    fetcher: NetworkFetcher | None = None,
    home: Path | None = None,
    emit_warning: bool = True,
) -> JWKSLoadResult:
    """Resolve a trust-anchor JWKS dict from the most appropriate source.

    Top-level orchestrator implementing the precedence described in the
    module docstring. Callers (CLI commands, test fixtures, downstream
    SDK code) pass operator inputs and a network fetcher; the resolver
    chooses the source and returns a :class:`JWKSLoadResult`.

    Args:
        flag_url: value of a ``--trust-anchor`` CLI flag; non-empty
            triggers VAL-W10-005 (BYO flag).
        config_path: optional path to a TOML config file; presence with
            a ``trust_anchor_url`` key triggers VAL-W10-006 (BYO
            config). The flag overrides the config.
        offline: when True (VAL-W10-004) the resolver ONLY uses the
            bundled JWKS; it does NOT touch the cache or the network.
            This is the canonical offline mode for air-gapped auditors.
        fetcher: optional callable that performs the live JWKS fetch.
            When None (default) the resolver behaves as ``offline=True``
            for the BUNDLED-only path; this keeps the package's import
            boundary clean (no built-in HTTP client).
        home: optional ``RELAY_HOME`` override for the cache directory
            (test seam). When None the resolver consults the
            ``RELAY_HOME`` env var, defaulting to ``~/.relay``.
        emit_warning: when True (default) cache-fallback and BYO-flag
            warnings are written to stderr as well as included in
            :attr:`JWKSLoadResult.warnings`. Tests that want to capture
            warnings without stderr pollution pass False.

    Returns:
        A populated :class:`JWKSLoadResult`. ``warnings`` is empty when
        the live or BYO source succeeded; non-empty when the cache
        fallback kicked in or a BYO flag was used.

    Raises:
        RelayConfigInvalidError: the config file was malformed.
        RelayJWKSUnavailableError: no source was usable (VAL-W10-008).
    """
    warnings: list[dict[str, Any]] = []
    url, source_kind = resolve_trust_anchor_url(
        flag_url=flag_url, config_path=config_path
    )

    # BYO flag/config users get a structured WARN so an auditor can
    # attribute the override to an explicit operator action.
    if source_kind == TRUST_ANCHOR_SOURCE_BYO_FLAG:
        warn = {
            "schema_version": "relay.verifier.warning.v1",
            "code": "RELAY-VERIFY-BYO-FLAG",
            "level": "warn",
            "trust_anchor": url,
            "default_trust_anchor": DEFAULT_JWKS_URL,
            "message": (
                "trust anchor overridden via --trust-anchor flag; the "
                "spec-pinned default is the compiled-in URL"
            ),
        }
        warnings.append(warn)
        if emit_warning:
            _emit_stderr_warning(warn)

    # Offline mode is the simplest path: bundled JWKS only.
    if offline:
        return JWKSLoadResult(
            jwks=load_bundled_jwks(),
            source=TRUST_ANCHOR_SOURCE_BUNDLED,
            trust_anchor_url=url,
            warnings=warnings,
        )

    # BYO flag/config users skip the live-fetch warning chain too: the
    # operator explicitly chose this URL, so cache and bundled fallback
    # do not apply. If the fetcher is None or fails we surface a clear
    # error rather than silently falling back to the default URL.
    if source_kind in {TRUST_ANCHOR_SOURCE_BYO_FLAG, TRUST_ANCHOR_SOURCE_BYO_CONFIG}:
        if fetcher is None:
            raise RelayJWKSUnavailableError(
                f"BYO trust anchor {url!r} requires a fetcher; pass "
                f"--offline if you want bundled-JWKS-only mode",
                details={"trust_anchor": url, "source": source_kind},
            )
        try:
            jwks = fetcher(url)
        except Exception as exc:  # noqa: BLE001 -- fetcher contract
            raise RelayJWKSUnavailableError(
                f"BYO trust anchor fetch failed for {url!r}: {exc}",
                details={"trust_anchor": url, "source": source_kind},
            ) from exc
        if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
            raise RelayJWKSUnavailableError(
                f"BYO trust anchor returned malformed JWKS for {url!r}",
                details={"trust_anchor": url, "source": source_kind},
            )
        return JWKSLoadResult(
            jwks=jwks, source=source_kind, trust_anchor_url=url, warnings=warnings,
        )

    # Default path: live -> cache -> bundled -> fail.
    if fetcher is not None:
        try:
            jwks = fetcher(url)
            if isinstance(jwks, dict) and isinstance(jwks.get("keys"), list):
                return JWKSLoadResult(
                    jwks=jwks,
                    source=TRUST_ANCHOR_SOURCE_LIVE,
                    trust_anchor_url=url,
                    warnings=warnings,
                )
        except Exception:  # noqa: BLE001 -- fetcher contract
            # Fall through to cache.
            pass

    cached = load_cached_jwks(url, home=home)
    if cached is not None:
        jwks, age = cached
        if age <= CACHE_STALENESS_THRESHOLD_SECONDS:
            warn = {
                "schema_version": "relay.verifier.warning.v1",
                "code": "RELAY-VERIFY-CACHE-FALLBACK",
                "level": "warn",
                "trust_anchor": url,
                "cache_age_seconds": age,
                "cache_staleness_threshold_seconds": (
                    CACHE_STALENESS_THRESHOLD_SECONDS
                ),
                "message": (
                    "live JWKS fetch failed; using cached JWKS within "
                    "staleness budget"
                ),
            }
            warnings.append(warn)
            if emit_warning:
                _emit_stderr_warning(warn)
            return JWKSLoadResult(
                jwks=jwks,
                source=TRUST_ANCHOR_SOURCE_CACHE,
                trust_anchor_url=url,
                warnings=warnings,
            )
        # Cache present but stale -> treat as miss; the operator should
        # refresh the cache. Continue to bundled.

    try:
        bundled = load_bundled_jwks()
    except RelayBundledJWKSMissingError as exc:
        raise RelayJWKSUnavailableError(
            f"no JWKS available for trust anchor {url!r}: "
            "live fetch failed, cache missing or stale, "
            "and bundled JWKS asset is missing",
            details={
                "trust_anchor": url,
                "bundled_error": str(exc),
                "cache_checked": True,
            },
        ) from exc
    return JWKSLoadResult(
        jwks=bundled,
        source=TRUST_ANCHOR_SOURCE_BUNDLED,
        trust_anchor_url=url,
        warnings=warnings,
    )


__all__ = [
    "BUNDLED_JWKS_ASSET",
    "CACHE_STALENESS_THRESHOLD_SECONDS",
    "JWKS_CACHE_DIRNAME",
    "JWKS_CACHE_SCHEMA_VERSION",
    "JWKSLoadResult",
    "NetworkFetcher",
    "TRUST_ANCHOR_SOURCE_BUNDLED",
    "TRUST_ANCHOR_SOURCE_BYO_CONFIG",
    "TRUST_ANCHOR_SOURCE_BYO_FLAG",
    "TRUST_ANCHOR_SOURCE_CACHE",
    "TRUST_ANCHOR_SOURCE_LIVE",
    "load_bundled_jwks",
    "load_cached_jwks",
    "resolve_jwks",
    "resolve_trust_anchor_url",
]
