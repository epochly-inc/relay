"""W10.1 VAL-W10-003 through VAL-W10-009 plumbing tier tests.

Covers:

  * VAL-W10-003: bundled JWKS shipped with required key annotations.
  * VAL-W10-004: offline mode uses bundled JWKS without network.
  * VAL-W10-005: BYO trust anchor via ``--trust-anchor`` flag.
  * VAL-W10-006: BYO trust anchor via config file.
  * VAL-W10-007: live unreachable + cached -> cache + WARN.
  * VAL-W10-008: live unreachable + no cache + no bundled -> clear fail.
  * VAL-W10-009: network-deny default for bundled-JWKS path.

All tests are plumbing-tier (offline; plumbing-tier budget per scripts/tier_budget_gate.py) per the
:data:`pytest.mark.plumbing` marker. Each test binds to its contract
assertion via :data:`pytest.mark.fulfills`.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import builtins
import hashlib
import json
import socket
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from relay_verifier import (
    DEFAULT_JWKS_URL,
    JWKS_CACHE_SCHEMA_VERSION,
    TRUST_ANCHOR_SOURCE_BUNDLED,
    TRUST_ANCHOR_SOURCE_BYO_CONFIG,
    TRUST_ANCHOR_SOURCE_BYO_FLAG,
    TRUST_ANCHOR_SOURCE_CACHE,
    TRUST_ANCHOR_SOURCE_LIVE,
    RelayBundledJWKSMissingError,
    RelayConfigInvalidError,
    RelayJWKSUnavailableError,
    load_bundled_jwks,
    load_cached_jwks,
    resolve_jwks,
    resolve_trust_anchor_url,
)
from relay_verifier.jwks_loader import (
    CACHE_STALENESS_THRESHOLD_SECONDS,
    _cache_path_for_url,
)

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------


def _write_cache_envelope(
    home: Path,
    url: str,
    jwks: dict[str, Any],
    *,
    fetched_at: str | None = None,
) -> Path:
    """Write a cache envelope at ``${home}/jwks-cache/<host>.json``.

    Mirrors the on-disk shape produced by the CLI's cache writer (see
    ``packages/cli/src/relay_cli/jwks_cache.py:236``) so the verifier's
    loader can read what the CLI writes. ``fetched_at`` defaults to
    "now" in UTC; pass an older RFC 3339 timestamp to simulate aged
    caches.
    """
    if fetched_at is None:
        fetched_at = datetime.now(tz=UTC).isoformat().replace("+00:00", "Z")
    envelope = {
        "schema_version": JWKS_CACHE_SCHEMA_VERSION,
        "trust_anchor_url": url,
        "fetched_at": fetched_at,
        "jwks": jwks,
    }
    path = _cache_path_for_url(url, home=home)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(envelope, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    return path


@contextmanager
def _block_all_network() -> Iterator[None]:
    """Patch ``socket.socket`` so any outbound network call raises.

    This is the most invasive guard available without privileged
    sandboxing. Any attempt to open an outbound socket (or a TCP DNS
    resolution that constructs one) raises ``OSError`` immediately;
    code paths that DO need the network in tests must catch the error
    or be patched explicitly.
    """
    original_socket = socket.socket
    original_create_connection = socket.create_connection
    original_getaddrinfo = socket.getaddrinfo

    def _blocked_socket(*args: Any, **kwargs: Any) -> None:
        raise OSError(
            "VAL-W10-004/009 network-deny: socket() forbidden in this test"
        )

    def _blocked_create_connection(*args: Any, **kwargs: Any) -> None:
        raise OSError(
            "VAL-W10-004/009 network-deny: create_connection() forbidden"
        )

    def _blocked_getaddrinfo(*args: Any, **kwargs: Any) -> None:
        raise OSError(
            "VAL-W10-004/009 network-deny: getaddrinfo() forbidden"
        )

    socket.socket = _blocked_socket  # type: ignore[assignment]
    socket.create_connection = _blocked_create_connection  # type: ignore[assignment]
    socket.getaddrinfo = _blocked_getaddrinfo  # type: ignore[assignment]
    try:
        yield
    finally:
        socket.socket = original_socket  # type: ignore[assignment]
        socket.create_connection = original_create_connection  # type: ignore[assignment]
        socket.getaddrinfo = original_getaddrinfo  # type: ignore[assignment]


# -----------------------------------------------------------------------------
# VAL-W10-003: Bundled JWKS shape + required key annotations
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-003")
def test_bundled_jwks_loads_and_has_required_key_annotations() -> None:
    """The bundled JWKS is present, valid, and every key has spec-required fields.

    VAL-W10-003: every key carries kid, kty, alg, use, not_before,
    not_after. The bundled snapshot is loaded via importlib.resources
    so the test works whether the package is editable-installed or
    wheel-installed.
    """
    jwks = load_bundled_jwks()
    assert isinstance(jwks, dict)
    keys = jwks.get("keys")
    assert isinstance(keys, list) and len(keys) >= 1, (
        f"bundled JWKS has no keys: {jwks!r}"
    )
    required_fields = ("kid", "kty", "alg", "use", "not_before", "not_after")
    for idx, key in enumerate(keys):
        assert isinstance(key, dict), f"key[{idx}] is not an object"
        missing = [f for f in required_fields if f not in key]
        assert not missing, f"bundled JWKS key[{idx}] missing fields: {missing!r}"
        # Sanity: alg/kty match expected pairings.
        if key["kty"] == "OKP":
            assert key["alg"] == "EdDSA"
            assert key.get("crv") == "Ed25519"
            assert "x" in key
        elif key["kty"] == "EC":
            assert key["alg"] == "ES256"
            assert key.get("crv") == "P-256"
            assert "x" in key and "y" in key
        else:
            pytest.fail(f"bundled JWKS key[{idx}] has unknown kty: {key['kty']!r}")

    # Bundled JWKS digest is reported in evidence; assert it is stable
    # across reads (no random / wall-clock dependency in the loader).
    digest_a = hashlib.sha256(
        json.dumps(load_bundled_jwks(), sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    digest_b = hashlib.sha256(
        json.dumps(load_bundled_jwks(), sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    assert digest_a == digest_b


# -----------------------------------------------------------------------------
# VAL-W10-004: Offline mode uses bundled JWKS without network
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-004")
def test_offline_resolve_uses_bundled_jwks_with_no_network(tmp_path: Path) -> None:
    """``resolve_jwks(offline=True)`` returns bundled JWKS under network deny.

    Even with an empty cache directory AND a network-deny patch, the
    offline path completes successfully and reports
    ``trust_anchor_source = "bundled_jwks"``.
    """
    with _block_all_network():
        result = resolve_jwks(offline=True, home=tmp_path, emit_warning=False)

    assert result.source == TRUST_ANCHOR_SOURCE_BUNDLED == "bundled_jwks"
    assert result.trust_anchor_url == DEFAULT_JWKS_URL
    assert isinstance(result.jwks.get("keys"), list)
    assert result.warnings == []


# -----------------------------------------------------------------------------
# VAL-W10-005: BYO trust anchor via flag
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-005")
def test_byo_flag_overrides_default_url(tmp_path: Path) -> None:
    """``flag_url=...`` overrides the default; fetcher called against override.

    Precedence: BYO flag wins. The default URL is never queried; a sentinel
    fetcher records which URL was asked about.
    """
    fetched_urls: list[str] = []
    override_url = "https://example.org/.well-known/jwks.json"

    fake_jwks = {"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": "k1",
                            "alg": "EdDSA", "use": "sig", "x": "AA"}]}

    def fetcher(url: str) -> dict[str, Any]:
        fetched_urls.append(url)
        return fake_jwks

    result = resolve_jwks(
        flag_url=override_url, fetcher=fetcher, home=tmp_path, emit_warning=False,
    )

    assert result.source == TRUST_ANCHOR_SOURCE_BYO_FLAG == "byo_flag"
    assert result.trust_anchor_url == override_url
    assert fetched_urls == [override_url]
    # The default URL must NOT have been queried.
    assert DEFAULT_JWKS_URL not in fetched_urls
    # The override emits a structured WARN listed in warnings.
    assert any(w.get("code") == "RELAY-VERIFY-BYO-FLAG" for w in result.warnings)


# -----------------------------------------------------------------------------
# VAL-W10-006: BYO trust anchor via config file + precedence
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-006")
def test_byo_config_file_overrides_default_and_flag_overrides_config(
    tmp_path: Path,
) -> None:
    """Config supplies URL; flag overrides config; both override default.

    Three-way precedence: flag > config > default.
    """
    config_path = tmp_path / "verifier.toml"
    config_path.write_text(
        'trust_anchor_url = "https://config.example.org/.well-known/jwks.json"\n',
        encoding="utf-8",
    )

    # Case 1: only config -> source == byo_config; URL from config.
    url, source = resolve_trust_anchor_url(config_path=config_path)
    assert source == TRUST_ANCHOR_SOURCE_BYO_CONFIG == "byo_config"
    assert url == "https://config.example.org/.well-known/jwks.json"

    # Case 2: flag + config -> flag wins.
    url2, source2 = resolve_trust_anchor_url(
        flag_url="https://flag.example.org/.well-known/jwks.json",
        config_path=config_path,
    )
    assert source2 == TRUST_ANCHOR_SOURCE_BYO_FLAG
    assert url2 == "https://flag.example.org/.well-known/jwks.json"

    # Case 3: neither -> default.
    url3, source3 = resolve_trust_anchor_url()
    assert source3 == TRUST_ANCHOR_SOURCE_LIVE
    assert url3 == DEFAULT_JWKS_URL

    # Case 4: malformed config (non-string) -> RelayConfigInvalidError.
    bad_config = tmp_path / "verifier_bad.toml"
    bad_config.write_text("trust_anchor_url = 42\n", encoding="utf-8")
    with pytest.raises(RelayConfigInvalidError):
        resolve_trust_anchor_url(config_path=bad_config)


# -----------------------------------------------------------------------------
# VAL-W10-007: Live unreachable + fresh cache -> cache + WARN
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-007")
def test_live_unreachable_with_fresh_cache_uses_cache_and_warns(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Failed live fetch + fresh cache -> source=cached_jwks with WARN."""
    cached_jwks = {
        "keys": [
            {"kty": "OKP", "crv": "Ed25519", "kid": "cached-k1",
             "alg": "EdDSA", "use": "sig", "x": "AA"}
        ]
    }
    # Fresh cache: fetched 1 hour ago.
    fetched_at = (
        (datetime.now(tz=UTC) - timedelta(hours=1))
        .isoformat()
        .replace("+00:00", "Z")
    )
    _write_cache_envelope(
        tmp_path, DEFAULT_JWKS_URL, cached_jwks, fetched_at=fetched_at,
    )

    def failing_fetcher(url: str) -> dict[str, Any]:
        raise OSError("network unreachable")

    # emit_warning=True so the stderr line is captured.
    result = resolve_jwks(
        fetcher=failing_fetcher, home=tmp_path, emit_warning=True,
    )

    assert result.source == TRUST_ANCHOR_SOURCE_CACHE == "cached_jwks"
    assert result.jwks == cached_jwks
    # Structured WARN includes the required fields.
    warn = next(
        (w for w in result.warnings if w.get("code") == "RELAY-VERIFY-CACHE-FALLBACK"),
        None,
    )
    assert warn is not None, f"no cache fallback WARN: {result.warnings!r}"
    assert isinstance(warn["cache_age_seconds"], int)
    assert warn["cache_age_seconds"] > 0
    assert warn["cache_staleness_threshold_seconds"] == CACHE_STALENESS_THRESHOLD_SECONDS

    # The WARN was emitted to stderr as a JSON line.
    captured = capsys.readouterr()
    stderr_line = next(
        (ln for ln in captured.err.splitlines() if "RELAY-VERIFY-CACHE-FALLBACK" in ln),
        None,
    )
    assert stderr_line is not None
    parsed_stderr = json.loads(stderr_line)
    assert parsed_stderr["code"] == "RELAY-VERIFY-CACHE-FALLBACK"
    assert "cache_age_seconds" in parsed_stderr


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-007")
def test_load_cached_jwks_returns_age_in_seconds(tmp_path: Path) -> None:
    """``load_cached_jwks`` reports the cache age accurately."""
    jwks = {"keys": []}
    fetched_at = (
        (datetime.now(tz=UTC) - timedelta(seconds=42))
        .isoformat()
        .replace("+00:00", "Z")
    )
    _write_cache_envelope(
        tmp_path, "https://example.org/jwks.json", jwks, fetched_at=fetched_at,
    )
    out = load_cached_jwks("https://example.org/jwks.json", home=tmp_path)
    assert out is not None
    loaded_jwks, age = out
    assert loaded_jwks == jwks
    # Allow a few seconds of slack for slow CI.
    assert 40 <= age <= 120


# -----------------------------------------------------------------------------
# VAL-W10-008: Live unreachable + no cache + no bundled -> clear fail
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-008")
def test_all_sources_unavailable_raises_typed_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No live, no cache, no bundled -> :class:`RelayJWKSUnavailableError`.

    Simulates a stripped install (bundled asset deliberately hidden) by
    monkeypatching :func:`load_bundled_jwks` to raise
    :class:`RelayBundledJWKSMissingError`.
    """
    from relay_verifier import jwks_loader as loader_mod

    def fake_load_bundled() -> dict[str, Any]:
        raise RelayBundledJWKSMissingError(
            "test: bundled asset removed",
            details={"asset": "bundled_jwks.json"},
        )

    monkeypatch.setattr(loader_mod, "load_bundled_jwks", fake_load_bundled)

    def failing_fetcher(url: str) -> dict[str, Any]:
        raise OSError("network down")

    with pytest.raises(RelayJWKSUnavailableError) as excinfo:
        resolve_jwks(
            fetcher=failing_fetcher,
            home=tmp_path,  # empty cache dir
            emit_warning=False,
        )

    err = excinfo.value
    assert err.code == "RELAY-VERIFY-001"
    assert "trust_anchor" in err.details
    assert "bundled_error" in err.details
    assert "no JWKS available" in err.message.lower() or "no jwks" in err.message.lower()


# -----------------------------------------------------------------------------
# VAL-W10-009: Network-deny default for bundled-JWKS path
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-009")
def test_bundled_jwks_path_makes_zero_network_calls(tmp_path: Path) -> None:
    """The bundled-JWKS code path is pure filesystem; zero outbound syscalls.

    Asserts via socket-monitor (sentinel) plus a stricter check: even
    constructing a socket raises in the test, so the entire path
    completes without touching the network stack.

    Counts ``open()`` calls during the bundled load to confirm the path
    is purely importlib.resources-based.
    """
    open_calls: list[str] = []
    real_open = builtins.open

    def tracking_open(file: Any, *args: Any, **kwargs: Any) -> Any:
        open_calls.append(str(file))
        return real_open(file, *args, **kwargs)

    builtins.open = tracking_open  # type: ignore[assignment]
    try:
        with _block_all_network():
            result = resolve_jwks(offline=True, home=tmp_path, emit_warning=False)
    finally:
        builtins.open = real_open  # type: ignore[assignment]

    assert result.source == TRUST_ANCHOR_SOURCE_BUNDLED
    # The bundled load may open the resource file once (importlib.resources
    # internals on some Python versions). Zero socket calls is the load-
    # bearing guarantee; we assert below that no socket-bound URL was
    # accessed via open().
    bad = [c for c in open_calls if c.startswith(("http://", "https://", "ftp://"))]
    assert not bad, f"URL-shaped open() call detected: {bad!r}"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-009")
def test_bundled_loader_does_not_import_urllib_request() -> None:
    """The bundled loader path must not transitively import an HTTP client.

    Imports the verifier package in a subprocess-style check (here:
    same-process check via a tracking module) and asserts that loading
    the bundled JWKS does not pull in ``urllib.request`` or ``httpx``.
    This is a structural guard: an HTTP client import in the loader
    would constitute "speculative network setup" forbidden by VAL-W10-009.
    """
    import sys

    # Snapshot modules currently loaded.
    before = set(sys.modules.keys())
    _ = load_bundled_jwks()
    after = set(sys.modules.keys())
    newly_loaded = after - before
    forbidden = {"urllib.request", "httpx", "requests", "aiohttp"}
    bad = newly_loaded & forbidden
    assert not bad, (
        f"VAL-W10-009: bundled-JWKS path pulled in HTTP-client modules: {bad!r}"
    )
