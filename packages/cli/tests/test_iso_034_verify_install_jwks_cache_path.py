"""VAL-ISO-034: verify-install JWKS error envelope must report the cache path
that ``load_jwks_from_cache`` actually consulted.

``_resolve_jwks`` consults ``load_jwks_from_cache(url, home=home)`` which, when
``home is None``, resolves the cache under ``relay_home()`` -- honoring the
``RELAY_HOME`` env var and the canonical ``jwks_cache.cache_path_for_url``
logic (lowercased host, port suffix, charset sanitization). But the error
path computed its diagnostic ``cache_path`` via a *separate* helper
(``_jwks_cache_path_for``) that fell back to ``Path.home() / ".relay"`` and
re-derived the host filename by hand -- so when ``RELAY_HOME`` pointed at a
non-``~/.relay`` directory (and ``--home``/``RLY_VERIFY_INSTALL_HOME`` were
unset), the envelope reported the WRONG path an operator could never use to
seed the cache.

This pins: the raised ``_JwksUnavailableError.cache_path`` is byte-identical
to ``cache_path_for_url(trust_anchor_url, home=home)`` -- including the
``relay_home()`` fallback -- so the diagnostic matches what was consulted.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from pathlib import Path

import pytest
from relay_cli.commands.verify_install import _JwksUnavailableError, _resolve_jwks
from relay_cli.jwks_cache import cache_path_for_url

_TRUST_ANCHOR = "https://relay.epochly.com/.well-known/jwks.json"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-034")
def test_offline_cache_miss_reports_relay_home_derived_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Contract trigger: --home / RLY_VERIFY_INSTALL_HOME unset (home=None),
    # but RELAY_HOME points at a NON-~/.relay directory and no cache exists.
    relay_home = tmp_path / "custom-relay-home"
    relay_home.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("RELAY_HOME", str(relay_home))

    expected = cache_path_for_url(_TRUST_ANCHOR, home=None)
    # The expected path MUST live under the RELAY_HOME override, proving the
    # fallback is relay_home() and not Path.home()/.relay.
    assert str(relay_home) in str(expected)

    with pytest.raises(_JwksUnavailableError) as exc:
        _resolve_jwks(trust_anchor_url=_TRUST_ANCHOR, home=None, offline=True)

    assert exc.value.cache_path == expected, (
        f"diagnostic path {exc.value.cache_path} != consulted path {expected}"
    )
    # The wrong (legacy) fallback path must NOT be reported.
    legacy = Path.home() / ".relay" / "jwks-cache" / "relay.epochly.com.json"
    assert exc.value.cache_path != legacy


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-034")
def test_explicit_home_override_matches_consulted_path(tmp_path: Path) -> None:
    # When --home IS set, the diagnostic must still match the consulted path.
    home = tmp_path / "explicit-home"
    home.mkdir(parents=True, exist_ok=True)
    expected = cache_path_for_url(_TRUST_ANCHOR, home=home)

    with pytest.raises(_JwksUnavailableError) as exc:
        _resolve_jwks(trust_anchor_url=_TRUST_ANCHOR, home=home, offline=True)

    assert exc.value.cache_path == expected
