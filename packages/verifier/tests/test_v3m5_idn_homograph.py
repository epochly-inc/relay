"""V3M5-F04 tier-1 plumbing tests: UTS-39 confusables guard on trust_anchor URLs.

Encodes VAL-V3M5-009: the verifier rejects trust_anchor URLs whose host
fails the UTS-39 confusables check against the canonical ASCII anchor
host. Five distinct homograph variants are exercised:

  1. Cyrillic-script substitution (Cyrillic "e", "p", "o", "a" for ASCII).
  2. Greek-script substitution (Greek omicron "o", rho "p").
  3. Armenian-script substitution (Armenian "h" / "o" / similar).
  4. Fullwidth ASCII substitution (U+FF52 fullwidth "r", etc.).
  5. Mathematical-styled letters (U+1D5CB MATHEMATICAL SANS-SERIF SMALL R).
  6. Mixed-script labels (single label mixing Latin + Cyrillic).

The guard rejects each variant with a structured error that names the
canonical (ASCII-folded) host. Pure ASCII hosts are accepted unchanged.

ASCII-only per CLAUDE.md "ASCII-Safe Source"; non-ASCII test inputs are
constructed via numeric escapes (no literal Unicode glyphs).
"""

from __future__ import annotations

import pytest

# Canonical ASCII host the homograph URLs target.
_CANONICAL = "relay.epochly.com"


def _u(*codepoints: int) -> str:
    """Return a string built from explicit Unicode codepoints (ASCII-safe source)."""
    return "".join(chr(cp) for cp in codepoints)


# Pre-built homograph hosts (literal codepoints only; no raw Unicode in source).

# Cyrillic homographs: small "e" U+0435, small "p" U+0440 (looks like Latin p),
# small "o" U+043E, small "a" U+0430.
# host = "r" + cyr_e + "lay.epochly.com" -> reads as "relay.epochly.com" but with cyr e
_CYRILLIC_HOST = "r" + _u(0x0435) + "lay.epochly.com"

# Greek homographs: small omicron U+03BF, small rho U+03C1.
# host = "relay.ep" + greek_o + "chly.c" + greek_o + "m"
_GREEK_HOST = "relay.ep" + _u(0x03BF) + "chly.c" + _u(0x03BF) + "m"

# Armenian homographs: small "o" U+0585 (looks like Latin o).
# host = "relay.eph" + armenian + "chly.com" -- shape close to "relay.epochly.com"
# We use armenian small "o" U+0585 in the "epochly" label.
_ARMENIAN_HOST = "relay.ep" + _u(0x0585) + "chly.com"

# Fullwidth ASCII: U+FF52 fullwidth "r".
_FULLWIDTH_HOST = _u(0xFF52) + "elay.epochly.com"

# Mathematical-styled: U+1D42B MATHEMATICAL BOLD SMALL R folds to "r".
_MATH_HOST = _u(0x1D42B) + "elay.epochly.com"

# Mixed-script: single "epochly" label mixing Latin chars + Cyrillic "o" U+043E.
_MIXED_HOST = "relay.ep" + _u(0x043E) + "chly.com"


def _make_url(host: str) -> str:
    return f"https://{host}/.well-known/jwks.json"


# -----------------------------------------------------------------------------
# Helper-level tests (uts39 module function)
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M5-009")
def test_canonical_ascii_host_passes() -> None:
    """ASCII canonical host is accepted; no rejection."""
    from relay_verifier.jwks_loader import check_host_confusable

    # Should not raise. Returns None when the host is safe.
    assert check_host_confusable(_CANONICAL, _CANONICAL) is None


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M5-009")
@pytest.mark.parametrize(
    "variant_name,host",
    [
        ("cyrillic", _CYRILLIC_HOST),
        ("greek", _GREEK_HOST),
        ("armenian", _ARMENIAN_HOST),
        ("fullwidth", _FULLWIDTH_HOST),
        ("mathematical", _MATH_HOST),
        ("mixed_script", _MIXED_HOST),
    ],
)
def test_homograph_variants_rejected(variant_name: str, host: str) -> None:
    """Each of the 5+ UTS-39 confusables variants is detected and rejected."""
    from relay_verifier.errors import RelayConfigInvalidError
    from relay_verifier.jwks_loader import check_host_confusable

    with pytest.raises(RelayConfigInvalidError) as exc:
        check_host_confusable(host, _CANONICAL)
    details = exc.value.details
    # Structured details name both the offending host and the canonical target.
    assert details.get("host") == host
    assert details.get("canonical_host") == _CANONICAL
    # Reason is one of the documented UTS-39 categories.
    reason = details.get("reason", "")
    assert reason in {"confusable", "mixed_script", "non_ascii"}, (
        f"variant={variant_name} unexpected reason={reason!r}"
    )


# -----------------------------------------------------------------------------
# Integration: resolve_trust_anchor_url + resolve_jwks reject BYO URLs whose
# host is a UTS-39 confusable of the canonical default host.
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M5-009")
def test_resolve_jwks_rejects_byo_flag_with_homograph_host() -> None:
    """BYO trust_anchor URL with a confusable host is rejected at resolve time."""
    from relay_verifier.errors import RelayConfigInvalidError
    from relay_verifier.jwks_loader import resolve_jwks

    homograph_url = _make_url(_CYRILLIC_HOST)
    with pytest.raises(RelayConfigInvalidError) as exc:
        resolve_jwks(
            flag_url=homograph_url,
            fetcher=lambda u: {"keys": []},
            emit_warning=False,
        )
    assert exc.value.details.get("trust_anchor") == homograph_url


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M5-009")
def test_resolve_jwks_accepts_canonical_default() -> None:
    """The compiled-in default URL passes the UTS-39 guard."""
    from relay_verifier import DEFAULT_JWKS_URL
    from relay_verifier.jwks_loader import resolve_jwks

    result = resolve_jwks(
        fetcher=lambda u: {"keys": [{"kty": "OKP", "kid": "test"}]},
        emit_warning=False,
    )
    assert result.trust_anchor_url == DEFAULT_JWKS_URL
