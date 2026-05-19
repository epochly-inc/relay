"""V3M5-F04 tier-1 plumbing tests: UTS-39 confusables guard on manifest URLs.

Encodes VAL-V3M5-010: the SDK rejects manifest URLs whose host fails the
UTS-39 confusables check against a caller-supplied canonical ASCII host.
Five distinct homograph variants are exercised against a canonical
``manifests.epochly.com`` target:

  1. Cyrillic-script substitution.
  2. Greek-script substitution.
  3. Armenian-script substitution.
  4. Fullwidth ASCII substitution.
  5. Mathematical-styled letters.
  6. Mixed-script labels.

Pure ASCII non-homograph hosts pass; pure ASCII canonical host passes.

ASCII-only per CLAUDE.md "ASCII-Safe Source"; homograph hosts are
constructed from numeric Unicode escapes.
"""

from __future__ import annotations

import pytest

_CANONICAL = "manifests.epochly.com"


def _u(*codepoints: int) -> str:
    return "".join(chr(cp) for cp in codepoints)


# Cyrillic small "e" U+0435 substituted for ASCII "e" in the "epochly" label.
_CYRILLIC_HOST = "manifests." + _u(0x0435) + "pochly.com"

# Greek small omicron U+03BF substituted for "o" in "epochly" + "com".
_GREEK_HOST = "manifests.ep" + _u(0x03BF) + "chly.c" + _u(0x03BF) + "m"

# Armenian small "o" U+0585.
_ARMENIAN_HOST = "manifests.ep" + _u(0x0585) + "chly.com"

# Fullwidth small "m" U+FF4D.
_FULLWIDTH_HOST = _u(0xFF4D) + "anifests.epochly.com"

# Mathematical bold small "m" U+1D426 -> NFKC folds to "m".
_MATH_HOST = _u(0x1D426) + "anifests.epochly.com"

# Mixed-script: Cyrillic small "o" U+043E in the "epochly" label.
_MIXED_HOST = "manifests.ep" + _u(0x043E) + "chly.com"


def _make_url(host: str) -> str:
    return f"https://{host}/manifest.yaml"


# -----------------------------------------------------------------------------
# Helper-level tests (network_policy.check_manifest_url_confusable)
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M5-010")
def test_canonical_ascii_manifest_url_passes() -> None:
    """A pure-ASCII canonical manifest URL is accepted."""
    from relay.network_policy import check_manifest_url_confusable

    # No exception raised; returns None.
    assert (
        check_manifest_url_confusable(_make_url(_CANONICAL), canonical_host=_CANONICAL)
        is None
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M5-010")
def test_unrelated_ascii_host_passes() -> None:
    """An unrelated ASCII host (not a confusable) is accepted."""
    from relay.network_policy import check_manifest_url_confusable

    # Distinct ASCII host should not trip the guard.
    assert (
        check_manifest_url_confusable(
            "https://example.org/manifest.yaml",
            canonical_host=_CANONICAL,
        )
        is None
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M5-010")
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
def test_manifest_url_homograph_variants_rejected(
    variant_name: str, host: str
) -> None:
    """Each UTS-39 confusable variant of the canonical host is rejected."""
    from relay.network_policy import (
        ManifestUrlHomographDenied,
        check_manifest_url_confusable,
    )

    url = _make_url(host)
    with pytest.raises(ManifestUrlHomographDenied) as exc:
        check_manifest_url_confusable(url, canonical_host=_CANONICAL)
    env = exc.value.envelope
    assert env["denied_url"] == url
    assert env["canonical_host"] == _CANONICAL
    assert env["denied_host"] == host
    assert env["denied_reason"] in {"confusable", "mixed_script", "non_ascii"}, (
        f"variant={variant_name} unexpected reason={env['denied_reason']!r}"
    )
    assert env["code"] == "RELAY-SDK-HOMOGRAPH"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M5-010")
def test_envelope_shape_is_stable() -> None:
    """The rejection envelope has the documented stable wire-format keys."""
    from relay.network_policy import (
        ManifestUrlHomographDenied,
        check_manifest_url_confusable,
    )

    with pytest.raises(ManifestUrlHomographDenied) as exc:
        check_manifest_url_confusable(
            _make_url(_CYRILLIC_HOST), canonical_host=_CANONICAL
        )
    env = exc.value.envelope
    required = {
        "code",
        "http_status",
        "denied_url",
        "denied_host",
        "canonical_host",
        "denied_reason",
    }
    assert required.issubset(env.keys()), (
        f"missing keys: {required - env.keys()}"
    )
    assert env["http_status"] == 400
