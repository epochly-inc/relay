"""Default trust-anchor lock guard (VAL-W10-002) -- pytest-discoverable.

Mirrors :mod:`default_trust_anchor_lock` (the canonical filename
stipulated by VAL-W10-002). Pytest's default discovery glob is
``test_*.py``; this file is the discoverable copy of the guard, kept
byte-equivalent to its sibling so a reviewer scanning either name sees
the same lock against banned pattern #13.

CLAUDE.md banned pattern #13 mandates that changing the OSS verifier's
compiled-in default JWKS URL is a board-level decision, not a routine
PR. This guard asserts :data:`relay_verifier.constants.DEFAULT_JWKS_URL`
against a frozen literal reference value. Any mutation trips a
structured pytest failure naming banned pattern #13.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import pytest
from relay_verifier.constants import DEFAULT_JWKS_URL, DEFAULT_TRUST_ANCHOR_URL

# Frozen reference value. Mutating the verifier's compiled-in default
# JWKS URL without also amending this literal is a CLAUDE.md banned
# pattern #13 violation -- a board-level decision, not a routine PR.
_FROZEN_DEFAULT_JWKS_URL: str = "https://relay.epochly.com/.well-known/jwks.json"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-002")
def test_default_jwks_url_matches_frozen_reference() -> None:
    """Guard: the verifier's default JWKS URL is the frozen reference."""
    assert DEFAULT_JWKS_URL == _FROZEN_DEFAULT_JWKS_URL, (
        "VAL-W10-002 GUARD FAILURE: relay_verifier.constants.DEFAULT_JWKS_URL "
        f"changed from {_FROZEN_DEFAULT_JWKS_URL!r} to {DEFAULT_JWKS_URL!r}. "
        "Per CLAUDE.md banned pattern #13 the OSS verifier's compiled-in "
        "default JWKS URL is a board-level decision; this change requires "
        "board approval and a coordinated update of this guard's frozen "
        "reference literal. See spec section AO.4 line 6165."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-002")
def test_default_trust_anchor_url_alias_matches() -> None:
    """Backwards-compatible alias must point to the same canonical URL."""
    assert DEFAULT_TRUST_ANCHOR_URL == DEFAULT_JWKS_URL
