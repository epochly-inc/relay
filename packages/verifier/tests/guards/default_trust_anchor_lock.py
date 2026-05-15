"""Default trust-anchor lock guard (VAL-W10-002).

CLAUDE.md banned pattern #13 mandates that changing the OSS verifier's
compiled-in default JWKS URL is a board-level decision, not a routine
PR. This guard test asserts :data:`relay_verifier.constants.DEFAULT_JWKS_URL`
against a frozen literal reference value. Any mutation of the constant
trips a structured pytest failure naming banned pattern #13.

This test is intentionally located at
``packages/verifier/tests/guards/default_trust_anchor_lock.py`` so a
PR reviewer scanning the diff for trust-anchor changes sees the guard
file alongside any constant change.

This module is a pytest test file (``pytest`` discovers it via the
``packages/verifier/tests`` testpath registered in the workspace root
``pyproject.toml``).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import pytest
from relay_verifier.constants import DEFAULT_JWKS_URL, DEFAULT_TRUST_ANCHOR_URL

# Frozen reference value. Mutating the verifier's compiled-in default
# JWKS URL without also amending this literal is a CLAUDE.md banned
# pattern #13 violation -- a board-level decision, not a routine PR.
# Reviewers: if you are looking at this constant changing, STOP and
# escalate to the trust-anchor governance owner.
_FROZEN_DEFAULT_JWKS_URL: str = "https://relay.epochly.com/.well-known/jwks.json"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-002")
def test_default_jwks_url_matches_frozen_reference() -> None:
    """Guard: the verifier's default JWKS URL is the frozen reference.

    Any mutation of :data:`DEFAULT_JWKS_URL` MUST also mutate the frozen
    literal in this file AND obtain board-level approval per CLAUDE.md
    banned pattern #13. A diff that touches only one side fails this
    guard with a message naming the banned pattern and pointing to the
    governance requirement.
    """
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
