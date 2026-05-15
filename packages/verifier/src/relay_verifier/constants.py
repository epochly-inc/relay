"""Compiled-in constants for the Relay offline verifier (W10.1).

This module is the **single canonical occurrence** of the default trust-
anchor JWKS URL literal in the verifier package's Python source tree
(VAL-W10-001 grep guard). A source-grep over
``packages/verifier/**/*.py`` (excluding test paths) MUST return exactly
one occurrence of the literal URL string, and that occurrence MUST live
on the ``DEFAULT_JWKS_URL`` assignment below.

Per CLAUDE.md keystone invariant #11 the OSS verifier defaults to the
spec section AO.4 trust anchor. Per banned pattern #13 changing the
default constant in a routine PR is CI-blocked; this is a board-level
decision because every offline verifier in the wild (forks, self-hosted
deployments, OSS users who never registered with the hosted product)
treats this URL as the root of trust for evidence-bundle signatures.

The companion guard test at
``packages/verifier/tests/guards/default_trust_anchor_lock.py`` re-asserts
the constant against a frozen reference value so any mutation of this
constant trips a structured CI failure pointing to banned pattern #13.

``DEFAULT_TRUST_ANCHOR_URL`` is exposed as a backwards-compatible alias
matching the CLI's pre-existing ``DEFAULT_TRUST_ANCHOR_URL`` constant
(``packages/cli/src/relay_cli/commands/evidence.py:79``); both names
resolve to the same string literal so downstream consumers may use
either spelling.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from typing import Final

# -----------------------------------------------------------------------------
# Package identity
# -----------------------------------------------------------------------------

VERIFIER_PACKAGE_NAME: Final[str] = "relay_verifier"
"""Importable Python package name; used by ``importlib.resources`` calls
in :mod:`relay_verifier.jwks_loader` to locate the bundled JWKS asset
without hardcoding a filesystem path."""


# -----------------------------------------------------------------------------
# Default trust-anchor JWKS URL (CANONICAL OCCURRENCE -- DO NOT DUPLICATE)
# -----------------------------------------------------------------------------
#
# VAL-W10-001 source-grep guard: exactly ONE occurrence of the literal
# string in the verifier package's *.py files outside the test tree. A
# duplicate occurrence -- even in a comment or docstring -- breaks the
# guard. If a future module needs the URL, import this constant; do NOT
# re-paste the literal.

DEFAULT_JWKS_URL: Final[str] = "https://relay.epochly.com/.well-known/jwks.json"
"""The OSS verifier's compiled-in default trust-anchor JWKS URL.

Spec: section AO.4 line 6165.

Changing this constant is a CLAUDE.md banned pattern #13 violation
unless approved as a board-level decision. Forks/self-hosters should
override the trust anchor at runtime via ``--trust-anchor <url>`` or a
config file entry (``trust_anchor_url = "..."``); see VAL-W10-005 /
VAL-W10-006.
"""


# Backwards-compatible alias matching the CLI's pre-existing constant
# name (``DEFAULT_TRUST_ANCHOR_URL``). Both names resolve to the same
# string object so downstream code may use either spelling.
DEFAULT_TRUST_ANCHOR_URL: Final[str] = DEFAULT_JWKS_URL


__all__ = [
    "DEFAULT_JWKS_URL",
    "DEFAULT_TRUST_ANCHOR_URL",
    "VERIFIER_PACKAGE_NAME",
]
