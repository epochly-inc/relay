"""TSA verifier implemented check (VAL-V2M09-025).

Per CLAUDE.md keystone invariant #11 + spec section AO.1 lines 6117-6119
+ spec section L.5, the RFC 3161 TimeStampResp ASN.1 verifier MUST be
wired (not fail-closed) for the TSA layer of the Relay trust anchor to
exist at all. M09 flipped the ``TSA_CRYPTO_IMPLEMENTED`` flag (in
``packages/verifier/src/relay_verifier/tsa.py``) from False to True
after wiring TimeStampResp decode + SignerInfo verification against the
bundled TSA cert chain.

This invariant verifies the flag value is still True. A False value
emits one finding pointing at the file + line where the flag is
declared so the operator can investigate the regression.

Per VAL-ISO-005 the flag is read from the SOURCE FILE under the
operator-supplied ``repo_root`` (AST parse, no import), so ``rly
verify-self --repo-root <tree>`` validates that tree's source rather than
whatever wheel happens to be on ``sys.path``.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

from verify_self.finding_codes import (
    RELAY_VERIFY_SELF_TSA_NOT_IMPLEMENTED,
)

from .util import Finding, suggested_fix_for
from .util_flag_source import resolve_bool_flag_from_source

CHECK_NAME: Final[str] = "tsa-verifier-implemented"

_FLAG_SOURCE_FILE: Final[str] = (
    "packages/verifier/src/relay_verifier/tsa.py"
)
_FLAG_NAME: Final[str] = "TSA_CRYPTO_IMPLEMENTED"


def _resolve_flag(repo_root: Path) -> bool | None:
    """Return the TSA-implemented flag value parsed from ``repo_root``."""
    return resolve_bool_flag_from_source(
        repo_root / _FLAG_SOURCE_FILE, _FLAG_NAME
    )


def _grep_flag_line(repo_root: Path) -> int:
    """Best-effort line number of ``_FLAG_NAME: Final[bool] = ...``."""
    src = repo_root / _FLAG_SOURCE_FILE
    if not src.is_file():
        return 1
    try:
        text = src.read_text(encoding="utf-8")
    except OSError:
        return 1
    needle = f"{_FLAG_NAME}: Final[bool]"
    for idx, line in enumerate(text.splitlines()):
        if needle in line:
            return idx + 1
    return 1


def run(repo_root: Path) -> tuple[str, list[Finding]]:
    """Run the tsa-verifier-implemented check."""
    findings: list[Finding] = []
    value = _resolve_flag(repo_root)
    if value is not True:
        findings.append(
            Finding(
                file=_FLAG_SOURCE_FILE,
                line=_grep_flag_line(repo_root),
                code=RELAY_VERIFY_SELF_TSA_NOT_IMPLEMENTED,
                suggested_fix=suggested_fix_for(
                    RELAY_VERIFY_SELF_TSA_NOT_IMPLEMENTED
                ),
                pattern=f"{_FLAG_NAME} = {value!r}",
            )
        )
    findings.sort(key=lambda f: (f.file, f.line, f.code))
    return CHECK_NAME, findings


__all__ = ["CHECK_NAME", "run"]
