"""Rekor verifier implemented check (VAL-V2M09-025).

Per CLAUDE.md keystone invariant #11 + spec section AO.1 lines 6117-6119,
the Rekor transparency-log inclusion-proof verifier MUST be wired
(not fail-closed) for the Rekor layer of the Relay trust anchor to exist
at all. M09 flipped the ``REKOR_CRYPTO_IMPLEMENTED`` flag (in
``packages/cli/src/relay_cli/commands/verify_install.py``) from False to
True after wiring Merkle inclusion proof + SET verification against
Rekor's public key.

This invariant verifies the flag value is still True. A False value
emits one finding pointing at the file + line where the flag is
declared so the operator can investigate the regression.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

from verify_self.finding_codes import (
    RELAY_VERIFY_SELF_REKOR_NOT_IMPLEMENTED,
)

from .util import Finding, suggested_fix_for

CHECK_NAME: Final[str] = "rekor-verifier-implemented"

_FLAG_SOURCE_FILE: Final[str] = (
    "packages/cli/src/relay_cli/commands/verify_install.py"
)
_FLAG_NAME: Final[str] = "REKOR_CRYPTO_IMPLEMENTED"


def _resolve_flag() -> bool | None:
    """Return the current value of the Rekor-implemented flag."""
    try:
        from relay_cli.commands.verify_install import REKOR_CRYPTO_IMPLEMENTED
    except Exception:  # noqa: BLE001 - any import failure is a finding
        return None
    return bool(REKOR_CRYPTO_IMPLEMENTED)


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
    """Run the rekor-verifier-implemented check."""
    findings: list[Finding] = []
    value = _resolve_flag()
    if value is not True:
        findings.append(
            Finding(
                file=_FLAG_SOURCE_FILE,
                line=_grep_flag_line(repo_root),
                code=RELAY_VERIFY_SELF_REKOR_NOT_IMPLEMENTED,
                suggested_fix=suggested_fix_for(
                    RELAY_VERIFY_SELF_REKOR_NOT_IMPLEMENTED
                ),
                pattern=f"{_FLAG_NAME} = {value!r}",
            )
        )
    findings.sort(key=lambda f: (f.file, f.line, f.code))
    return CHECK_NAME, findings


__all__ = ["CHECK_NAME", "run"]
