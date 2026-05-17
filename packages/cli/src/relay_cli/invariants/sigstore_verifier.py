"""Sigstore verifier implemented check (VAL-V2M09-025).

Per CLAUDE.md keystone invariant #11 + spec section AO.1 lines 6117-6119,
the public ``relay`` verifier's cryptographic core MUST be wired (not
fail-closed) for the Sigstore layer of the Relay trust anchor to exist
at all. M09 flipped the ``VERIFIER_SIGSTORE_CRYPTO_IMPLEMENTED`` flag
(in ``packages/cli/src/relay_cli/bundle.py``) from False to True after
wiring real ``sigstore-python`` verification with Fulcio root + Rekor
inclusion + expected identity/issuer.

This invariant verifies the flag value is still True. A False value
emits one finding pointing at the file + line where the flag is
declared so the operator can investigate the regression (the fail-closed
path is reachable only via deliberate edit of that constant).

The check is pure: it reads the constant via Python import (no
filesystem regex), so flag flips made via ``sed`` are caught at the
next ``rly verify-self`` run.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

from verify_self.finding_codes import (
    RELAY_VERIFY_SELF_SIGSTORE_NOT_IMPLEMENTED,
)

from .util import Finding, suggested_fix_for

CHECK_NAME: Final[str] = "sigstore-verifier-implemented"

# Source location of the flag declaration. The finding's ``file`` field
# points at this path; ``line`` is the canonical declaration line. If
# the constant moves the line number stays best-effort -- the file
# reference is the load-bearing identifier the operator follows.
_FLAG_SOURCE_FILE: Final[str] = (
    "packages/cli/src/relay_cli/bundle.py"
)
_FLAG_NAME: Final[str] = "VERIFIER_SIGSTORE_CRYPTO_IMPLEMENTED"


def _resolve_flag() -> bool | None:
    """Return the current value of the Sigstore-implemented flag.

    Returns ``None`` when the flag cannot be imported (e.g., the
    verifier package was uninstalled or the constant was renamed). The
    runner treats ``None`` as a finding because the absence of the flag
    is itself a regression of the canonical surface.
    """
    try:
        from relay_cli.bundle import VERIFIER_SIGSTORE_CRYPTO_IMPLEMENTED
    except Exception:  # noqa: BLE001 - any import failure is a finding
        return None
    return bool(VERIFIER_SIGSTORE_CRYPTO_IMPLEMENTED)


def _grep_flag_line(repo_root: Path) -> int:
    """Best-effort line number of ``_FLAG_NAME: Final[bool] = ...``.

    Returns 1 when the source file is unreadable or the declaration is
    absent; the finding's ``file`` reference is the actionable item.
    """
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
    """Run the sigstore-verifier-implemented check.

    Returns ``(check_name, findings)``. Zero findings = pass (the flag
    is True). One finding = fail (the flag is False or absent).
    """
    findings: list[Finding] = []
    value = _resolve_flag()
    if value is not True:
        findings.append(
            Finding(
                file=_FLAG_SOURCE_FILE,
                line=_grep_flag_line(repo_root),
                code=RELAY_VERIFY_SELF_SIGSTORE_NOT_IMPLEMENTED,
                suggested_fix=suggested_fix_for(
                    RELAY_VERIFY_SELF_SIGSTORE_NOT_IMPLEMENTED
                ),
                pattern=f"{_FLAG_NAME} = {value!r}",
            )
        )
    findings.sort(key=lambda f: (f.file, f.line, f.code))
    return CHECK_NAME, findings


__all__ = ["CHECK_NAME", "run"]
