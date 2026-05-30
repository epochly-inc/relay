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

The check is pure: it reads the constant by parsing the SOURCE FILE
under the operator-supplied ``repo_root`` (VAL-ISO-005), NOT by importing
the installed package on ``sys.path``. ``rly verify-self --repo-root
<tree>`` therefore validates the tree the operator named -- a flag flipped
to ``False`` in that tree's source is reported even when the installed
wheel ships ``True``. Reading via import would silently validate the
wheel, not the tree, and miss the regression.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

from verify_self.finding_codes import (
    RELAY_VERIFY_SELF_SIGSTORE_NOT_IMPLEMENTED,
)

from .util import Finding, suggested_fix_for
from .util_flag_source import resolve_bool_flag_from_source

CHECK_NAME: Final[str] = "sigstore-verifier-implemented"

# Source location of the flag declaration. The finding's ``file`` field
# points at this path; ``line`` is the canonical declaration line. If
# the constant moves the line number stays best-effort -- the file
# reference is the load-bearing identifier the operator follows.
_FLAG_SOURCE_FILE: Final[str] = (
    "packages/cli/src/relay_cli/bundle.py"
)
_FLAG_NAME: Final[str] = "VERIFIER_SIGSTORE_CRYPTO_IMPLEMENTED"


def _resolve_flag(repo_root: Path) -> bool | None:
    """Return the Sigstore-implemented flag value parsed from ``repo_root``.

    Reads the flag's module-level assignment from the SOURCE FILE under
    ``repo_root`` (not via import). Returns ``None`` when the source file
    is absent/unreadable or the assignment cannot be found or is not a
    boolean literal -- the runner treats ``None`` as a finding because the
    absence of the canonical declaration is itself a regression.
    """
    return resolve_bool_flag_from_source(
        repo_root / _FLAG_SOURCE_FILE, _FLAG_NAME
    )


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
    value = _resolve_flag(repo_root)
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
