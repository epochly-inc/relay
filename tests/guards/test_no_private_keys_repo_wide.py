"""Guard: repo-wide no-private-key-material invariant (VAL-V2M09-020).

Per CLAUDE.md banned pattern #14 the Relay repo MUST NEVER contain
private-key PEM blocks (RSA, EC, ECDSA, OpenSSH, PGP, encrypted, raw
``PRIVATE KEY``). Trust-anchor key material lives only in KMS/HSM
(spec section L.1) and is NOT covered by the Apache 2.0 grant
(spec section AO.4).

This guard supersedes the earlier ``packages/cli``-scoped guard at
``tests/guards/test_no_private_keys.py`` (which was deliberately
limited to w9-1's surface). The M09 sub-feature w9.4 contract
assertion VAL-V2M09-020 requires a REPO-WIDE grep returning empty.
The pre-existing PEM literals previously embedded in
``scripts/generate-jws-rfc7515-*.py`` are remediated in the same
commit that introduces this guard: those scripts now generate the
RSA-2048 keypair at runtime via
``cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key``
and never persist a PEM to the working tree.

Allowed exceptions (files that legitimately reference the BANNED
header tokens as data, not as embedded key material):

  * ``tests/guards/test_no_private_keys.py`` -- earlier cli-scoped
    guard that enumerates the same tokens as scan inputs.
  * ``tests/guards/test_no_private_keys_repo_wide.py`` -- THIS file.
  * ``packages/verifier/tests/test_w10_4_chain_and_invariants.py`` --
    verifier-package guard that enumerates the tokens as scan inputs.
  * Any other future ``tests/`` file whose path matches the
    ``_GUARD_FILE_ALLOWLIST`` regex below.

The allowlist mechanism is intentionally narrow: a file containing a
banned token is permitted ONLY if its path is explicitly enumerated
here AND its content was inspected during this guard's authorship.
Adding to the allowlist requires a peer-reviewed PR that audits the
new file. No tests dir is blanket-exempt; even test files MUST NOT
embed real-looking key material outside of the explicit allowlist.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

# Banned PEM headers (CLAUDE.md banned pattern #14, VAL-V2M09-020).
# These are the literal substrings the guard scans for. We deliberately
# avoid the bare "PRIVATE KEY-----" suffix token used by the verifier-
# package guard because it would over-match prose mentions of "private
# key" in docstrings; the explicit BEGIN-line headers below are the
# authoritative substring set for the contract assertion.
_BANNED_PEM_HEADERS: tuple[str, ...] = (
    "BEGIN PRIVATE KEY",
    "BEGIN RSA PRIVATE KEY",
    "BEGIN EC PRIVATE KEY",
    "BEGIN DSA PRIVATE KEY",
    "BEGIN OPENSSH PRIVATE KEY",
    "BEGIN PGP PRIVATE KEY BLOCK",
    "BEGIN ENCRYPTED PRIVATE KEY",
    "BEGIN ED25519 PRIVATE KEY",
)

# Banned key-bearing file extensions. A file with one of these suffixes
# MUST NOT exist anywhere in the tracked tree.
_BANNED_KEY_FILE_SUFFIXES: tuple[str, ...] = (
    ".p8",
    ".p12",
    ".pfx",
    ".key",
    ".jks",
)

# Files explicitly permitted to mention the banned tokens as data (e.g.
# guard tests that enumerate the tokens themselves). Each entry is a
# REPO-relative POSIX path. The allowlist is a closed set: adding a
# new entry requires PR review and an audit of the file's content.
_GUARD_FILE_ALLOWLIST: frozenset[str] = frozenset(
    {
        "tests/guards/test_no_private_keys.py",
        "tests/guards/test_no_private_keys_repo_wide.py",
        "packages/verifier/tests/test_w10_4_chain_and_invariants.py",
    }
)


def _git_ls_files() -> list[Path]:
    """Return absolute paths of every git-tracked file in the repo.

    We restrict scanning to tracked files so untracked test scratch,
    local OIDC tokens, developer build outputs, and editor swap files
    cannot trip the guard.
    """
    proc = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "ls-files"],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if proc.returncode != 0:
        pytest.skip(
            "git ls-files failed (not a git checkout?): "
            f"rc={proc.returncode} stderr={proc.stderr!r}"
        )
    paths: list[Path] = []
    for line in proc.stdout.splitlines():
        if not line:
            continue
        paths.append(REPO_ROOT / line)
    return paths


def _is_text_file(data: bytes) -> bool:
    """Cheap binary-vs-text heuristic. A NUL byte in the first 4 KiB
    is taken as a binary signal; binary files cannot contain ASCII
    PEM headers and are skipped to keep the guard fast."""
    return b"\x00" not in data[:4096]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M09-020")
def test_no_private_key_pem_material_repo_wide() -> None:
    """No banned PEM header may appear in any git-tracked file in the
    repository, EXCEPT in the explicit guard-file allowlist."""
    files = _git_ls_files()
    assert files, (
        "VAL-V2M09-020: git ls-files returned no files; refusing to "
        "declare PASS"
    )
    offenders: list[tuple[str, str]] = []
    for path in files:
        try:
            if not path.exists() or path.is_dir():
                continue
            # Skip very large files (>1 MiB) -- a key blob would never
            # legitimately exceed that.
            if path.stat().st_size > 1_048_576:
                continue
            data = path.read_bytes()
        except OSError:
            continue
        if not _is_text_file(data):
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            continue
        rel_posix = path.relative_to(REPO_ROOT).as_posix()
        for header in _BANNED_PEM_HEADERS:
            if header in text:
                if rel_posix in _GUARD_FILE_ALLOWLIST:
                    # Allowed: the guard enumerates the token as data.
                    break
                offenders.append((rel_posix, header))
                break
    assert not offenders, (
        "VAL-V2M09-020 / CLAUDE.md banned pattern #14 violation: "
        "private-key PEM headers found in git-tracked files outside the "
        "guard-file allowlist. Offenders:\n"
        + "\n".join(f"  {rel}  ({header})" for rel, header in offenders)
        + "\n\nRemediation: never embed a PEM-encoded private key in the "
        "repo. Generate keys at runtime via "
        "cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key "
        "(or analogous for EC/Ed25519); write to a tmpdir if persistence "
        "is required for a single test process. See spec section L.1 "
        "and CLAUDE.md banned pattern #14."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M09-020")
def test_no_banned_key_file_extensions_repo_wide() -> None:
    """No file with a private-key-bearing extension may exist in the
    tracked tree."""
    files = _git_ls_files()
    offenders: list[str] = []
    for path in files:
        rel_posix = path.relative_to(REPO_ROOT).as_posix()
        suffix = Path(rel_posix).suffix.lower()
        if suffix in _BANNED_KEY_FILE_SUFFIXES:
            offenders.append(rel_posix)
    assert not offenders, (
        "VAL-V2M09-020 violation: forbidden key-file extensions present "
        "in the tracked tree:\n"
        + "\n".join(f"  {rel}" for rel in offenders)
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M09-020")
def test_tsa_chain_pem_contains_only_certificates() -> None:
    """The bundled TSA cert chain MUST contain at least one
    ``BEGIN CERTIFICATE`` block AND zero banned private-key blocks.

    Positive grep (CERTIFICATE present) + negative grep (no banned
    headers) together prove the chain file is a certificate-only PEM.
    """
    chain = (
        REPO_ROOT
        / "packages"
        / "verifier"
        / "src"
        / "relay_verifier"
        / "tsa_chain"
        / "tsa-chain.pem"
    )
    if not chain.exists():
        pytest.skip(
            f"TSA chain not yet present at {chain}; w9-2 must land first"
        )
    text = chain.read_text(encoding="utf-8")
    assert "BEGIN CERTIFICATE" in text, (
        f"VAL-V2M09-020: {chain} exists but contains no BEGIN CERTIFICATE "
        "block"
    )
    for banned in _BANNED_PEM_HEADERS:
        assert banned not in text, (
            f"VAL-V2M09-020: {chain} contains banned private-key block "
            f"{banned!r}"
        )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M09-020")
def test_guard_file_allowlist_paths_actually_exist() -> None:
    """Every path in the guard-file allowlist MUST exist in the tracked
    tree. A stale allowlist entry is a maintenance hazard: a future
    file could land at the same path and silently inherit exemption."""
    missing: list[str] = []
    for rel in _GUARD_FILE_ALLOWLIST:
        path = REPO_ROOT / rel
        if not path.is_file():
            missing.append(rel)
    assert not missing, (
        "VAL-V2M09-020: guard-file allowlist contains stale entries; "
        "remove them or restore the files:\n"
        + "\n".join(f"  {rel}" for rel in missing)
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M09-020")
def test_banned_pem_header_token_set_is_non_empty_and_unique() -> None:
    """Internal sanity: the banned-header token set is non-empty and
    has no duplicates. A regression that emptied the token set would
    silently disable the guard."""
    assert _BANNED_PEM_HEADERS, "banned header token set is empty"
    assert len(_BANNED_PEM_HEADERS) == len(set(_BANNED_PEM_HEADERS)), (
        f"banned header tokens contain duplicates: {_BANNED_PEM_HEADERS}"
    )
    # Each token MUST start with "BEGIN " -- otherwise we are scanning
    # for substrings that could over-match unrelated content.
    pat = re.compile(r"^BEGIN [A-Z0-9 ]+( BLOCK)?$")
    for token in _BANNED_PEM_HEADERS:
        assert pat.match(token), (
            f"banned token {token!r} does not match expected BEGIN-line "
            "shape; tighten or remove"
        )
