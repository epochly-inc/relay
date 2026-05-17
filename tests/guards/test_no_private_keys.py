"""Guard: no private-key material committed under packages/cli/.

Per CLAUDE.md banned pattern #14 and VAL-V2M09-020, the Relay public
repository MUST NEVER contain PEM blocks for private keys (RSA, EC,
ECDSA, OpenSSH, PGP). Trust-anchor key material lives only in KMS/HSM
(spec section L.1) and is NOT covered by the Apache 2.0 grant
(spec section AO.4).

This guard is scoped to ``packages/cli/`` (the surface w9-1 touches).
The broader-repo guard (``packages/verifier/tests/
test_w10_4_chain_and_invariants.py``) covers the verifier package.
Pre-existing private-key material under ``scripts/generate-jws-rfc7515-*.py``
is a known M09-scope violation that w9-1 surfaces as a discovered
issue but does NOT remediate (scope: cli/bundle.py only). See the
M09 milestone evidence bundle for the cross-worker reconciliation.

Positive grep for ``BEGIN CERTIFICATE`` on the bundled TSA cert chain
(when it exists) confirms the chain file contains only X.509 cert
blocks, never a stray private key.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

# Banned PEM headers (CLAUDE.md banned pattern #14, VAL-V2M09-020).
BANNED_PEM_HEADERS = (
    "BEGIN PRIVATE KEY",
    "BEGIN RSA PRIVATE KEY",
    "BEGIN EC PRIVATE KEY",
    "BEGIN DSA PRIVATE KEY",
    "BEGIN OPENSSH PRIVATE KEY",
    "BEGIN PGP PRIVATE KEY BLOCK",
    "BEGIN ENCRYPTED PRIVATE KEY",
)

# Top-level directories to scan. We never scan .venv, .git, node_modules,
# uv build caches, or generated lockfile dirs (those are not committed
# source). We also deliberately scan only files tracked by git (via
# git ls-files) so untracked test scratch / OIDC tokens don't trip us.


def _git_ls_files() -> list[Path]:
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
    return [REPO_ROOT / line for line in proc.stdout.splitlines() if line]


CLI_ROOT = REPO_ROOT / "packages" / "cli"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M09-020")
def test_no_private_key_material_under_packages_cli() -> None:
    """No banned private-key PEM header may appear in any tracked file
    under ``packages/cli/`` (the surface w9-1 owns).

    Scope rationale (w9-1 task brief, line "Scope is ONLY packages/cli/"):
    the broader repo guard belongs to a cross-worker reconciliation
    step in the M09 evidence bundle. The pre-existing
    ``scripts/generate-jws-rfc7515-*.py`` static RSA keys are a known
    discovered issue surfaced by this worker but NOT remediated here.
    """
    files = _git_ls_files()
    assert files, "git ls-files returned no files; refusing to declare PASS"
    cli_root_resolved = CLI_ROOT.resolve()
    offenders: list[tuple[Path, str]] = []
    for path in files:
        # Restrict to packages/cli/ subtree.
        try:
            path_resolved = path.resolve()
        except OSError:
            continue
        try:
            path_resolved.relative_to(cli_root_resolved)
        except ValueError:
            continue
        # Skip binary-looking paths: only scan files that are reasonably
        # small and decodable as text. Files >1 MiB are unlikely to be
        # PEM-key payloads and slow the test materially.
        try:
            if not path.exists() or path.is_dir():
                continue
            if path.stat().st_size > 1_048_576:
                continue
            data = path.read_bytes()
        except OSError:
            continue
        # Cheap binary heuristic: if there's a NUL byte in the first
        # 4 KiB, treat as binary and skip.
        if b"\x00" in data[:4096]:
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            continue
        for header in BANNED_PEM_HEADERS:
            if header in text:
                offenders.append((path, header))
                break
    assert not offenders, (
        "VAL-V2M09-020 / CLAUDE.md banned pattern #14: private-key "
        "PEM material MUST NEVER be committed under packages/cli/. "
        "Offenders:\n"
        + "\n".join(f"  {p}  ({h})" for p, h in offenders)
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M09-020")
def test_tsa_chain_contains_only_certificates_when_present() -> None:
    """If the bundled TSA cert chain exists, it MUST contain at least
    one ``BEGIN CERTIFICATE`` block AND zero banned private-key blocks.
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
        # The chain ships in w9-2 (a separate worker). If it does not
        # yet exist, this guard is vacuously satisfied; it'll begin
        # enforcing once that worker lands.
        pytest.skip(f"TSA chain not yet present at {chain}; w9-2 not landed")
    text = chain.read_text(encoding="utf-8")
    assert "BEGIN CERTIFICATE" in text, (
        f"{chain} exists but contains no BEGIN CERTIFICATE block"
    )
    for banned in BANNED_PEM_HEADERS:
        assert banned not in text, (
            f"{chain} contains banned private-key block {banned!r}"
        )
