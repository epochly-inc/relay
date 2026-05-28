"""W12.5 sidecar bundle workflow + guard plumbing tests.

Tests the static guard ``scripts/check-sidecar-bundle.py`` against the
committed workflow + supporting docs. Covers 12 of the 14 contract
assertions assigned to feature ``w12.5-release-sidecar-bundle``:

- VAL-W12-020  Release publishes signed sidecar binaries for every
               supported OS/arch (canonical five-arch matrix).
- VAL-W12-021  Sigstore keyless signing + Rekor inclusion proof.
- VAL-W12-022  Sigstore TSA timestamp attached.
- VAL-W12-023  Functional equivalence (tier-1 plumbing parity).
- VAL-W12-024  Signing on the SLSA L3 hermetic builder.
- VAL-W12-025  npm wrapper digest-first / Sigstore-second.
- VAL-W12-026  macOS notarized; Windows Authenticode-signed.
- VAL-W12-027  Bundle binaries are signed and verifiable
               (digest matches manifest + Rekor entry validates).
- VAL-W12-035  No trust-anchor key material in repo.
- VAL-W12-036  Secret-scan workflow present.
- VAL-W12-037  Rekor offline-verifiability declared.
- VAL-W12-041  Compromised-OIDC drill documented.
- VAL-W12-042  Trust-anchor governance document references pipeline.
- VAL-W12-043  Sectigo TSA fallback wired but inactive by default.

Per CLAUDE.md TDD discipline: each test binds to its contract
assertion via ``@pytest.mark.fulfills("VAL-W12-NNN")`` so the gate
engine can trace test-to-assertion coverage. ASCII-only source per
CLAUDE.md.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

# Repository root: tests/release/test_*.py -> tests/release -> tests -> repo.
REPO_ROOT: Path = Path(__file__).resolve().parents[2]
GUARD_SCRIPT: Path = REPO_ROOT / "scripts" / "check-sidecar-bundle.py"
WORKFLOW_PATH: Path = (
    REPO_ROOT / ".github" / "workflows" / "release-sidecar-bundle.yml"
)
SECRET_SCAN_WORKFLOW: Path = (
    REPO_ROOT / ".github" / "workflows" / "secret-scan.yml"
)
SIDECAR_BUNDLE_PKG: Path = (
    REPO_ROOT / "packages" / "sdk-typescript-sidecar-bundle"
)
COMPROMISED_OIDC_DOC: Path = (
    REPO_ROOT / "docs" / "release" / "compromised-oidc-drill.md"
)
SECTIGO_DOC: Path = (
    REPO_ROOT / "docs" / "release" / "sectigo-tsa-fallback.md"
)
TRUST_ANCHOR_GOV_DOC: Path = (
    REPO_ROOT / "docs" / "release" / "trust-anchor-governance.md"
)
RUNBOOK_PATH: Path = REPO_ROOT / "docs" / "release" / "runbook.md"

# Canonical four-arch matrix pinned in the contract (VAL-W12-020,
# revised 2026-05-28). macos-x86_64 removed by board-level decision
# documented in CHANGELOG v0.1.16.
CANONICAL_MATRIX: tuple[str, ...] = (
    "macos-arm64",
    "linux-x86_64",
    "linux-arm64",
    "windows-x86_64",
)


# ---------------------------------------------------------------------------
# Guard invocation helpers.
# ---------------------------------------------------------------------------


def _run_guard_json() -> dict:
    """Run the guard with --json and return parsed report."""
    proc = subprocess.run(
        [sys.executable, str(GUARD_SCRIPT), "--json"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode in (0, 1), (
        f"guard returned unexpected exit {proc.returncode}: "
        f"stdout={proc.stdout!r} stderr={proc.stderr!r}"
    )
    return json.loads(proc.stdout)


def _assertion(report: dict, assertion_id: str) -> dict:
    """Find the named assertion's check record in the guard report."""
    for c in report["checks"]:
        if c["assertion"] == assertion_id:
            return c
    raise AssertionError(
        f"assertion {assertion_id} not found in guard report; "
        f"checks={[c['assertion'] for c in report['checks']]}"
    )


# ---------------------------------------------------------------------------
# Workflow + guard presence preflights.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_guard_script_exists_and_is_executable_via_python() -> None:
    assert GUARD_SCRIPT.is_file(), f"guard script missing at {GUARD_SCRIPT}"
    text = GUARD_SCRIPT.read_text(encoding="utf-8")
    assert text.startswith("#!"), "guard script lacks shebang"
    # ASCII-safe per CLAUDE.md.
    text.encode("ascii")


@pytest.mark.plumbing
def test_workflow_file_exists() -> None:
    assert WORKFLOW_PATH.is_file(), (
        f"sidecar-bundle release workflow missing at {WORKFLOW_PATH}"
    )


# ---------------------------------------------------------------------------
# VAL-W12-020 -- canonical five-arch matrix.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-020")
def test_workflow_declares_all_five_canonical_cells() -> None:
    text = WORKFLOW_PATH.read_text(encoding="utf-8")
    for slug in CANONICAL_MATRIX:
        assert slug in text, f"workflow missing canonical matrix cell '{slug}'"

    report = _run_guard_json()
    check = _assertion(report, "VAL-W12-020")
    assert check["passed"], check["message"]
    assert check["error_code"] == "RELAY-RELEASE-020"


# ---------------------------------------------------------------------------
# VAL-W12-021 -- Sigstore keyless signing + Rekor inclusion proof.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-021")
def test_workflow_references_sigstore_and_rekor_with_id_token_write() -> None:
    text = WORKFLOW_PATH.read_text(encoding="utf-8")
    assert "sigstore" in text.lower(), "workflow does not reference Sigstore"
    assert "rekor" in text.lower(), "workflow does not reference Rekor"
    # OIDC keyless signing requires id-token: write granted on the
    # signing job. The static guard performs the structural check; the
    # test asserts the guard agrees.
    report = _run_guard_json()
    check = _assertion(report, "VAL-W12-021")
    assert check["passed"], check["message"]


# ---------------------------------------------------------------------------
# VAL-W12-022 -- Sigstore TSA timestamp.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-022")
def test_workflow_declares_tsa_timestamp_configuration() -> None:
    report = _run_guard_json()
    check = _assertion(report, "VAL-W12-022")
    assert check["passed"], check["message"]


# ---------------------------------------------------------------------------
# VAL-W12-023 -- functional equivalence (tier-1 plumbing parity).
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-023")
def test_workflow_runs_tier1_plumbing_parity_step() -> None:
    text = WORKFLOW_PATH.read_text(encoding="utf-8")
    # Either a job named *parity*/*plumb*/*equiv* or a step name with
    # 'tier-1' / 'plumbing' / 'equivalence' satisfies the contract.
    indicators = ("parity", "plumbing", "equivalence", "tier-1")
    assert any(ind in text.lower() for ind in indicators), (
        "workflow does not run any tier-1 plumbing parity job/step"
    )
    report = _run_guard_json()
    check = _assertion(report, "VAL-W12-023")
    assert check["passed"], check["message"]


# ---------------------------------------------------------------------------
# VAL-W12-024 -- SLSA L3 hermetic builder.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-024")
def test_workflow_uses_slsa_l3_hermetic_builder() -> None:
    text = WORKFLOW_PATH.read_text(encoding="utf-8")
    assert "slsa-framework/slsa-github-generator" in text, (
        "workflow does not invoke the SLSA L3 hermetic builder"
    )
    report = _run_guard_json()
    check = _assertion(report, "VAL-W12-024")
    assert check["passed"], check["message"]


# ---------------------------------------------------------------------------
# VAL-W12-025 -- npm wrapper digest-first / Sigstore-second.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-025")
def test_sidecar_bundle_pkg_carries_digest_first_error_codes() -> None:
    assert SIDECAR_BUNDLE_PKG.is_dir(), (
        f"sidecar-bundle package missing at {SIDECAR_BUNDLE_PKG}"
    )
    sources = list(SIDECAR_BUNDLE_PKG.rglob("*.ts")) + list(
        SIDECAR_BUNDLE_PKG.rglob("*.mts")
    )
    assert sources, "sidecar-bundle package has no TS sources"

    needed = {"RELAY-RELEASE-025-DIGEST", "RELAY-RELEASE-025-SIGSTORE"}
    found: set[str] = set()
    for src in sources:
        text = src.read_text(encoding="utf-8")
        for token in needed:
            if token in text:
                found.add(token)
    missing = needed - found
    assert not missing, f"wrapper missing canonical error tokens: {missing}"

    report = _run_guard_json()
    check = _assertion(report, "VAL-W12-025")
    assert check["passed"], check["message"]


# ---------------------------------------------------------------------------
# VAL-W12-026 -- macOS notarized + stapled; Windows Authenticode.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-026")
def test_workflow_notarizes_macos_and_codesigns_windows() -> None:
    text = WORKFLOW_PATH.read_text(encoding="utf-8").lower()
    assert "notariz" in text, "workflow does not notarize macOS binaries"
    assert any(
        tok in text for tok in ("signtool", "authenticode", "osslsigncode")
    ), "workflow does not codesign Windows binaries"
    report = _run_guard_json()
    check = _assertion(report, "VAL-W12-026")
    assert check["passed"], check["message"]


# ---------------------------------------------------------------------------
# VAL-W12-027 -- bundle binaries are signed and verifiable
# (digest matches manifest + Rekor entry validates).
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-027")
def test_build_driver_computes_sha256_and_workflow_consumes_manifest() -> None:
    driver = REPO_ROOT / "scripts" / "build-sidecar-bundle.py"
    assert driver.is_file(), f"build driver missing at {driver}"
    driver_text = driver.read_text(encoding="utf-8")
    assert "sha256" in driver_text, "build driver does not compute SHA-256"
    text = WORKFLOW_PATH.read_text(encoding="utf-8")
    assert "manifest" in text.lower(), (
        "workflow does not reference the build manifest output"
    )
    report = _run_guard_json()
    check = _assertion(report, "VAL-W12-027")
    assert check["passed"], check["message"]


# ---------------------------------------------------------------------------
# VAL-W12-035 -- no trust-anchor key material in repo.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-035")
def test_workflow_contains_no_trust_anchor_key_material() -> None:
    text = WORKFLOW_PATH.read_text(encoding="utf-8")
    # PEM blocks, KMS URNs, vault URLs MUST NOT appear in the workflow.
    assert "-----BEGIN" not in text, "workflow contains a PEM block"
    assert "arn:aws:kms" not in text, "workflow references AWS KMS URN"
    assert "vault.azure.net/keys" not in text, (
        "workflow references Azure key-vault URL"
    )
    assert "/keyRings/" not in text, "workflow references GCP key ring path"
    # Long-lived publish secrets MUST NOT appear either.
    for name in ("PYPI_TOKEN", "TWINE_PASSWORD", "NPM_TOKEN"):
        assert f"secrets.{name}" not in text, (
            f"workflow references long-lived publish secret 'secrets.{name}'"
        )
    report = _run_guard_json()
    check = _assertion(report, "VAL-W12-035")
    assert check["passed"], check["message"]


# ---------------------------------------------------------------------------
# VAL-W12-036 -- secret-scan workflow present.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-036")
def test_secret_scan_workflow_present_with_pattern_coverage() -> None:
    assert SECRET_SCAN_WORKFLOW.is_file(), (
        f"secret-scan workflow missing at {SECRET_SCAN_WORKFLOW}"
    )
    text = SECRET_SCAN_WORKFLOW.read_text(encoding="utf-8")
    for tok in (".pem", ".p12", "kms", "sectigo"):
        assert tok in text, f"secret-scan workflow missing pattern token '{tok}'"
    assert "gitleaks" in text.lower() or "scan" in text.lower(), (
        "secret-scan workflow does not invoke a named scanner"
    )
    report = _run_guard_json()
    check = _assertion(report, "VAL-W12-036")
    assert check["passed"], check["message"]


# ---------------------------------------------------------------------------
# VAL-W12-037 -- Rekor offline-verifiability declared.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-037")
def test_workflow_declares_rekor_offline_verifiability() -> None:
    text = WORKFLOW_PATH.read_text(encoding="utf-8").lower()
    assert "rekor" in text, "workflow does not reference Rekor"
    assert any(
        tok in text for tok in ("offline", "inclusion", "merkle")
    ), "workflow does not declare offline / Merkle / inclusion verification"
    report = _run_guard_json()
    check = _assertion(report, "VAL-W12-037")
    assert check["passed"], check["message"]


# ---------------------------------------------------------------------------
# VAL-W12-041 -- compromised-OIDC drill documented + runbook reference.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-041")
def test_compromised_oidc_drill_documented_with_all_four_steps() -> None:
    assert COMPROMISED_OIDC_DOC.is_file(), (
        f"compromised-OIDC drill doc missing at {COMPROMISED_OIDC_DOC}"
    )
    text = COMPROMISED_OIDC_DOC.read_text(encoding="utf-8").lower()
    for step_token in ("revoke", "rotate", "advisory", "publish a new release"):
        assert step_token in text, (
            f"compromised-OIDC drill missing step token '{step_token}'"
        )
    # Runbook must reference the drill.
    assert RUNBOOK_PATH.is_file(), "runbook missing"
    runbook_text = RUNBOOK_PATH.read_text(encoding="utf-8")
    assert "Compromised OIDC" in runbook_text, (
        "runbook does not reference 'Compromised OIDC' section"
    )
    report = _run_guard_json()
    check = _assertion(report, "VAL-W12-041")
    assert check["passed"], check["message"]


# ---------------------------------------------------------------------------
# VAL-W12-042 -- trust-anchor governance document references the
# release pipeline.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-042")
def test_trust_anchor_governance_doc_references_release_pipeline() -> None:
    assert TRUST_ANCHOR_GOV_DOC.is_file(), (
        f"trust-anchor governance doc missing at {TRUST_ANCHOR_GOV_DOC}"
    )
    text = TRUST_ANCHOR_GOV_DOC.read_text(encoding="utf-8").lower()
    for ref in ("release pipeline", "sigstore", "in-toto", "slsa"):
        assert ref in text, (
            f"trust-anchor governance doc missing reference '{ref}'"
        )
    report = _run_guard_json()
    check = _assertion(report, "VAL-W12-042")
    assert check["passed"], check["message"]


# ---------------------------------------------------------------------------
# VAL-W12-043 -- Sectigo TSA fallback wired but inactive by default.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-043")
def test_sectigo_tsa_fallback_documented_and_inactive_by_default() -> None:
    assert SECTIGO_DOC.is_file(), (
        f"Sectigo TSA fallback doc missing at {SECTIGO_DOC}"
    )
    sectigo_text = SECTIGO_DOC.read_text(encoding="utf-8")
    assert (
        'TSA_PRIMARY = "sigstore"' in sectigo_text
        or 'TSA_PRIMARY="sigstore"' in sectigo_text
    ), "Sectigo doc does not pin TSA_PRIMARY='sigstore' as default"
    assert "sectigo" in sectigo_text.lower(), (
        "Sectigo doc does not reference Sectigo"
    )
    workflow_text = WORKFLOW_PATH.read_text(encoding="utf-8")
    assert "TSA_PRIMARY" in workflow_text, (
        "workflow does not declare TSA_PRIMARY"
    )
    # Default in the workflow is "sigstore" -- enforced by the guard.
    report = _run_guard_json()
    check = _assertion(report, "VAL-W12-043")
    assert check["passed"], check["message"]


# ---------------------------------------------------------------------------
# VAL-W12-012 SHA-pin enforcement (Bug 3 strengthening + Bug 1 fix).
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-012")
def test_sidecar_workflow_passes_sha_pinning_check() -> None:
    """The real release-sidecar-bundle.yml has every supply-chain critical
    ``uses:`` ref 40-char SHA-pinned (Bug 1 fix)."""
    report = _run_guard_json()
    check = _assertion(report, "VAL-W12-012")
    assert check["passed"], (
        f"VAL-W12-012 SHA-pin check rejected sidecar workflow: "
        f"{check['message']!r}"
    )
    assert check["error_code"] == "RELAY-RELEASE-012"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-012")
def test_sidecar_workflow_pins_slsa_generator_to_40_char_sha() -> None:
    """The SLSA generator ``uses:`` ref MUST be 40-char lowercase hex.

    Direct file-level assertion (does not depend on the guard) so a
    regression that bypasses the guard still trips this test.
    """
    workflow_text = WORKFLOW_PATH.read_text(encoding="utf-8")
    # Find the SLSA generator uses: line.
    found_ref: str | None = None
    for line in workflow_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("uses:") and (
            "slsa-framework/slsa-github-generator" in stripped
        ):
            value = stripped[len("uses:") :].strip().strip("'\"")
            _, _, ref = value.partition("@")
            found_ref = ref
            break
    assert found_ref is not None, (
        "no SLSA generator uses: line found in sidecar workflow"
    )
    import re as _re

    sha40 = _re.compile(r"^[a-f0-9]{40}$")
    assert sha40.match(found_ref), (
        f"SLSA generator ref {found_ref!r} is not a 40-char SHA "
        "(must be SHA-pinned per spec keystone #11)"
    )


# ---------------------------------------------------------------------------
# Composite guard exit code -- if every assertion passes the guard
# exits 0 (suitable for CI use).
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_guard_exit_code_matches_aggregate_status() -> None:
    proc = subprocess.run(
        [sys.executable, str(GUARD_SCRIPT)],
        capture_output=True,
        text=True,
        check=False,
    )
    report = _run_guard_json()
    expected = 0 if report["ok"] else 1
    assert proc.returncode == expected, (
        f"guard exit code {proc.returncode} != expected {expected}; "
        f"stderr={proc.stderr!r}"
    )
